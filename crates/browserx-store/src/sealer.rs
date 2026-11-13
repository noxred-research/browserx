//! Authenticated encryption of state snapshots.

use std::fmt;
use std::io::{Read, Write};
use std::path::Path;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use browserx_core::snapshot::STATE_FORMAT_VERSION;
use browserx_core::{Error, Result, Snapshot, SnapshotMeta, StateSnapshot};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const KEY_FILE_MAGIC: &str = "browserx-snapshot-key";
/// Newest key file format this build reads and writes.
const KEY_FILE_VERSION: u32 = 1;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const KEY_FILE_MAX_BYTES: u64 = 4096;

/// Seals and opens [`StateSnapshot`] values with AES-256-GCM.
///
/// Layout of [`Snapshot::sealed`]: `nonce(12) || ciphertext || tag(16)`. The
/// nonce is random per seal. The associated data is the canonical JSON of
/// `(profile_id, version, session_id, generation)` taken from the snapshot
/// metadata, so a sealed blob only opens under the exact metadata it was
/// written with: moving it to another profile, version, session or generation
/// fails authentication.
///
/// One key is active and seals every new snapshot. Retired keys (key rotation)
/// are open-only: [`Sealer::open`] picks the key named by `meta.key_id`, so
/// snapshots written before a rotation stay readable. A snapshot sealed with a
/// key that is neither active nor retired fails with `Crypto("unknown key_id ..")`.
///
/// Keys live only inside the cipher state, which is zeroized on drop.
pub struct Sealer {
    key_id: String,
    cipher: Aes256Gcm,
    /// Keys that can still open old snapshots but never seal new ones.
    retired: Vec<(String, Aes256Gcm)>,
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct Aad<'a> {
    v: u8,
    profile_id: &'a browserx_core::ProfileId,
    version: u64,
    session_id: &'a browserx_core::SessionId,
    generation: u64,
}

#[derive(Deserialize)]
struct FormatPeek {
    format_version: u32,
}

fn aad(meta: &SnapshotMeta) -> Result<Vec<u8>> {
    serde_json::to_vec(&Aad {
        v: 1,
        profile_id: &meta.profile_id,
        version: meta.version,
        session_id: &meta.session_id,
        generation: meta.generation.0,
    })
    .map_err(|e| Error::Internal(format!("encode snapshot aad: {e}")))
}

fn crypto(msg: &str) -> Error {
    Error::Crypto(msg.to_owned())
}

fn derive_key_id(key: &[u8; KEY_BYTES]) -> String {
    let mut h = Sha256::new();
    h.update(b"browserx-snapshot-key-id");
    h.update(key);
    hex::encode(&h.finalize()[..4])
}

impl Sealer {
    /// Builds a sealer from raw key material. `key_id` is recorded in snapshot
    /// metadata so keys can be rotated; it must not be derived from secrets.
    #[must_use]
    pub fn new(key_id: String, mut key: [u8; KEY_BYTES]) -> Self {
        let cipher = Aes256Gcm::new(&key.into());
        key.zeroize();
        Self {
            key_id,
            cipher,
            retired: Vec::new(),
        }
    }

    /// Adds open-only keys, as `(key_id, key)` pairs. Entries whose id equals the
    /// active key's id or an already retired id are ignored.
    #[must_use]
    pub fn with_retired(mut self, retired: Vec<(String, [u8; KEY_BYTES])>) -> Self {
        for (id, mut key) in retired {
            if !self.knows_key(&id) {
                self.retired.push((id, Aes256Gcm::new(&key.into())));
            }
            key.zeroize();
        }
        self
    }

    /// Loads a key file (same format as [`Self::from_key_file`]) as an open-only
    /// retired key. Fails if its `key_id` is already known.
    pub fn add_retired_key_file(&mut self, path: &Path) -> Result<()> {
        let other = Self::from_key_file(path)?;
        if self.knows_key(&other.key_id) {
            return Err(Error::Crypto(format!(
                "key_id {} is already loaded; a retired key needs a distinct key_id",
                other.key_id
            )));
        }
        self.retired
            .push((other.key_id.clone(), other.cipher.clone()));
        Ok(())
    }

    fn knows_key(&self, id: &str) -> bool {
        self.key_id == id || self.retired.iter().any(|(r, _)| r == id)
    }

    fn cipher_for(&self, id: &str) -> Result<&Aes256Gcm> {
        if id == self.key_id {
            return Ok(&self.cipher);
        }
        self.retired
            .iter()
            .find(|(r, _)| r == id)
            .map(|(_, c)| c)
            .ok_or_else(|| Error::Crypto(format!("unknown key_id {id}")))
    }

    /// The identifier written into [`SnapshotMeta::key_id`] by [`Self::seal`].
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Writes a new random key file at `path` with mode `0600`.
    ///
    /// Format (text, newline separated):
    /// ```text
    /// browserx-snapshot-key v1
    /// key_id=<8 hex digits>
    /// key=<base64 of 32 bytes>
    /// ```
    /// The `key_id` is a truncated hash of the key. Never overwrites: an
    /// existing file is a `Conflict`.
    pub fn generate_key_file(path: &Path) -> Result<()> {
        let mut key = [0u8; KEY_BYTES];
        rand::rng().fill_bytes(&mut key);
        let content = Zeroizing::new(format!(
            "{KEY_FILE_MAGIC} v{KEY_FILE_VERSION}\nkey_id={}\nkey={}\n",
            derive_key_id(&key),
            STANDARD.encode(key)
        ));
        key.zeroize();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Storage(format!("create key directory: {e}")))?;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Conflict("snapshot key file already exists; refusing to overwrite".into())
            } else {
                Error::Storage(format!("create snapshot key file: {e}"))
            }
        })?;
        file.write_all(content.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| Error::Storage(format!("write snapshot key file: {e}")))
    }

    /// Loads a key file written by [`Self::generate_key_file`].
    ///
    /// Refuses files readable by "other" users and files declaring a newer
    /// format version than this build understands.
    pub fn from_key_file(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|e| Error::Crypto(format!("cannot open snapshot key file: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = file
                .metadata()
                .map_err(|e| Error::Crypto(format!("cannot stat snapshot key file: {e}")))?
                .permissions()
                .mode();
            if mode & 0o007 != 0 {
                return Err(crypto(
                    "snapshot key file is accessible by other users; chmod 600",
                ));
            }
            if mode & 0o070 != 0 {
                tracing::warn!("snapshot key file is accessible by its group; chmod 600 advised");
            }
        }
        let mut text = Zeroizing::new(String::new());
        file.take(KEY_FILE_MAX_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| Error::Crypto(format!("cannot read snapshot key file: {e}")))?;
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > KEY_FILE_MAX_BYTES {
            return Err(crypto("snapshot key file is too large"));
        }
        Self::parse_key_file(&text)
    }

    fn parse_key_file(text: &str) -> Result<Self> {
        let mut lines = text.lines();
        let header = lines.next().unwrap_or_default();
        let version = header
            .strip_prefix(KEY_FILE_MAGIC)
            .and_then(|r| r.strip_prefix(" v"))
            .and_then(|v| v.parse::<u32>().ok())
            .ok_or_else(|| crypto("not a BrowserX snapshot key file"))?;
        if version > KEY_FILE_VERSION {
            return Err(Error::Crypto(format!(
                "snapshot key file format v{version} is newer than supported v{KEY_FILE_VERSION}; upgrade BrowserX"
            )));
        }
        if version == 0 {
            return Err(crypto("unsupported snapshot key file format v0"));
        }
        let mut key_id: Option<String> = None;
        let mut key: Option<Zeroizing<Vec<u8>>> = None;
        for line in lines.filter(|l| !l.trim().is_empty()) {
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| crypto("malformed snapshot key file line"))?;
            match name {
                "key_id" => key_id = Some(value.trim().to_owned()),
                "key" => {
                    key = Some(Zeroizing::new(
                        STANDARD
                            .decode(value.trim())
                            .map_err(|_| crypto("snapshot key is not valid base64"))?,
                    ));
                }
                _ => return Err(crypto("unknown field in snapshot key file")),
            }
        }
        let key_id = key_id.ok_or_else(|| crypto("snapshot key file lacks key_id"))?;
        if key_id.len() != 8 || !key_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(crypto("snapshot key_id must be 8 hex digits"));
        }
        let raw = key.ok_or_else(|| crypto("snapshot key file lacks key"))?;
        let mut bytes = [0u8; KEY_BYTES];
        if raw.len() != KEY_BYTES {
            return Err(crypto("snapshot key must be exactly 32 bytes"));
        }
        bytes.copy_from_slice(&raw);
        Ok(Self::new(key_id, bytes))
    }

    /// Encrypts `state` and returns the snapshot to store. Fills `meta.size` and
    /// `meta.key_id`; every other metadata field is bound into the AAD.
    pub fn seal(&self, meta: SnapshotMeta, state: &StateSnapshot) -> Result<Snapshot> {
        if state.format_version > STATE_FORMAT_VERSION {
            return Err(Error::Crypto(format!(
                "state format v{} is newer than supported v{STATE_FORMAT_VERSION}",
                state.format_version
            )));
        }
        let plain = Zeroizing::new(
            serde_json::to_vec(state)
                .map_err(|e| Error::Internal(format!("encode snapshot state: {e}")))?,
        );
        self.seal_bytes(meta, &plain)
    }

    fn seal_bytes(&self, mut meta: SnapshotMeta, plain: &[u8]) -> Result<Snapshot> {
        let mut nonce_bytes = [0u8; NONCE_BYTES];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce: Nonce<U12> = nonce_bytes.into();
        let aad = aad(&meta)?;
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .map_err(|_| crypto("snapshot encryption failed"))?;
        let mut sealed = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        meta.key_id.clone_from(&self.key_id);
        meta.size = u64::try_from(sealed.len()).unwrap_or(u64::MAX);
        Ok(Snapshot { meta, sealed })
    }

    /// Verifies and decrypts a stored snapshot. Fails with `Crypto` when the key
    /// differs, the bytes or metadata were altered, or the plaintext format is
    /// newer than this build supports.
    pub fn open(&self, snap: &Snapshot) -> Result<StateSnapshot> {
        let cipher = self.cipher_for(&snap.meta.key_id)?;
        if snap.sealed.len() < NONCE_BYTES + TAG_BYTES {
            return Err(crypto("sealed snapshot is truncated"));
        }
        let (nonce_bytes, ciphertext) = snap.sealed.split_at(NONCE_BYTES);
        let mut nonce_arr = [0u8; NONCE_BYTES];
        nonce_arr.copy_from_slice(nonce_bytes);
        let nonce: Nonce<U12> = nonce_arr.into();
        let aad = aad(&snap.meta)?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| {
                    crypto("snapshot authentication failed (wrong key or altered data)")
                })?,
        );
        let peek: FormatPeek = serde_json::from_slice(&plain)
            .map_err(|_| crypto("snapshot plaintext is malformed"))?;
        if peek.format_version > STATE_FORMAT_VERSION {
            return Err(Error::Crypto(format!(
                "snapshot state format v{} is newer than supported v{STATE_FORMAT_VERSION}; upgrade BrowserX",
                peek.format_version
            )));
        }
        serde_json::from_slice(&plain).map_err(|_| crypto("snapshot plaintext is malformed"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use browserx_core::{Generation, ProfileId, SessionId};
    use time::OffsetDateTime;

    use super::*;

    fn meta() -> SnapshotMeta {
        SnapshotMeta {
            profile_id: ProfileId::new(),
            version: 1,
            session_id: SessionId::new(),
            generation: Generation(1),
            created_at: OffsetDateTime::UNIX_EPOCH,
            size: 0,
            key_id: String::new(),
        }
    }

    #[test]
    fn open_refuses_newer_plaintext_format() {
        let sealer = Sealer::new("00000000".into(), [7u8; 32]);
        let future = br#"{"format_version":2,"something_new":true}"#;
        let snap = sealer.seal_bytes(meta(), future).unwrap();
        let err = sealer.open(&snap).unwrap_err();
        assert!(
            matches!(err, Error::Crypto(m) if m.contains("newer")),
            "unexpected error"
        );
    }

    #[test]
    fn rotation_opens_old_snapshots_with_retired_keys() {
        let old = Sealer::new("0000000a".into(), [1u8; 32]);
        let old_snap = old.seal(meta(), &StateSnapshot::default()).unwrap();

        let rotated = Sealer::new("0000000b".into(), [2u8; 32]).with_retired(vec![
            ("0000000a".into(), [1u8; 32]),
            ("0000000b".into(), [9u8; 32]),
        ]);
        // retired key opens old data; the active key seals new data
        assert!(rotated.open(&old_snap).is_ok());
        let new_snap = rotated.seal(meta(), &StateSnapshot::default()).unwrap();
        assert_eq!(new_snap.meta.key_id, "0000000b");
        assert!(rotated.open(&new_snap).is_ok());
        // a retired key never seals, and the old sealer cannot open the new data
        assert!(
            matches!(old.open(&new_snap), Err(Error::Crypto(m)) if m.contains("unknown key_id 0000000b"))
        );
        // a key id nobody holds
        let stranger = Sealer::new("0000000c".into(), [3u8; 32]);
        let foreign = stranger.seal(meta(), &StateSnapshot::default()).unwrap();
        assert!(
            matches!(rotated.open(&foreign), Err(Error::Crypto(m)) if m == "unknown key_id 0000000c")
        );
        // a retired id with the wrong key material fails authentication, not lookup
        let wrong = Sealer::new("0000000b".into(), [2u8; 32])
            .with_retired(vec![("0000000a".into(), [7u8; 32])]);
        assert!(
            matches!(wrong.open(&old_snap), Err(Error::Crypto(m)) if m.contains("authentication"))
        );
    }

    #[test]
    fn retired_key_file_is_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let (old_path, new_path) = (dir.path().join("old.key"), dir.path().join("new.key"));
        Sealer::generate_key_file(&old_path).unwrap();
        Sealer::generate_key_file(&new_path).unwrap();
        let old = Sealer::from_key_file(&old_path).unwrap();
        let snap = old.seal(meta(), &StateSnapshot::default()).unwrap();

        let mut current = Sealer::from_key_file(&new_path).unwrap();
        assert!(current.open(&snap).is_err());
        current.add_retired_key_file(&old_path).unwrap();
        assert!(current.open(&snap).is_ok());
        // duplicates are refused
        assert!(current.add_retired_key_file(&old_path).is_err());
        assert!(current.add_retired_key_file(&new_path).is_err());
    }

    #[test]
    fn seal_refuses_newer_state_format() {
        let sealer = Sealer::new("00000000".into(), [7u8; 32]);
        let state = StateSnapshot {
            format_version: STATE_FORMAT_VERSION + 1,
            ..Default::default()
        };
        assert!(sealer.seal(meta(), &state).is_err());
    }
}
