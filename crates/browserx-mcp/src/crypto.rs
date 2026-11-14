//! Small cryptographic helpers shared by the engagement manifest, scope grants and approvals:
//! HMAC-SHA256 with domain separation, constant-time comparison, operator key files and an
//! AEAD box for opaque state handed to clients.

use std::collections::BTreeMap;
use std::path::Path;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng as _;
use sha2::{Digest as _, Sha256};

/// Shortest operator key accepted, in bytes.
pub const MIN_KEY_BYTES: usize = 16;

const BLOCK: usize = 64;
const NONCE_BYTES: usize = 12;

/// Why a signature or sealed value was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The signature file is not `key_id:hex`.
    #[error("the signature is malformed: expected `<key id>:<64 hex digits>`")]
    MalformedSignature,
    /// The signature names a key this deployment does not hold.
    #[error("the signature names an unknown operator key {0:?}")]
    UnknownKey(String),
    /// The signature does not match the signed bytes.
    #[error("the signature does not match the content")]
    Mismatch,
    /// The key file is malformed.
    #[error("operator keys: {0}")]
    Keys(String),
    /// A sealed value is malformed, altered or sealed by another process.
    #[error("the sealed value is not valid")]
    Sealed,
}

/// HMAC-SHA256 (RFC 2104).
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    let mut outer = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(data);
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Compares two byte strings without an early exit on the first difference.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The operator keys of a deployment, by key id.
#[derive(Clone, Default)]
pub struct OperatorKeys {
    keys: BTreeMap<String, Vec<u8>>,
}

impl std::fmt::Debug for OperatorKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorKeys")
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl OperatorKeys {
    /// No keys: nothing verifies.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key.
    ///
    /// # Errors
    /// When the id is empty or has whitespace or `:`, or the key is shorter than [`MIN_KEY_BYTES`].
    pub fn insert(&mut self, key_id: &str, key: Vec<u8>) -> Result<(), CryptoError> {
        if key_id.is_empty()
            || key_id.len() > 64
            || key_id
                .chars()
                .any(|c| c.is_whitespace() || c == ':' || c == '=')
        {
            return Err(CryptoError::Keys(format!(
                "key id {key_id:?} must be 1..=64 characters without whitespace, `:` or `=`"
            )));
        }
        if key.len() < MIN_KEY_BYTES {
            return Err(CryptoError::Keys(format!(
                "key {key_id:?} is shorter than {MIN_KEY_BYTES} bytes"
            )));
        }
        self.keys.insert(key_id.to_owned(), key);
        Ok(())
    }

    /// Parses a key file: one `key_id = <hex>` per line; `#` starts a comment.
    ///
    /// # Errors
    /// When a line is malformed or a key is too short.
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        let mut keys = Self::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (id, value) = line.split_once('=').ok_or_else(|| {
                CryptoError::Keys(format!("line {}: expected `key_id = <hex>`", number + 1))
            })?;
            let bytes = hex::decode(value.trim()).map_err(|_| {
                CryptoError::Keys(format!("line {}: the key is not hexadecimal", number + 1))
            })?;
            keys.insert(id.trim(), bytes)?;
        }
        if keys.keys.is_empty() {
            return Err(CryptoError::Keys("the key file holds no key".into()));
        }
        Ok(keys)
    }

    /// Reads a key file.
    ///
    /// # Errors
    /// When the file is unreadable or malformed.
    pub fn load(path: &Path) -> Result<Self, CryptoError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CryptoError::Keys(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// The ids of the keys held.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }

    /// The signature line `key_id:hex` over `domain || content` with key `key_id`.
    ///
    /// # Errors
    /// When the key id is unknown.
    pub fn sign(&self, key_id: &str, domain: &[u8], content: &[u8]) -> Result<String, CryptoError> {
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| CryptoError::UnknownKey(key_id.to_owned()))?;
        Ok(format!(
            "{key_id}:{}",
            hex::encode(mac(key, domain, content))
        ))
    }

    /// Verifies a signature line over `domain || content`; returns the key id that signed.
    ///
    /// # Errors
    /// When the line is malformed, names an unknown key or does not match.
    pub fn verify(
        &self,
        signature: &str,
        domain: &[u8],
        content: &[u8],
    ) -> Result<String, CryptoError> {
        let (key_id, hexed) = signature
            .trim()
            .split_once(':')
            .ok_or(CryptoError::MalformedSignature)?;
        let given = hex::decode(hexed).map_err(|_| CryptoError::MalformedSignature)?;
        if given.len() != 32 {
            return Err(CryptoError::MalformedSignature);
        }
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| CryptoError::UnknownKey(key_id.to_owned()))?;
        if ct_eq(&mac(key, domain, content), &given) {
            Ok(key_id.to_owned())
        } else {
            Err(CryptoError::Mismatch)
        }
    }
}

fn mac(key: &[u8], domain: &[u8], content: &[u8]) -> [u8; 32] {
    let mut message = Vec::with_capacity(domain.len() + content.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(content);
    hmac_sha256(key, &message)
}

/// A new random operator key line (`key_id = <64 hex digits>`).
#[must_use]
pub fn new_key_line(key_id: &str) -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("{key_id} = {}", hex::encode(bytes))
}

/// Opaque, authenticated state for clients: AES-256-GCM under a random per-process key, so a
/// restarted server refuses everything an earlier process sealed.
pub struct StateBox {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for StateBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateBox").finish_non_exhaustive()
    }
}

impl StateBox {
    /// A box under a fresh random key.
    #[must_use]
    pub fn random() -> Self {
        let key: [u8; 32] = rand::random();
        Self::from_key(&key)
    }

    /// A box under `key` (tests, and callers that derive keys).
    #[must_use]
    pub fn from_key(key: &[u8; 32]) -> Self {
        let key: &Key<Aes256Gcm> = key.into();
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }

    /// Seals `plain` with `aad` bound; the result is URL-safe base64 of `nonce || ciphertext`.
    #[must_use]
    pub fn seal(&self, aad: &[u8], plain: &[u8]) -> String {
        let nonce_bytes: [u8; NONCE_BYTES] = rand::random();
        let nonce: Nonce<U12> = nonce_bytes.into();
        // Encryption of a bounded buffer cannot fail; an empty string would be refused on open.
        let ciphertext = self
            .cipher
            .encrypt(&nonce, Payload { msg: plain, aad })
            .unwrap_or_default();
        if ciphertext.is_empty() {
            return String::new();
        }
        let mut sealed = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        URL_SAFE_NO_PAD.encode(sealed)
    }

    /// Opens a value sealed by this box with the same `aad`.
    ///
    /// # Errors
    /// [`CryptoError::Sealed`] for anything that does not authenticate.
    pub fn open(&self, aad: &[u8], sealed: &str) -> Result<Vec<u8>, CryptoError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(sealed.trim())
            .map_err(|_| CryptoError::Sealed)?;
        if bytes.len() < NONCE_BYTES + 16 {
            return Err(CryptoError::Sealed);
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_BYTES);
        let mut nonce_arr = [0_u8; NONCE_BYTES];
        nonce_arr.copy_from_slice(nonce_bytes);
        let nonce: Nonce<U12> = nonce_arr.into();
        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Sealed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn hmac_matches_rfc_4231_vectors() {
        // Test case 1.
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Test case 2.
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test case 6: a key longer than the block size.
        let mac = hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex::encode(mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    fn keys() -> OperatorKeys {
        let mut keys = OperatorKeys::new();
        keys.insert("op1", vec![7; 32]).unwrap();
        keys
    }

    #[test]
    fn signatures_are_domain_separated_and_detect_any_change() {
        let keys = keys();
        let signature = keys.sign("op1", b"domain/a\0", b"content").unwrap();
        assert_eq!(
            keys.verify(&signature, b"domain/a\0", b"content").unwrap(),
            "op1"
        );
        assert_eq!(
            keys.verify(&signature, b"domain/b\0", b"content"),
            Err(CryptoError::Mismatch)
        );
        assert_eq!(
            keys.verify(&signature, b"domain/a\0", b"contenT"),
            Err(CryptoError::Mismatch)
        );
        assert!(matches!(
            keys.verify("nokey:00", b"d", b"c"),
            Err(CryptoError::MalformedSignature)
        ));
        let other = signature.replace("op1:", "op2:");
        assert!(matches!(
            keys.verify(&other, b"domain/a\0", b"content"),
            Err(CryptoError::UnknownKey(_))
        ));
        assert!(keys.sign("missing", b"d", b"c").is_err());
    }

    #[test]
    fn key_files_are_validated() {
        let line = new_key_line("alpha");
        let parsed = OperatorKeys::parse(&format!("# comment\n{line}\n")).unwrap();
        assert_eq!(parsed.ids().collect::<Vec<_>>(), vec!["alpha"]);
        assert!(OperatorKeys::parse("short = abcd").is_err());
        assert!(OperatorKeys::parse("").is_err());
        assert!(OperatorKeys::parse("a b = 00").is_err());
        assert!(OperatorKeys::parse("a = zz").is_err());
        assert!(format!("{parsed:?}").contains("alpha"));
        assert!(!format!("{parsed:?}").contains(&line[8..]));
    }

    #[test]
    fn every_seal_draws_a_fresh_nonce() {
        let boxed = StateBox::random();
        let decode = |s: &str| URL_SAFE_NO_PAD.decode(s).unwrap();
        let a = decode(&boxed.seal(b"aad", b"hello"));
        let b = decode(&boxed.seal(b"aad", b"hello"));
        assert_ne!(a[..NONCE_BYTES], b[..NONCE_BYTES]);
        assert_ne!(a, b);
    }

    #[test]
    fn the_state_box_authenticates_content_and_context() {
        let boxed = StateBox::random();
        let sealed = boxed.seal(b"aad", b"hello");
        assert_eq!(boxed.open(b"aad", &sealed).unwrap(), b"hello");
        assert_eq!(boxed.open(b"other", &sealed), Err(CryptoError::Sealed));
        let mut tampered = sealed.clone().into_bytes();
        let last = tampered.len() - 2;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            boxed.open(b"aad", &String::from_utf8(tampered).unwrap()),
            Err(CryptoError::Sealed)
        );
        assert_eq!(
            StateBox::random().open(b"aad", &sealed),
            Err(CryptoError::Sealed)
        );
        assert_eq!(boxed.open(b"aad", "!!"), Err(CryptoError::Sealed));
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"a", b"ab"));
    }
}
