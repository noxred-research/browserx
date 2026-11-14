//! Sealed snapshot storage in an S3-API object store.
//!
//! Layout under the configured prefix:
//!
//! ```text
//! <prefix>snapshots/<profile id>/<version:020>.snap
//! ```
//!
//! The object body is the sealed payload. [`SnapshotMeta`] travels in the object's user
//! metadata (`x-amz-meta-bx-meta`, base64 of its JSON), so one `PUT` writes payload and
//! metadata atomically: an object either exists complete or does not exist, and no separate
//! commit marker is needed. `list` reads the metadata with one `HEAD` per retained version.
//!
//! Versions are created with `If-None-Match: *` so two writers that both pass the "newer than
//! the latest" check cannot overwrite each other. A service that does not support the header
//! (it answers 501, or 400 for the argument) is detected on first use and the store then falls
//! back to an unconditional `PUT`; the check against the listing remains, and the narrow race
//! between two simultaneous writers of the same profile (which the lease generation already
//! forbids) is not closed on such a service.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use browserx_core::{Error, ProfileId, Result, Snapshot, SnapshotMeta, SnapshotStore};

use crate::MAX_SEALED_BYTES;
use crate::common::check_put;
use crate::object::{ObjectError, ObjectStore, ObjectStoreConfig};

const META_KEY: &str = "bx-meta";
/// Largest encoded `SnapshotMeta` the store writes or accepts back (S3 allows 2 KiB of user
/// metadata in total).
const META_MAX_ENCODED_BYTES: usize = 1536;
/// Versions of one profile `list` reads metadata for. A profile with more must be pruned.
const MAX_LISTED_VERSIONS: usize = 1024;
/// Re-reads when the newest version is pruned between the listing and the read.
const LATEST_ATTEMPTS: usize = 3;

/// A [`SnapshotStore`] keeping sealed snapshots in an S3-API bucket under a key prefix.
#[derive(Clone)]
pub struct S3SnapshotStore {
    store: ObjectStore,
    snapshots_prefix: Arc<str>,
    conditional_create: Arc<AtomicBool>,
}

impl std::fmt::Debug for S3SnapshotStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3SnapshotStore")
            .field("service", &self.store.summary())
            .finish()
    }
}

fn version_stem(version: u64) -> String {
    format!("{version:020}")
}

impl S3SnapshotStore {
    /// Validates the configuration and builds the client. Credentials come from the file named
    /// in the configuration or the environment. No network access happens here; call
    /// [`ping`](Self::ping) to check the bucket.
    pub fn connect(cfg: &ObjectStoreConfig) -> Result<Self> {
        Ok(Self::with_store(ObjectStore::connect(cfg)?))
    }

    /// Builds the store on an existing client (its prefix is the namespace).
    #[must_use]
    pub fn with_store(store: ObjectStore) -> Self {
        let snapshots_prefix: Arc<str> = format!("{}snapshots/", store.prefix()).into();
        Self {
            store,
            snapshots_prefix,
            conditional_create: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Checks that the bucket exists and the credentials may list the prefix.
    pub async fn ping(&self) -> Result<()> {
        Ok(self.store.ping().await?)
    }

    /// A one-line description for logs. Never contains credentials.
    #[must_use]
    pub fn profile_summary(&self) -> String {
        self.store.summary().to_owned()
    }

    fn profile_prefix(&self, profile: ProfileId) -> String {
        format!("{}{}/", self.snapshots_prefix, profile.prefixed())
    }

    fn key(&self, profile: ProfileId, version: u64) -> String {
        format!(
            "{}{}.snap",
            self.profile_prefix(profile),
            version_stem(version)
        )
    }

    /// Committed versions of a profile with their keys and sizes, ascending.
    async fn versions(&self, profile: ProfileId) -> Result<Vec<(u64, String, u64)>> {
        let prefix = self.profile_prefix(profile);
        let entries = self.store.list(&prefix).await?;
        Ok(parse_versions(&prefix, entries))
    }
}

/// The entries of a listing that are snapshot objects (`<20 digits>.snap`), ascending.
fn parse_versions(prefix: &str, entries: Vec<(String, u64)>) -> Vec<(u64, String, u64)> {
    let mut out: Vec<(u64, String, u64)> = entries
        .into_iter()
        .filter_map(|(key, size)| {
            let stem = key.strip_prefix(prefix)?.strip_suffix(".snap")?;
            if stem.len() != 20 || !stem.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some((stem.parse::<u64>().ok()?, key, size))
        })
        .collect();
    out.sort_by_key(|(v, _, _)| *v);
    out
}

fn encode_meta(meta: &SnapshotMeta) -> Result<String> {
    let json = serde_json::to_vec(meta)
        .map_err(|e| Error::Internal(format!("encode snapshot metadata: {e}")))?;
    let encoded = BASE64.encode(json);
    if encoded.len() > META_MAX_ENCODED_BYTES {
        return Err(Error::InvalidRequest(format!(
            "snapshot metadata is {} bytes encoded; the object store limit is {META_MAX_ENCODED_BYTES}",
            encoded.len()
        )));
    }
    Ok(encoded)
}

fn decode_meta(
    metadata: &BTreeMap<String, String>,
    profile: ProfileId,
    version: u64,
) -> Result<SnapshotMeta> {
    let encoded = metadata
        .get(META_KEY)
        .ok_or_else(|| Error::Storage(format!("snapshot v{version} has no metadata")))?;
    if encoded.len() > META_MAX_ENCODED_BYTES {
        return Err(Error::Storage(format!(
            "snapshot v{version} metadata is too large"
        )));
    }
    let json = BASE64
        .decode(encoded)
        .map_err(|_| Error::Storage(format!("corrupt snapshot metadata v{version}")))?;
    let meta: SnapshotMeta = serde_json::from_slice(&json)
        .map_err(|e| Error::Storage(format!("corrupt snapshot metadata v{version}: {e}")))?;
    if meta.version != version || meta.profile_id != profile {
        return Err(Error::Storage(format!(
            "snapshot metadata v{version} does not match its location"
        )));
    }
    Ok(meta)
}

#[async_trait]
impl SnapshotStore for S3SnapshotStore {
    async fn put(&self, snapshot: &Snapshot) -> Result<()> {
        check_put(snapshot)?;
        let profile = snapshot.meta.profile_id;
        let version = snapshot.meta.version;
        let encoded = encode_meta(&snapshot.meta)?;
        if let Some((newest, _, _)) = self.versions(profile).await?.last()
            && version <= *newest
        {
            return Err(Error::Conflict(format!(
                "snapshot version {version} is not newer than stored version {newest}"
            )));
        }
        let key = self.key(profile, version);
        let metadata = BTreeMap::from([(META_KEY.to_owned(), encoded)]);
        let conditional = self.conditional_create.load(Ordering::Relaxed);
        match self
            .store
            .put(&key, &snapshot.sealed, &metadata, conditional)
            .await
        {
            Ok(()) => Ok(()),
            Err(ObjectError::PreconditionFailed) => {
                // A retried write may have landed the first time: the same bytes and metadata
                // at this key mean success, anything else is a competing writer.
                match self.store.head(&key).await? {
                    Some(head)
                        if head.size == snapshot.meta.size
                            && head.metadata.get(META_KEY) == metadata.get(META_KEY) =>
                    {
                        Ok(())
                    }
                    _ => Err(Error::Conflict(format!(
                        "snapshot version {version} was written concurrently"
                    ))),
                }
            }
            Err(ObjectError::Unsupported(_)) if conditional => {
                tracing::warn!(
                    service = %self.store.summary(),
                    "object store does not support conditional create; writing unconditionally"
                );
                self.conditional_create.store(false, Ordering::Relaxed);
                Ok(self
                    .store
                    .put(&key, &snapshot.sealed, &metadata, false)
                    .await?)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn latest(&self, profile: ProfileId) -> Result<Option<Snapshot>> {
        for _ in 0..LATEST_ATTEMPTS {
            let versions = self.versions(profile).await?;
            let Some((version, key, _)) = versions.last() else {
                return Ok(None);
            };
            let Some((sealed, metadata)) = self.store.get(key).await? else {
                continue; // pruned between the listing and the read
            };
            let meta = decode_meta(&metadata, profile, *version)?;
            if u64::try_from(sealed.len()).ok() != Some(meta.size)
                || sealed.len() > MAX_SEALED_BYTES
            {
                return Err(Error::Storage(format!(
                    "snapshot v{version} length does not match its metadata"
                )));
            }
            return Ok(Some(Snapshot { meta, sealed }));
        }
        Err(Error::Storage(
            "the newest snapshot kept changing while it was read".into(),
        ))
    }

    async fn list(&self, profile: ProfileId) -> Result<Vec<SnapshotMeta>> {
        let versions = self.versions(profile).await?;
        if versions.len() > MAX_LISTED_VERSIONS {
            return Err(Error::Storage(format!(
                "profile has {} snapshots; prune it below {MAX_LISTED_VERSIONS} before listing",
                versions.len()
            )));
        }
        let mut out = Vec::with_capacity(versions.len());
        for (version, key, _) in versions.iter().rev() {
            // A version pruned meanwhile no longer exists.
            if let Some(head) = self.store.head(key).await? {
                out.push(decode_meta(&head.metadata, profile, *version)?);
            }
        }
        Ok(out)
    }

    async fn prune(&self, profile: ProfileId, keep: usize) -> Result<u64> {
        let versions = self.versions(profile).await?;
        let excess = versions.len().saturating_sub(keep);
        let doomed: Vec<String> = versions
            .into_iter()
            .take(excess)
            .map(|(_, key, _)| key)
            .collect();
        for chunk in doomed.chunks(256) {
            self.store.delete_many(chunk).await?;
        }
        Ok(u64::try_from(doomed.len()).unwrap_or(u64::MAX))
    }

    async fn delete_profile(&self, profile: ProfileId) -> Result<u64> {
        let prefix = self.profile_prefix(profile);
        let mut entries = self.store.list(&prefix).await?;
        let count = parse_versions(&prefix, entries.clone()).len();
        // Newest first, so an interrupted erasure leaves the oldest history and never a
        // "latest" that predates deleted versions.
        entries.sort_by(|a, b| b.0.cmp(&a.0));
        for chunk in entries.chunks(256) {
            let keys: Vec<String> = chunk.iter().map(|(k, _)| k.clone()).collect();
            self.store.delete_many(&keys).await?;
        }
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }
}
