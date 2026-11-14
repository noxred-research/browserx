//! In-process snapshot storage.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use browserx_core::{Error, ProfileId, Result, Snapshot, SnapshotMeta, SnapshotStore};

use crate::common::check_put;

type Profiles = HashMap<ProfileId, BTreeMap<u64, Snapshot>>;

/// A [`SnapshotStore`] that keeps sealed snapshots in memory. Lost on restart.
#[derive(Default)]
pub struct MemorySnapshotStore {
    profiles: Mutex<Profiles>,
}

impl MemorySnapshotStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<MutexGuard<'_, Profiles>> {
        self.profiles
            .lock()
            .map_err(|_| Error::Internal("snapshot store lock poisoned".into()))
    }
}

#[async_trait]
impl SnapshotStore for MemorySnapshotStore {
    async fn put(&self, snapshot: &Snapshot) -> Result<()> {
        check_put(snapshot)?;
        let mut profiles = self.lock()?;
        let versions = profiles.entry(snapshot.meta.profile_id).or_default();
        if let Some((&newest, _)) = versions.last_key_value()
            && snapshot.meta.version <= newest
        {
            return Err(Error::Conflict(format!(
                "snapshot version {} is not newer than stored version {newest}",
                snapshot.meta.version
            )));
        }
        versions.insert(snapshot.meta.version, snapshot.clone());
        Ok(())
    }

    async fn latest(&self, profile: ProfileId) -> Result<Option<Snapshot>> {
        Ok(self
            .lock()?
            .get(&profile)
            .and_then(|v| v.last_key_value())
            .map(|(_, s)| s.clone()))
    }

    async fn list(&self, profile: ProfileId) -> Result<Vec<SnapshotMeta>> {
        Ok(self
            .lock()?
            .get(&profile)
            .map(|v| v.values().rev().map(|s| s.meta.clone()).collect())
            .unwrap_or_default())
    }

    async fn prune(&self, profile: ProfileId, keep: usize) -> Result<u64> {
        let mut profiles = self.lock()?;
        let Some(versions) = profiles.get_mut(&profile) else {
            return Ok(0);
        };
        let excess = versions.len().saturating_sub(keep);
        let doomed: Vec<u64> = versions.keys().copied().take(excess).collect();
        for v in &doomed {
            versions.remove(v);
        }
        if versions.is_empty() {
            profiles.remove(&profile);
        }
        Ok(u64::try_from(doomed.len()).unwrap_or(u64::MAX))
    }

    async fn delete_profile(&self, profile: ProfileId) -> Result<u64> {
        Ok(self
            .lock()?
            .remove(&profile)
            .map_or(0, |v| u64::try_from(v.len()).unwrap_or(u64::MAX)))
    }
}
