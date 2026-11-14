//! Profile identity: ownership markers, in-process claims and erasure.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use browserx_core::{Error, ProfileId, Result, SessionId, SnapshotMeta};
use browserx_runtime::ProfileLock;
use tokio::io::AsyncWriteExt;

use crate::state::Inner;

/// Rolls back an owner-quota slot and a profile claim unless committed.
pub(crate) struct Admitted {
    inner: Arc<Inner>,
    owner: String,
    profile: Option<(ProfileId, SessionId)>,
    armed: bool,
}

impl Admitted {
    pub(crate) fn commit(mut self) {
        self.armed = false;
    }

    pub(crate) fn claim_profile(&mut self, profile: ProfileId, session: SessionId) -> Result<()> {
        self.inner.claim_profile(profile, session)?;
        self.profile = Some((profile, session));
        Ok(())
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut st = self.inner.st();
        if let Some(n) = st.owner_counts.get_mut(&self.owner) {
            *n = n.saturating_sub(1);
        }
        if let Some((profile, session)) = self.profile
            && st.profiles.get(&profile) == Some(&session)
        {
            st.profiles.remove(&profile);
        }
    }
}

/// A profile claim that is given back when dropped, however the holder ends.
pub(crate) struct ProfileClaim {
    inner: Arc<Inner>,
    profile: ProfileId,
    holder: SessionId,
}

impl ProfileClaim {
    /// Claims `profile` for a one-off operation (not a session).
    pub(crate) fn new(inner: &Arc<Inner>, profile: ProfileId) -> Result<Self> {
        let holder = SessionId::new();
        inner.claim_profile(profile, holder)?;
        Ok(Self {
            inner: inner.clone(),
            profile,
            holder,
        })
    }
}

impl Drop for ProfileClaim {
    fn drop(&mut self) {
        self.inner.unclaim_profile(self.profile, self.holder);
    }
}

impl Inner {
    /// Counts a new non-terminal session against the owner's quota.
    pub(crate) fn admit_owner(self: &Arc<Self>, owner: &str) -> Result<Admitted> {
        let quota = self.cfg.quota_for(owner);
        {
            let mut st = self.st();
            let count = st.owner_counts.entry(owner.to_owned()).or_insert(0);
            if *count >= quota {
                self.metrics.adm_quota.inc();
                return Err(Error::Capacity(format!(
                    "owner quota of {quota} concurrent sessions reached"
                )));
            }
            *count += 1;
        }
        Ok(Admitted {
            inner: self.clone(),
            owner: owner.to_owned(),
            profile: None,
            armed: true,
        })
    }

    pub(crate) fn profile_dir(&self, id: ProfileId) -> PathBuf {
        self.profiles_root.join(id.prefixed())
    }

    fn owners_dir(&self) -> PathBuf {
        self.profiles_root.join(".owners")
    }

    fn owner_marker(&self, id: ProfileId) -> PathBuf {
        self.owners_dir().join(id.prefixed())
    }

    pub(crate) fn claim_profile(&self, profile: ProfileId, session: SessionId) -> Result<()> {
        let mut st = self.st();
        if st.profiles.contains_key(&profile) {
            return Err(Error::Conflict(format!(
                "profile {profile} is in use by an active session"
            )));
        }
        st.profiles.insert(profile, session);
        Ok(())
    }

    pub(crate) fn unclaim_profile(&self, profile: ProfileId, session: SessionId) {
        let mut st = self.st();
        if st.profiles.get(&profile) == Some(&session) {
            st.profiles.remove(&profile);
        }
    }

    /// Records `owner` as the owner of a newly minted profile.
    pub(crate) async fn register_profile_owner(&self, owner: &str, id: ProfileId) -> Result<()> {
        let dir = self.owners_dir();
        tokio::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .await
            .map_err(|e| Error::Storage(format!("create profile owner directory: {e}")))?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.owner_marker(id))
            .await
            .map_err(|e| Error::Storage(format!("register profile owner: {e}")))?;
        file.write_all(owner.as_bytes())
            .await
            .map_err(|e| Error::Storage(format!("register profile owner: {e}")))?;
        file.flush()
            .await
            .map_err(|e| Error::Storage(format!("register profile owner: {e}")))
    }

    /// Succeeds only when `owner` owns `id`. Unknown and foreign profiles look the same.
    pub(crate) async fn check_profile_owner(&self, owner: &str, id: ProfileId) -> Result<()> {
        match tokio::fs::read_to_string(self.owner_marker(id)).await {
            Ok(stored) if stored == owner => Ok(()),
            Ok(_) => Err(Error::NotFound(format!("profile {id}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::NotFound(format!("profile {id}")))
            }
            Err(e) => Err(Error::Storage(format!("read profile owner: {e}"))),
        }
    }

    pub(crate) async fn forget_profile_owner(&self, id: ProfileId) {
        if let Err(e) = tokio::fs::remove_file(self.owner_marker(id)).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(profile = %id, error = %e, "could not remove profile owner marker");
        }
    }

    pub(crate) async fn list_profile_snapshots_impl(
        &self,
        owner: &str,
        id: ProfileId,
    ) -> Result<Vec<SnapshotMeta>> {
        self.check_profile_owner(owner, id).await?;
        self.snapshots.list(id).await
    }

    /// Erases snapshots, the profile directory (when no browser holds it) and
    /// the ownership record. Refuses while a session uses the profile.
    pub(crate) async fn delete_profile_impl(
        self: &Arc<Self>,
        owner: &str,
        id: ProfileId,
    ) -> Result<u64> {
        self.check_profile_owner(owner, id).await?;
        let _claim = ProfileClaim::new(self, id)?;
        let result = self.erase_profile(id).await;
        if result.is_ok() {
            self.forget_profile_owner(id).await;
        }
        result
    }

    async fn erase_profile(&self, id: ProfileId) -> Result<u64> {
        let dir = self.profile_dir(id);
        if path_exists(&dir).await {
            let lock = ProfileLock::acquire(&dir)?;
            tokio::fs::remove_dir_all(&dir)
                .await
                .map_err(|e| Error::Storage(format!("remove profile directory: {e}")))?;
            drop(lock);
        }
        self.snapshots.delete_profile(id).await
    }
}

pub(crate) async fn path_exists(path: &Path) -> bool {
    tokio::fs::try_exists(path).await.unwrap_or(false)
}

/// Whether a profile directory already holds browser data (ignoring the lock file).
pub(crate) async fn dir_has_content(dir: &Path) -> bool {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return false;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if entry.file_name() != ".browserx.lock" {
            return true;
        }
    }
    false
}
