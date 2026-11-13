//! In-process lease registry. State is lost on restart; use it for tests and
//! single-process deployments that accept that.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use browserx_core::{
    Clock, Error, Generation, LeaseStore, Result, SessionId, SessionLease, SessionStatus,
    SystemClock,
};
use time::OffsetDateTime;

use crate::common::{check_cas, scrubbed_if_terminal};

struct Entry {
    lease: SessionLease,
    updated_at: OffsetDateTime,
}

/// A [`LeaseStore`] backed by a mutex-guarded map.
pub struct MemoryLeaseStore {
    clock: Arc<dyn Clock>,
    leases: Mutex<HashMap<SessionId, Entry>>,
}

impl Default for MemoryLeaseStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryLeaseStore {
    /// An empty store using the system clock for `updated_at` bookkeeping.
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    /// An empty store whose write timestamps (used by `purge_terminal`) come from `clock`.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            leases: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, HashMap<SessionId, Entry>>> {
        self.leases
            .lock()
            .map_err(|_| Error::Internal("lease store lock poisoned".into()))
    }
}

#[async_trait]
impl LeaseStore for MemoryLeaseStore {
    async fn insert(&self, lease: &SessionLease) -> Result<()> {
        let now = self.clock.now();
        let mut map = self.lock()?;
        if map.contains_key(&lease.session_id) {
            return Err(Error::Conflict(format!(
                "lease {} already exists",
                lease.session_id
            )));
        }
        map.insert(
            lease.session_id,
            Entry {
                lease: scrubbed_if_terminal(lease).unwrap_or_else(|| lease.clone()),
                updated_at: now,
            },
        );
        Ok(())
    }

    async fn get(&self, id: SessionId) -> Result<Option<SessionLease>> {
        Ok(self.lock()?.get(&id).map(|e| e.lease.clone()))
    }

    async fn compare_and_swap(&self, expected: Generation, lease: &SessionLease) -> Result<()> {
        let now = self.clock.now();
        let mut map = self.lock()?;
        let entry = map
            .get_mut(&lease.session_id)
            .ok_or_else(|| Error::NotFound(format!("lease {}", lease.session_id)))?;
        check_cas(entry.lease.generation, expected, lease)?;
        entry.lease = scrubbed_if_terminal(lease).unwrap_or_else(|| lease.clone());
        entry.updated_at = now;
        Ok(())
    }

    async fn list(
        &self,
        owner: Option<&str>,
        statuses: Option<&[SessionStatus]>,
    ) -> Result<Vec<SessionLease>> {
        let map = self.lock()?;
        let mut out: Vec<SessionLease> = map
            .values()
            .map(|e| &e.lease)
            .filter(|l| owner.is_none_or(|o| l.owner == o))
            .filter(|l| statuses.is_none_or(|s| s.contains(&l.status)))
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.session_id.cmp(&b.session_id))
        });
        Ok(out)
    }

    async fn purge_terminal(&self, older_than: OffsetDateTime) -> Result<u64> {
        let mut map = self.lock()?;
        let before = map.len();
        map.retain(|_, e| !(e.lease.status.is_terminal() && e.updated_at < older_than));
        Ok(u64::try_from(before - map.len()).unwrap_or(u64::MAX))
    }
}
