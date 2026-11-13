//! Storage traits. Implementations live in `browserx-store`.

use async_trait::async_trait;

use crate::error::Result;
use crate::ids::{Generation, ProfileId, SessionId};
use crate::lease::{SessionLease, SessionStatus};
use crate::snapshot::{Snapshot, SnapshotMeta};

/// The lease registry: the single source of truth for session ownership.
#[async_trait]
pub trait LeaseStore: Send + Sync + 'static {
    /// Inserts a new lease. Fails with `Conflict` if the id exists.
    async fn insert(&self, lease: &SessionLease) -> Result<()>;

    /// Loads one lease.
    async fn get(&self, id: SessionId) -> Result<Option<SessionLease>>;

    /// Replaces the stored lease only if its generation still equals `expected`.
    /// The caller decides the new generation (`expected` or `expected.next()`).
    /// Returns `StaleGeneration` when another writer advanced the lease.
    async fn compare_and_swap(&self, expected: Generation, lease: &SessionLease) -> Result<()>;

    /// Lists leases, optionally filtered by owner and/or status.
    async fn list(
        &self,
        owner: Option<&str>,
        statuses: Option<&[SessionStatus]>,
    ) -> Result<Vec<SessionLease>>;

    /// Deletes terminal leases older than the retention window. Returns how many.
    async fn purge_terminal(&self, older_than: time::OffsetDateTime) -> Result<u64>;
}

/// Encrypted snapshot storage. Never sees plaintext.
#[async_trait]
pub trait SnapshotStore: Send + Sync + 'static {
    /// Stores a snapshot. Fails with `Conflict` if `meta.version` is not newer
    /// than the latest stored version for the profile.
    async fn put(&self, snapshot: &Snapshot) -> Result<()>;

    /// The newest snapshot of a profile.
    async fn latest(&self, profile: ProfileId) -> Result<Option<Snapshot>>;

    /// Metadata of all retained snapshots, newest first.
    async fn list(&self, profile: ProfileId) -> Result<Vec<SnapshotMeta>>;

    /// Keeps the newest `keep` versions and deletes the rest. Returns how many were deleted.
    async fn prune(&self, profile: ProfileId, keep: usize) -> Result<u64>;

    /// Deletes every snapshot of a profile (erasure).
    async fn delete_profile(&self, profile: ProfileId) -> Result<u64>;
}
