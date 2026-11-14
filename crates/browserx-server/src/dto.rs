//! JSON shapes of the HTTP API.

use std::collections::BTreeMap;

use browserx_core::{
    Isolation, PersistenceMode, RecoveryOutcome, RecoveryPolicy, SessionLease, SessionStatus,
    SnapshotMeta,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// What a client may see of a lease. Internal identifiers (worker, context,
/// token digest) are not exposed.
#[derive(Debug, Serialize, Deserialize)]
pub struct LeaseView {
    /// Session id (`ses_...`).
    pub session_id: String,
    /// Owner name.
    pub owner: String,
    /// Lifecycle state.
    pub status: SessionStatus,
    /// Current fencing generation.
    pub generation: u64,
    /// Isolation.
    pub isolation: Isolation,
    /// Persistence mode.
    pub persistence: PersistenceMode,
    /// Recovery policy.
    pub recovery: RecoveryPolicy,
    /// Launch profile requested (`null` = server default).
    pub launch_profile: Option<String>,
    /// Persistent identity (`prf_...`), when persistence is not ephemeral.
    pub profile_id: Option<String>,
    /// Newest snapshot version of the profile.
    pub snapshot_version: Option<u64>,
    /// How the session reached its current browser.
    pub last_recovery: Option<RecoveryOutcome>,
    /// How many times the browser was replaced.
    pub recoveries: u32,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Lease expiry.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Absolute lifetime cap.
    #[serde(with = "time::serde::rfc3339")]
    pub max_expires_at: OffsetDateTime,
    /// Last attach or detach.
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub last_attach_at: Option<OffsetDateTime>,
    /// Reason of the latest terminal or recovery transition.
    pub reason: Option<String>,
    /// Caller's labels.
    pub labels: BTreeMap<String, String>,
}

impl From<&SessionLease> for LeaseView {
    fn from(l: &SessionLease) -> Self {
        Self {
            session_id: l.session_id.prefixed(),
            owner: l.owner.clone(),
            status: l.status,
            generation: l.generation.0,
            isolation: l.spec.isolation,
            persistence: l.spec.persistence,
            recovery: l.spec.recovery,
            launch_profile: l.spec.launch_profile.clone(),
            profile_id: l.profile_id.map(|p| p.prefixed()),
            snapshot_version: l.snapshot_version,
            last_recovery: l.last_recovery,
            recoveries: l.recoveries,
            created_at: l.created_at,
            expires_at: l.expires_at,
            max_expires_at: l.max_expires_at,
            last_attach_at: l.last_attach_at,
            reason: l.reason.clone(),
            labels: l.spec.labels.clone(),
        }
    }
}

/// Snapshot metadata as exposed to clients.
#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotView {
    /// Profile (`prf_...`).
    pub profile_id: String,
    /// Monotonic version.
    pub version: u64,
    /// Writer session.
    pub session_id: String,
    /// Writer generation.
    pub generation: u64,
    /// Capture time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Sealed size in bytes.
    pub size: u64,
    /// Key that sealed it.
    pub key_id: String,
}

impl From<&SnapshotMeta> for SnapshotView {
    fn from(m: &SnapshotMeta) -> Self {
        Self {
            profile_id: m.profile_id.prefixed(),
            version: m.version,
            session_id: m.session_id.prefixed(),
            generation: m.generation.0,
            created_at: m.created_at,
            size: m.size,
            key_id: m.key_id.clone(),
        }
    }
}

/// Body of `POST /v1/sessions/{id}/renew`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewBody {
    /// Generation the caller holds.
    pub generation: u64,
    /// New TTL in seconds (default: the session's own TTL).
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

/// Body of `POST /v1/sessions/{id}/handoff`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffBody {
    /// Generation the caller holds.
    pub generation: u64,
}
