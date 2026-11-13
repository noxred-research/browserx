//! Lifecycle events broadcast by the pool (consumed by the relay and metrics).

use browserx_core::{Generation, RecoveryOutcome, SessionId};

/// What happened to a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolEventKind {
    /// Allocated and persisted.
    Created,
    /// A controller attached.
    Attached,
    /// The last relay connection closed.
    Detached,
    /// Lease expiry extended.
    Renewed,
    /// Control moved to a new token and generation.
    HandedOff,
    /// A snapshot was written.
    Snapshotted,
    /// The backing browser was lost; replacement in progress.
    Recovering,
    /// A replacement browser is serving the session (new generation).
    Recovered,
    /// The session ended without a clean release.
    Lost,
    /// Release started.
    Draining,
    /// Release finished.
    Closed,
}

/// One lifecycle event.
#[derive(Clone, Debug)]
pub struct PoolEvent {
    /// Affected session.
    pub session_id: SessionId,
    /// What happened.
    pub kind: PoolEventKind,
    /// Lease generation after the event.
    pub generation: Generation,
    /// Recovery outcome, for `Recovered`.
    pub outcome: Option<RecoveryOutcome>,
}
