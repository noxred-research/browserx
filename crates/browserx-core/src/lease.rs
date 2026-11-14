//! The durable lease record and its state machine.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::ids::{BrowserId, ContextId, Generation, ProfileId, SessionId, WorkerId};
use crate::spec::{RecoveryOutcome, SessionSpec};

/// Lifecycle states.
///
/// ```text
/// queued -> allocating -> active <-> idle
///                           |  \      |
///                           |   +-> recovering -> active
///                           v         |
///                        draining     v
///                           |        lost
///                           v
///                         closed
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Admitted, waiting for capacity.
    Queued,
    /// A browser is being launched or a context created.
    Allocating,
    /// A controller is attached (or was within the idle window).
    Active,
    /// Running, no controller attached.
    Idle,
    /// The browser was lost; a replacement is being launched and restored.
    Recovering,
    /// Release requested: final snapshot, cleanup, then `closed`.
    Draining,
    /// The browser was lost and recovery is disabled or failed. Terminal.
    Lost,
    /// Released and cleaned up. Terminal.
    Closed,
}

impl SessionStatus {
    /// Terminal states never change again.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Lost | Self::Closed)
    }

    /// States in which a controller may attach.
    #[must_use]
    pub fn is_attachable(self) -> bool {
        matches!(self, Self::Active | Self::Idle)
    }

    /// Whether `self -> next` is a legal transition.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        use SessionStatus::*;
        if self == next {
            return !self.is_terminal();
        }
        match self {
            Queued => matches!(next, Allocating | Closed),
            Allocating => matches!(next, Active | Idle | Lost | Closed | Draining),
            Active => matches!(next, Idle | Recovering | Draining | Lost),
            Idle => matches!(next, Active | Recovering | Draining | Lost),
            Recovering => matches!(next, Active | Idle | Lost | Draining),
            Draining => matches!(next, Closed | Lost),
            Lost | Closed => false,
        }
    }
}

/// The registry record for one session. Stored as a whole and replaced with
/// compare-and-swap on `generation`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLease {
    /// Public stable identity.
    pub session_id: SessionId,
    /// Authenticated principal that created the session (API key name).
    pub owner: String,
    /// The request as admitted.
    pub spec: SessionSpec,
    /// Lifecycle state.
    pub status: SessionStatus,
    /// Fencing counter; incremented by allocation, recovery and handoff.
    pub generation: Generation,
    /// Worker currently responsible for the browser, if any.
    pub worker_id: Option<WorkerId>,
    /// The browser process instance currently backing the session.
    pub browser_id: Option<BrowserId>,
    /// Browser context (shared-browser isolation only).
    pub context_id: Option<ContextId>,
    /// Persistent identity, when persistence is not ephemeral.
    pub profile_id: Option<ProfileId>,
    /// Version of the newest snapshot written for this session's profile.
    pub snapshot_version: Option<u64>,
    /// SHA-256 of the current controller token. Rotated on handoff.
    pub token_digest: Option<String>,
    /// How the session reached its current browser.
    pub last_recovery: Option<RecoveryOutcome>,
    /// Number of times the backing browser was replaced.
    pub recoveries: u32,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Lease expiry; renewals move it forward, never past `max_expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Absolute lifetime cap, independent of renewals and heartbeats.
    #[serde(with = "time::serde::rfc3339")]
    pub max_expires_at: OffsetDateTime,
    /// Last worker heartbeat for the backing browser.
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub last_heartbeat_at: Option<OffsetDateTime>,
    /// Last time a controller was attached or detached.
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub last_attach_at: Option<OffsetDateTime>,
    /// Human-readable reason for the latest terminal or recovery transition.
    pub reason: Option<String>,
}

impl SessionLease {
    /// Moves to `next` if the state machine allows it.
    pub fn transition(&mut self, next: SessionStatus, reason: Option<String>) -> Result<()> {
        if !self.status.can_transition_to(next) {
            return Err(Error::Conflict(format!(
                "session {} cannot go from {:?} to {:?}",
                self.session_id, self.status, next
            )));
        }
        self.status = next;
        if reason.is_some() {
            self.reason = reason;
        }
        Ok(())
    }

    /// Whether the lease has run past its expiry or absolute cap at `now`.
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at || now >= self.max_expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::SessionStatus::*;

    #[test]
    fn terminal_states_are_final() {
        for s in [Lost, Closed] {
            for n in [
                Queued, Allocating, Active, Idle, Recovering, Draining, Lost, Closed,
            ] {
                assert!(!s.can_transition_to(n), "{s:?} -> {n:?}");
            }
        }
    }

    #[test]
    fn recovery_paths() {
        assert!(Active.can_transition_to(Recovering));
        assert!(Recovering.can_transition_to(Active));
        assert!(Recovering.can_transition_to(Lost));
        assert!(!Queued.can_transition_to(Recovering));
        assert!(!Draining.can_transition_to(Active));
    }
}
