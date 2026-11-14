//! Typed errors shared across crates. Each variant maps to one HTTP status in
//! the server so clients can branch on cause rather than on message text.

use crate::ids::Generation;

/// Result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Every error a BrowserX component reports across a crate boundary.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The request is malformed or names an unsupported combination.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Missing or wrong credential.
    #[error("unauthorized")]
    Unauthorized,
    /// The credential is valid but does not grant this operation.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// No such session, profile or snapshot.
    #[error("not found: {0}")]
    NotFound(String),
    /// Compare-and-swap lost: someone else advanced the lease.
    #[error("stale generation: expected {expected}, found {found}")]
    StaleGeneration {
        /// The generation the caller held.
        expected: Generation,
        /// The generation now stored.
        found: Generation,
    },
    /// The lease or its state forbids the operation (closed, draining, wrong status).
    #[error("conflict: {0}")]
    Conflict(String),
    /// Admission refused: queue full, owner quota reached or wait deadline passed.
    #[error("capacity exhausted: {0}")]
    Capacity(String),
    /// A profile directory is held by another browser.
    #[error("profile locked: {0}")]
    ProfileLocked(String),
    /// The browser runtime failed (launch, crash, protocol).
    #[error("browser: {0}")]
    Browser(String),
    /// A bounded operation ran out of time.
    #[error("timed out: {0}")]
    Timeout(String),
    /// Storage backend failure.
    #[error("storage: {0}")]
    Storage(String),
    /// Snapshot encryption or integrity failure. Never carries key material.
    #[error("crypto: {0}")]
    Crypto(String),
    /// Upstream proxy / egress failure.
    #[error("egress: {0}")]
    Egress(String),
    /// The service is shutting down.
    #[error("shutting down")]
    ShuttingDown,
    /// A bug or an unexpected internal state.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Stable machine-readable code used in API error bodies and metrics labels.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::NotFound(_) => "not_found",
            Self::StaleGeneration { .. } => "stale_generation",
            Self::Conflict(_) => "conflict",
            Self::Capacity(_) => "capacity",
            Self::ProfileLocked(_) => "profile_locked",
            Self::Browser(_) => "browser",
            Self::Timeout(_) => "timeout",
            Self::Storage(_) => "storage",
            Self::Crypto(_) => "crypto",
            Self::Egress(_) => "egress",
            Self::ShuttingDown => "shutting_down",
            Self::Internal(_) => "internal",
        }
    }
}
