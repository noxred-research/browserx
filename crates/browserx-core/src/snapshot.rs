//! Logical browser state snapshots: cookies and per-origin storage.
//!
//! A snapshot is portable authentication state, not a process checkpoint. It is
//! encrypted before it reaches a [`crate::SnapshotStore`]; stores only ever see
//! ciphertext plus metadata.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ids::{Generation, ProfileId, SessionId};

/// Current plaintext format version. Readers refuse newer versions.
pub const STATE_FORMAT_VERSION: u32 = 1;

/// One cookie, in the shape CDP `Network.getAllCookies` reports and
/// `Network.setCookies` accepts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieRecord {
    /// Name.
    pub name: String,
    /// Value. Treat snapshots as credentials.
    pub value: String,
    /// Domain.
    pub domain: String,
    /// Path.
    pub path: String,
    /// Expiry as seconds since the epoch; negative or absent for session cookies.
    #[serde(default)]
    pub expires: Option<f64>,
    /// HttpOnly flag.
    #[serde(default)]
    pub http_only: bool,
    /// Secure flag.
    #[serde(default)]
    pub secure: bool,
    /// SameSite policy (`Strict`, `Lax`, `None`).
    #[serde(default)]
    pub same_site: Option<String>,
}

/// Storage captured for one origin.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OriginStorage {
    /// Origin, e.g. `https://example.test`.
    pub origin: String,
    /// `localStorage` entries.
    #[serde(default)]
    pub local_storage: Vec<(String, String)>,
}

/// The plaintext captured from a browser.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Format version of this structure.
    pub format_version: u32,
    /// Browser product/version string at capture time.
    pub browser_version: String,
    /// All cookies of the captured browser context.
    pub cookies: Vec<CookieRecord>,
    /// Storage for the origins that were open at capture time. Origins that were
    /// never opened during the session are not enumerated.
    pub origins: Vec<OriginStorage>,
    /// URLs of the top-level pages at capture time (reopened on restore).
    #[serde(default)]
    pub open_urls: Vec<String>,
}

/// Metadata stored next to the ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMeta {
    /// Persistent identity the snapshot belongs to.
    pub profile_id: ProfileId,
    /// Monotonic version within the profile (1, 2, ...).
    pub version: u64,
    /// Session and generation that wrote it (stale writers are refused).
    pub session_id: SessionId,
    /// Generation of the writer.
    pub generation: Generation,
    /// Capture time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Ciphertext length in bytes.
    pub size: u64,
    /// Identifier of the key that encrypted it (supports key rotation).
    pub key_id: String,
}

/// Encrypted snapshot: metadata plus `nonce || ciphertext || tag`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Metadata.
    pub meta: SnapshotMeta,
    /// AES-256-GCM sealed payload.
    pub sealed: Vec<u8>,
}
