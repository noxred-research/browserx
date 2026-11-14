//! The boundary between the scheduler and a browser implementation.
//!
//! `browserx-runtime` implements it for locally supervised Chromium processes.
//! Any other provider (a remote browser service, a custom build) plugs in by
//! implementing the same two traits.

use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::ids::{BrowserId, ContextId};
use crate::snapshot::StateSnapshot;

/// Everything needed to start one browser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchRequest {
    /// Identity assigned by the scheduler.
    pub browser_id: BrowserId,
    /// Named launch profile from configuration; `None` = default.
    pub launch_profile: Option<String>,
    /// Dedicated user-data directory (profile persistence). The caller already
    /// holds the exclusive lock. `None` = a temporary directory owned by the handle.
    pub user_data_dir: Option<PathBuf>,
    /// Loopback proxy the browser must use (`http://127.0.0.1:<port>`), if any.
    pub proxy_server: Option<String>,
    /// Stable per-identity value substituted for `{persona_seed}` in launch-profile
    /// arguments. Derived with [`persona_seed`] from the profile id when the session
    /// has one (so a restored identity keeps the same seed), else from the session id.
    pub persona_seed: String,
}

/// Decimal seed derived from an identity: the first 8 bytes of
/// `SHA-256("browserx-persona:" + uuid)` as an unsigned integer. Digits only, so it
/// can never smuggle extra flags into a launch command line.
#[must_use]
pub fn persona_seed(identity: &uuid::Uuid) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("browserx-persona:{identity}").as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes).to_string()
}

/// Liveness as observed by the runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum RuntimeHealth {
    /// The process is alive and answered a protocol ping.
    Healthy,
    /// The process is alive but did not answer within the probe deadline.
    Unresponsive {
        /// What failed.
        detail: String,
    },
    /// The process has exited (or the remote browser is gone).
    Exited {
        /// Exit status or reason, when known.
        detail: String,
    },
}

/// A running browser.
#[async_trait]
pub trait BrowserHandle: Send + Sync + 'static {
    /// Scheduler-assigned identity.
    fn id(&self) -> BrowserId;

    /// Browser-level DevTools WebSocket URL (loopback). Privileged: it controls
    /// every context. Never handed to clients directly; the relay scopes access.
    fn browser_ws_url(&self) -> &str;

    /// Product/version string reported by the browser.
    fn version(&self) -> &str;

    /// OS process id, when the runtime owns a local process.
    fn pid(&self) -> Option<u32>;

    /// Probes liveness with a bounded protocol round trip.
    async fn health(&self) -> RuntimeHealth;

    /// Creates an isolated browser context (shared-browser isolation).
    async fn create_context(&self) -> Result<ContextId>;

    /// Disposes a browser context and every target in it.
    async fn dispose_context(&self, context: &ContextId) -> Result<()>;

    /// Captures cookies and storage of the open origins. `context` = `None`
    /// captures the default context.
    async fn capture_state(&self, context: Option<&ContextId>) -> Result<StateSnapshot>;

    /// Replays a snapshot into a context (default context when `None`).
    async fn restore_state(&self, context: Option<&ContextId>, state: &StateSnapshot)
    -> Result<()>;

    /// Closes the browser and returns only once the process is confirmed gone
    /// (or returns an error if death could not be confirmed). Idempotent.
    async fn shutdown_confirmed(&self) -> Result<()>;
}

/// Starts browsers.
#[async_trait]
pub trait BrowserRuntime: Send + Sync + 'static {
    /// Launches a browser and waits until its DevTools endpoint answers.
    async fn launch(&self, request: LaunchRequest) -> Result<Box<dyn BrowserHandle>>;

    /// Names of the launch profiles this runtime can start.
    fn launch_profiles(&self) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::persona_seed;

    #[test]
    fn persona_seed_is_stable_digits_per_identity() {
        let a = uuid::Uuid::from_u128(1);
        let b = uuid::Uuid::from_u128(2);
        assert_eq!(persona_seed(&a), persona_seed(&a));
        assert_ne!(persona_seed(&a), persona_seed(&b));
        assert!(persona_seed(&a).bytes().all(|c| c.is_ascii_digit()));
    }
}
