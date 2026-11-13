//! Resource limits of the listeners and the relay, and the relay connection table.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use browserx_core::{Error, Result, SessionId};

use crate::api::AppState;

/// Default cap on relay connections per session.
pub const DEFAULT_RELAY_CONNECTIONS_PER_SESSION: usize = 4;
/// Default largest WebSocket message on a shared-session relay.
pub const DEFAULT_SCOPED_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// Default time a client has to send a complete request head.
pub const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Default cap on open connections of the API listener.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;
/// Default cap on open connections of the operations listener.
pub const DEFAULT_OPS_MAX_CONNECTIONS: usize = 64;

/// Limits applied by the listeners and the relay.
#[derive(Clone, Debug)]
pub struct ServerLimits {
    /// Open relay connections one session may have.
    pub relay_connections_per_session: usize,
    /// Largest WebSocket message, in bytes, on a shared-session relay.
    pub scoped_relay_max_message_bytes: usize,
    /// Time a client has to send a complete request head.
    pub header_read_timeout: Duration,
    /// Open connections the API listener keeps; further ones are closed at once.
    pub max_connections: usize,
    /// Open connections the operations listener keeps.
    pub ops_max_connections: usize,
    /// Absolute directory under which each session gets its download directory.
    pub download_root: PathBuf,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            relay_connections_per_session: DEFAULT_RELAY_CONNECTIONS_PER_SESSION,
            scoped_relay_max_message_bytes: DEFAULT_SCOPED_MESSAGE_BYTES,
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            ops_max_connections: DEFAULT_OPS_MAX_CONNECTIONS,
            download_root: std::env::temp_dir().join("browserx-downloads"),
        }
    }
}

/// Relay limits plus the count of open relay connections per session.
#[derive(Default)]
pub struct RelayHub {
    limits: RwLock<Arc<ServerLimits>>,
    conns: Mutex<HashMap<SessionId, usize>>,
}

impl RelayHub {
    pub(crate) fn limits(&self) -> Arc<ServerLimits> {
        self.limits
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_limits(&self, limits: ServerLimits) {
        *self.limits.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(limits);
    }

    fn release(&self, id: SessionId) -> bool {
        let mut conns = self.conns.lock().unwrap_or_else(PoisonError::into_inner);
        match conns.get_mut(&id) {
            Some(n) if *n > 1 => {
                *n -= 1;
                false
            }
            Some(_) => {
                conns.remove(&id);
                true
            }
            None => false,
        }
    }
}

impl AppState {
    /// Replaces the listener and relay limits (defaults apply until this is called).
    pub fn set_limits(&self, limits: ServerLimits) {
        self.inner.relay.set_limits(limits);
    }

    /// The limits in force.
    #[must_use]
    pub fn limits(&self) -> Arc<ServerLimits> {
        self.inner.relay.limits()
    }

    /// Counts one more relay connection of `id`, or refuses when it has too many.
    pub(crate) fn acquire_relay_slot(&self, id: SessionId) -> Result<RelaySlot> {
        let max = self.limits().relay_connections_per_session;
        let mut conns = self
            .inner
            .relay
            .conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let open = conns.entry(id).or_insert(0);
        if *open >= max {
            if *open == 0 {
                conns.remove(&id);
            }
            return Err(Error::Capacity(format!(
                "session {id} already has {max} open relay connections"
            )));
        }
        *open += 1;
        Ok(RelaySlot {
            app: self.clone(),
            id: Some(id),
        })
    }
}

/// One counted relay connection; released on drop.
pub(crate) struct RelaySlot {
    app: AppState,
    id: Option<SessionId>,
}

impl RelaySlot {
    /// Releases the slot; true when it was the session's last open relay connection.
    pub(crate) fn release(mut self) -> bool {
        self.id
            .take()
            .is_some_and(|id| self.app.inner.relay.release(id))
    }
}

impl Drop for RelaySlot {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.app.inner.relay.release(id);
        }
    }
}
