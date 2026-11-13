//! Browsing over a session's CDP endpoint: one [`Conn`] per controlled session, created on first
//! use and re-created through `attach` when the browser was recovered.

mod act;
mod ax;
mod conn;
mod features;
mod page;
mod scripts;
mod snapshot;

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use browserx_core::Secret;
use tokio::sync::OwnedMutexGuard;

pub use act::{ActionOutcome, Direction, ScrollRequest, SelectBy};
pub use ax::parse_ref;
pub use conn::{Conn, TabRef};
pub use page::{NetFilter, WaitFor};
pub use snapshot::{FindQuery, MAX_FIND_LIMIT, SnapshotRequest};

use crate::backend::Backend;
use crate::config::BrowseSection;
use crate::error::{ToolError, ToolResult};
use crate::safety::Scope;

/// Bounds of browsing.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Per-command CDP timeout.
    pub command_timeout: Duration,
    /// How long a navigation or an action may wait for the page to settle.
    pub navigation_timeout: Duration,
    /// Tabs per session.
    pub max_tabs: usize,
    /// Network log entries per tab.
    pub net_entries: usize,
    /// Console messages per tab.
    pub console_entries: usize,
    /// Largest CDP message accepted.
    pub max_message_bytes: usize,
    /// Largest screenshot returned, in bytes.
    pub max_screenshot_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            command_timeout: Duration::from_secs(20),
            navigation_timeout: Duration::from_secs(30),
            max_tabs: 8,
            net_entries: 500,
            console_entries: 200,
            max_message_bytes: 32 * 1024 * 1024,
            max_screenshot_bytes: 2 * 1024 * 1024,
        }
    }
}

impl Limits {
    /// Limits from the `[browse]` section.
    #[must_use]
    pub fn from_config(browse: &BrowseSection) -> Self {
        Self {
            command_timeout: Duration::from_secs(browse.command_timeout_secs),
            navigation_timeout: Duration::from_secs(browse.navigation_timeout_secs),
            max_tabs: browse.max_tabs,
            net_entries: browse.network_log_entries,
            console_entries: browse.console_log_entries,
            ..Self::default()
        }
    }
}

type Slot = Arc<tokio::sync::Mutex<Option<Arc<Conn>>>>;

/// The connections of every controlled session.
pub struct Hub {
    limits: Limits,
    scope: Arc<Scope>,
    slots: Mutex<HashMap<String, Slot>>,
}

/// Exclusive use of one session's connection. Operations on a session run one at a time; the
/// handle releases the session when dropped.
pub struct Handle {
    _guard: OwnedMutexGuard<Option<Arc<Conn>>>,
    conn: Arc<Conn>,
    /// Set when the browser connection was re-established: what the model must know.
    pub notice: Option<String>,
}

impl Deref for Handle {
    type Target = Conn;
    fn deref(&self) -> &Conn {
        &self.conn
    }
}

impl Hub {
    /// A hub whose connections enforce `scope`.
    #[must_use]
    pub fn new(limits: Limits, scope: Arc<Scope>) -> Self {
        Self {
            limits,
            scope,
            slots: Mutex::new(HashMap::new()),
        }
    }

    fn slot(&self, session_id: &str) -> Slot {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(session_id.to_owned())
            .or_default()
            .clone()
    }

    /// Locks the session's connection, (re)connecting through `attach` when there is none or the
    /// browser went away.
    ///
    /// # Errors
    /// When attaching or connecting fails.
    pub async fn connection(
        &self,
        session_id: &str,
        token: &Secret,
        backend: &Backend,
    ) -> ToolResult<Handle> {
        let mut guard = self.slot(session_id).lock_owned().await;
        let had_connection = guard.is_some();
        if let Some(conn) = guard.as_ref()
            && !conn.is_closed()
        {
            return Ok(Handle {
                conn: Arc::clone(conn),
                _guard: guard,
                notice: None,
            });
        }
        let attached = backend
            .attach(session_id, token)
            .await
            .map_err(ToolError::from)?;
        let conn = Arc::new(
            Conn::connect(
                attached.cdp_url.expose(),
                self.limits,
                Arc::clone(&self.scope),
            )
            .await?,
        );
        let notice = (had_connection || attached.outcome != "resumed_same_process").then(|| {
            let meaning = match attached.outcome.as_str() {
                "resumed_same_process" => "the same browser process is still running; open pages are intact",
                "restored_from_profile" => "the browser was replaced and reopened on its profile directory: cookies and storage persisted, open pages and JavaScript state did not",
                "restored_from_snapshot" => "the browser was replaced and a snapshot was replayed: cookies, localStorage and page URLs came back, JavaScript state did not",
                _ => "the browser was replaced by an empty one: nothing was restored",
            };
            format!(
                "The browser connection was re-established (recovery outcome: {}): {meaning}. Earlier element refs are invalid; take a new page_snapshot.",
                attached.outcome
            )
        });
        *guard = Some(Arc::clone(&conn));
        Ok(Handle {
            conn,
            _guard: guard,
            notice,
        })
    }

    /// Closes and forgets a session's connection.
    pub async fn forget(&self, session_id: &str) {
        let slot = self
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(session_id);
        if let Some(slot) = slot {
            let conn = slot.lock().await.take();
            if let Some(conn) = conn {
                conn.close().await;
            }
        }
    }

    /// Closes every connection.
    pub async fn close_all(&self) {
        let ids: Vec<String> = self
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        for id in ids {
            self.forget(&id).await;
        }
    }
}
