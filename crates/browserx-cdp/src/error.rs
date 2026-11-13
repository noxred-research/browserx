//! Typed errors of the CDP client.

use std::time::Duration;

/// Everything that can go wrong talking to a browser over CDP.
#[derive(Debug, thiserror::Error)]
pub enum CdpError {
    /// The WebSocket handshake failed or timed out.
    #[error("cdp connect failed: {0}")]
    Connect(String),
    /// The connection is closed (by us, by the browser, or after a transport error).
    /// Every call still pending when the reader ends fails with this error.
    #[error("cdp connection closed: {0}")]
    Closed(String),
    /// The command got no reply within the per-command timeout.
    #[error("cdp command {method} timed out after {timeout:?}")]
    Timeout {
        /// The CDP method that timed out.
        method: String,
        /// The configured per-command timeout.
        timeout: Duration,
    },
    /// Too many commands are already awaiting a reply.
    #[error("too many pending cdp commands (limit {limit})")]
    TooManyPending {
        /// The configured `max_pending`.
        limit: usize,
    },
    /// A message exceeded the configured size limit (outbound command or inbound frame).
    #[error("cdp message exceeds the {limit} byte limit")]
    MessageTooLarge {
        /// The configured `max_message_bytes`.
        limit: usize,
    },
    /// The browser answered a command with a protocol error object.
    #[error("cdp error {code} in {method}: {message}")]
    Protocol {
        /// The CDP method that failed.
        method: String,
        /// CDP error code.
        code: i64,
        /// CDP error message.
        message: String,
    },
    /// The command could not be encoded.
    #[error("cannot encode cdp command: {0}")]
    Encode(String),
}

impl From<CdpError> for browserx_core::Error {
    fn from(err: CdpError) -> Self {
        match err {
            CdpError::Timeout { .. } => Self::Timeout(err.to_string()),
            other => Self::Browser(other.to_string()),
        }
    }
}
