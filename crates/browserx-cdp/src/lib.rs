//! A bounded Chrome DevTools Protocol client.
//!
//! [`CdpClient`] multiplexes commands over one WebSocket: it assigns command ids,
//! keeps a bounded map of pending calls, enforces a per-command timeout, routes
//! replies through one-shot channels and fans events out on a broadcast channel.
//! Flattened sessions are supported by passing a `sessionId` per call and reading
//! it back on every [`CdpEvent`].
//!
//! Every resource is bounded: pending calls (`max_pending`), message size in both
//! directions (`max_message_bytes`), the outbound queue, and the event buffer. When
//! the connection ends for any reason, all pending calls fail with
//! [`CdpError::Closed`] (or [`CdpError::MessageTooLarge`]) instead of hanging.

mod client;
mod error;

pub use client::{CdpClient, CdpEvent, CdpLimits};
pub use error::CdpError;
