//! A Model Context Protocol server for BrowserX: AI agents can watch, drive and explain BrowserX
//! within limits an operator sets.
//!
//! * **Monitor** (always on, read-only): health, pool status over a window, graded assessment
//!   with remediation, session views and deterministic explanations of statuses, recovery
//!   outcomes and errors.
//! * **Manage** (capabilities `sessions`, `handoff`): create, renew, snapshot, release and hand
//!   off sessions. The server holds the lease tokens; the model never sees them.
//! * **Browse and interact** (capabilities `browse`, `interact`, `evaluate`): the server connects
//!   to a controlled session's CDP endpoint itself and offers accessibility snapshots with stable
//!   element references, readable text, screenshots, network and console logs and interactions.
//!   Navigation is confined to operator-configured origins, checked before and after redirects.
//! * **Advise** (optional `[ai]`): summaries, structured extraction and a diagnosis narrative
//!   through any chat-completions compatible endpoint, with deterministic fallbacks.
//!
//! Models advise and act through scoped tools; they never authorize. Leases, recovery, egress
//! policy and the host-protection relay policy stay deterministic code in the BrowserX server;
//! no model sits in the data path. Page content is untrusted and always wrapped as such; every
//! call lands in a hash-chained audit log.
//!
//! Two transports share one protocol engine: newline-delimited JSON-RPC on stdio ([`stdio`]) and
//! streamable HTTP with a bearer token ([`http`]). The entry point of the binary is [`run`].

#![deny(missing_docs)]

mod assess;
pub mod audit;
mod backend;
mod browse;
mod cli;
pub mod config;
mod ctx;
mod error;
mod explain;
pub mod http;
mod llm;
mod metrics;
mod prompts;
pub mod protocol;
mod redact;
mod resources;
mod safety;
mod schema;
pub mod server;
mod sessions;
pub mod stdio;
#[cfg(test)]
mod testing;
mod tools;

pub use cli::{McpArgs, McpCommand, run};
pub use config::Config;
pub use ctx::Ctx;
pub use error::McpError;
pub use server::Server;
