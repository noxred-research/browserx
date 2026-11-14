//! BrowserX HTTP server.
//!
//! * [`api_router`]: the JSON API under `/v1` and the authenticated CDP relay at
//!   `/cdp/{session_id}/{token}`.
//! * [`ops_router`]: `/healthz`, `/readyz` and Prometheus `/metrics`.
//! * [`Config`]: the TOML configuration; [`run`] wires everything and serves.
//!
//! Every relay connection passes the host-protection policy (see [`host_policy`]):
//! no `file:` or internal-page navigation, no per-context proxy overrides, no
//! host file selection, downloads confined to a per-session directory. Dedicated
//! sessions otherwise get a transparent relay to the browser-level DevTools
//! endpoint. Shared-browser sessions get a scoped relay (see [`scope`]) that
//! confines a cooperative client to its own browser context; it is not a
//! boundary against a hostile tenant.
//!
//! Transport is plaintext WebSocket/HTTP. Terminate TLS in front of the server
//! for any use beyond a trusted network or loopback.

mod api;
mod auth;
mod config;
mod dto;
mod error;
pub mod hardening;
pub mod host_policy;
mod limits;
mod listener;
mod ops;
mod relay;
mod run;
pub mod scope;

pub use api::{AppState, Owner, ReadyProbe, TOKEN_HEADER, api_router};
pub use auth::{Authenticator, key_digest};
pub use config::{
    ApiKeyConfig, AuthSection, Config, HealthSection, PoolSection, ServerSection, SessionSection,
    StorageSection,
};
pub use dto::{LeaseView, SnapshotView};
pub use error::{ApiError, status_of};
pub use limits::ServerLimits;
pub use ops::{ops_router, render_metrics};
pub use relay::MAX_MESSAGE_BYTES;
pub use run::{build, ping_lease_registry, run, serve, shutdown_signal};
