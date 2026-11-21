//! Per-session loopback egress forwarder.
//!
//! A browser is pointed at `http://127.0.0.1:<port>` (see
//! [`Forwarder::proxy_server`]) and never learns the real upstream or its
//! credentials. The forwarder accepts two kinds of proxy requests:
//!
//! * `CONNECT host:port`: a raw tunnel (HTTPS, WebSockets, anything);
//! * absolute-form `GET http://host/path` (and other methods): plain HTTP, which
//!   the forwarder rewrites to origin-form and sends through a tunnel to the
//!   destination, one request per connection (`Connection: close`).
//!
//! Both are turned into a tunnel to the destination through the configured
//! [`ProxyRoute`]:
//!
//! | upstream            | behavior                                                         |
//! |---------------------|------------------------------------------------------------------|
//! | none                | direct dial after local DNS, destination policy enforced         |
//! | `http://`           | `CONNECT` with `Proxy-Authorization: Basic`                      |
//! | `https://`          | same, over TLS to the proxy (system-independent built-in roots)  |
//! | `socks5://`         | SOCKS5 with local DNS; the policy checks the resolved address    |
//! | `socks5h://`        | SOCKS5 with remote DNS; only literals can be checked locally     |
//!
//! Because plain-HTTP requests also travel as `CONNECT` to the upstream, gateways
//! that only allow `CONNECT` work for `http://` pages as well.
//!
//! The upstream username is rendered from the route template: `{session}` becomes
//! the sticky key and `{generation}` the lease generation, so an upstream pool
//! that pins exits by username keeps one exit per session.
//!
//! ## Limits and guarantees
//!
//! Request heads are limited to 16 KiB; connecting (including upstream
//! handshakes) to 15 s; idle tunnels are closed after 5 minutes; at most 512
//! connections run at once, further ones receive `503`. Policy refusals answer
//! `403`, upstream failures `502`/`504`, malformed requests `400`. Credentials
//! are never logged and never appear in error responses.
//!
//! ## Trust boundary
//!
//! The listener binds `127.0.0.1` only, but any local process can connect to it
//! and borrow the upstream route; browsers cannot authenticate to a proxy through
//! a command-line flag. Run the worker on a host where local processes are
//! trusted, or in its own network namespace.

mod forwarder;
#[doc(hidden)]
pub mod fuzzing;
mod http;
mod policy;
mod relay;
mod upstream;

pub use browserx_core::ProxyRoute;
pub use forwarder::{Forwarder, ForwarderOptions, ForwarderStats};
pub use policy::EgressPolicy;
