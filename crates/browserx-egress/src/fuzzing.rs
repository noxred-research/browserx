//! Entry points for the cargo-fuzz targets in `fuzz/`. Not part of the API.
//!
//! The forwarder reads a browser's proxy request and an upstream proxy's reply from the
//! network; these wrappers expose its parsers with plain return types.

use crate::EgressPolicy;
use crate::http;

/// A parsed request head: method, target and header count.
pub fn request_head(head: &[u8]) -> Result<(String, String, usize), &'static str> {
    match http::parse_head(head) {
        Ok(raw) => Ok((raw.method, raw.target, raw.headers.len())),
        Err(http::HeadError::Bad(why)) => Err(why),
        Err(_) => Err("head refused"),
    }
}

/// Status code of an upstream reply head.
#[must_use]
pub fn reply_status(head: &[u8]) -> Option<u16> {
    http::parse_status(head)
}

/// A `CONNECT` authority, normalized as the forwarder dials it (`host:port`, IPv6 bracketed).
pub fn connect_authority(authority: &str) -> Result<String, &'static str> {
    let (host, port) = http::parse_connect_authority(authority)?;
    Ok(host.authority(port))
}

/// An absolute-form `http://` target: dialed authority, `Host` header value and origin-form path.
pub fn absolute_target(target: &str) -> Result<(String, String, String), &'static str> {
    let parsed = http::parse_absolute_http(target)?;
    Ok((
        parsed.host.authority(parsed.port),
        parsed.host_header,
        parsed.path,
    ))
}

/// Whether `text` is accepted as an `allow_cidrs` entry.
#[must_use]
pub fn cidr_accepted(text: &str) -> bool {
    EgressPolicy {
        block_private: true,
        allow_cidrs: vec![text.to_owned()],
    }
    .validate()
    .is_ok()
}

/// Builds the upstream route of a session the way the forwarder does: the scheme and shape
/// checks, the URL parse and the credential rendering. Nothing is dialed.
pub fn upstream_route(
    route: &browserx_core::ProxyRoute,
    sticky_key: &str,
    generation: u64,
) -> Result<(), browserx_core::Error> {
    crate::upstream::Route::from_proxy(route, sticky_key, generation, None, 16 * 1024).map(|_| ())
}
