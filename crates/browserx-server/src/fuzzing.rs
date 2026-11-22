//! Entry points for the cargo-fuzz targets in `fuzz/`. Not part of the API.
//!
//! Each function runs the same parsing and validation a request handler runs on untrusted
//! input, up to the point where the handler would touch the pool, and returns what was parsed.

use axum::body::Bytes;
use browserx_core::{Error, SessionSpec};

use crate::api::parse_body;
use crate::dto::{HandoffBody, RenewBody};

/// Body of `POST /v1/sessions`: parsed like `create_session`, then admitted like the pool does.
pub fn create_session_body(body: &[u8]) -> Result<SessionSpec, Error> {
    let spec: SessionSpec = parse_body(&Bytes::copy_from_slice(body), "{}")?;
    spec.validate()?;
    Ok(spec)
}

/// Body of `POST /v1/sessions/{id}/renew`: the generation and the optional TTL in seconds.
pub fn renew_body(body: &[u8]) -> Result<(u64, Option<u64>), Error> {
    let req: RenewBody = parse_body(&Bytes::copy_from_slice(body), "")?;
    Ok((req.generation, req.ttl_secs))
}

/// Body of `POST /v1/sessions/{id}/handoff`: the generation the caller holds.
pub fn handoff_body(body: &[u8]) -> Result<u64, Error> {
    let req: HandoffBody = parse_body(&Bytes::copy_from_slice(body), "")?;
    Ok(req.generation)
}
