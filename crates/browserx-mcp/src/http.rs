//! The streamable HTTP transport: one endpoint, one JSON-RPC message per `POST`, answered with
//! `application/json`.
//!
//! Security: a bearer token is always required and compared by SHA-256 digest in constant time
//! (only the digest is configured), the `Origin` header is validated (DNS rebinding), the
//! default bind is loopback, bodies are capped and in-flight requests are bounded. There are no
//! sessions and no server-initiated stream (`GET` and `DELETE` answer `405`); an
//! `Mcp-Session-Id` sent by a client is ignored. TLS is not terminated here: put a reverse proxy
//! in front for anything beyond loopback.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::header::{ALLOW, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::protocol::{
    INTERNAL_ERROR, INVALID_REQUEST, Incoming, PARSE_ERROR, RpcError, SUPPORTED_VERSIONS,
    error_frame, parse_incoming, result_frame,
};
use crate::server::{Server, Transport};

/// HTTP transport settings.
#[derive(Clone, Debug)]
pub struct HttpOptions {
    /// URL path of the endpoint.
    pub path: String,
    /// SHA-256 of the bearer token.
    pub token_sha256: [u8; 32],
    /// `Origin` values accepted besides loopback origins.
    pub allowed_origins: Vec<String>,
    /// The listener is bound to a loopback address.
    pub loopback_bind: bool,
    /// Largest request body.
    pub max_body_bytes: usize,
}

struct AppState {
    server: Arc<Server>,
    options: HttpOptions,
    permits: Semaphore,
}

fn equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Decodes a 64-character hex digest.
///
/// # Errors
/// When the text is not 64 hex characters.
pub fn parse_digest(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text).map_err(|e| format!("not hex: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "a SHA-256 digest is 32 bytes".to_owned())
}

/// The router, for tests and for embedding.
pub fn router(server: Arc<Server>, options: HttpOptions) -> Router {
    let path = options.path.clone();
    let limit = options.max_body_bytes;
    let permits = Semaphore::new(server.ctx.cfg.mcp.max_in_flight);
    let state = Arc::new(AppState {
        server,
        options,
        permits,
    });
    Router::new()
        .route(&path, any(endpoint))
        .route("/healthz", get(healthz))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

/// Serves `router` on `listener` until `cancel` fires.
///
/// # Errors
/// When the server fails.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move { cancel.cancelled().await })
    .await
}

fn respond(status: StatusCode, body: &Value) -> Response {
    let mut response = (status, serde_json::to_string(body).unwrap_or_default()).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Liveness: no authentication, no backend call, no secret.
async fn healthz() -> Response {
    respond(StatusCode::OK, &json!({"status": "ok"}))
}

fn fail(status: StatusCode, code: i64, message: &str) -> Response {
    respond(
        status,
        &error_frame(&Value::Null, &RpcError::new(code, message)),
    )
}

fn origin_allowed(origin: &str, options: &HttpOptions) -> bool {
    if options
        .allowed_origins
        .iter()
        .any(|allowed| allowed == origin)
    {
        return true;
    }
    if !options.loopback_bind {
        return false;
    }
    url::Url::parse(origin)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .is_some_and(|host| matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]" | "::1"))
}

fn error_response(error: &RpcError, id: &Value) -> Response {
    let status = error
        .http_status
        .and_then(|code| StatusCode::from_u16(code).ok())
        .unwrap_or(StatusCode::OK);
    respond(status, &error_frame(id, error))
}

async fn endpoint(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(origin) = headers.get("origin") {
        let allowed = origin
            .to_str()
            .is_ok_and(|origin| origin_allowed(origin, &state.options));
        if !allowed {
            return fail(
                StatusCode::FORBIDDEN,
                INVALID_REQUEST,
                "the Origin is not allowed",
            );
        }
    }
    let presented = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let (scheme, token) = value.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then_some(token.trim())
        });
    let digest: [u8; 32] = Sha256::digest(presented.unwrap_or("").as_bytes()).into();
    if presented.is_none() || !equal(&digest, &state.options.token_sha256) {
        let mut response = fail(
            StatusCode::UNAUTHORIZED,
            INVALID_REQUEST,
            "a valid bearer token is required",
        );
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"browserx-mcp\""),
        );
        return response;
    }
    if method != Method::POST {
        let mut response = fail(
            StatusCode::METHOD_NOT_ALLOWED,
            INVALID_REQUEST,
            "send JSON-RPC messages with POST",
        );
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("POST"));
        return response;
    }
    let is_json = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim()
                .to_ascii_lowercase()
                .starts_with("application/json")
        });
    if !is_json {
        return fail(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            INVALID_REQUEST,
            "Content-Type must be application/json",
        );
    }
    if let Some(accept) = headers.get("accept").and_then(|value| value.to_str().ok()) {
        let ok = accept.split(',').any(|item| {
            let kind = item.split(';').next().unwrap_or("").trim();
            matches!(kind, "application/json" | "application/*" | "*/*")
        });
        if !ok {
            return fail(
                StatusCode::NOT_ACCEPTABLE,
                INVALID_REQUEST,
                "Accept must allow application/json",
            );
        }
    }
    if let Some(version) = headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok())
        && !SUPPORTED_VERSIONS.contains(&version.trim())
    {
        return respond(
            StatusCode::BAD_REQUEST,
            &error_frame(
                &Value::Null,
                &RpcError::new(INVALID_REQUEST, "unsupported MCP-Protocol-Version")
                    .with_data(json!({"supported": SUPPORTED_VERSIONS, "requested": version})),
            ),
        );
    }
    let value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            return respond(
                StatusCode::BAD_REQUEST,
                &error_frame(
                    &Value::Null,
                    &RpcError::new(PARSE_ERROR, format!("parse error: {error}")),
                ),
            );
        }
    };
    if value.is_array() {
        return fail(
            StatusCode::BAD_REQUEST,
            INVALID_REQUEST,
            "send one JSON-RPC message per request",
        );
    }
    let (id, rpc_method, params) = match parse_incoming(value) {
        Err((id, error)) => return error_response(&error, &id),
        Ok(Incoming::Notification { .. } | Incoming::Response) => {
            return StatusCode::ACCEPTED.into_response();
        }
        Ok(Incoming::Request { id, method, params }) => (id, method, params),
    };
    let Ok(_permit) = state.permits.try_acquire() else {
        return respond(
            StatusCode::TOO_MANY_REQUESTS,
            &error_frame(
                &id,
                &RpcError::new(INTERNAL_ERROR, "too many requests in flight")
                    .with_data(json!({"reason": "busy"})),
            ),
        );
    };
    let transport = Transport {
        name: "http",
        remote: Some(peer.ip().to_string()),
    };
    match state.server.handle(&rpc_method, params, &transport).await {
        Ok(result) => respond(StatusCode::OK, &result_frame(&id, result)),
        Err(error) => error_response(&error, &id),
    }
}
