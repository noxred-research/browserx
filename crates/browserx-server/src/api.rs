//! The JSON API under `/v1`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Path, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use browserx_core::{
    Error, Generation, LeaseToken, ProfileId, SessionId, SessionLease, SessionSpec, SessionStatus,
};
use browserx_pool::Pool;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::auth::Authenticator;
use crate::dto::{HandoffBody, LeaseView, RenewBody, SnapshotView};
use crate::error::ApiError;

/// Header carrying the session token for token-authenticated operations.
pub const TOKEN_HEADER: &str = "x-browserx-token";
const MAX_BODY_BYTES: usize = 256 * 1024;

/// Check run by `/readyz` beyond the built-in ones; returns why not ready.
pub type ReadyProbe = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;

pub(crate) struct AppInner {
    pub pool: Pool,
    pub auth: Authenticator,
    pub ws_base: String,
    pub default_launch_profile: String,
    pub ready: ReadyProbe,
    pub relay_stop: CancellationToken,
}

/// Shared state of the HTTP handlers. Cheap to clone.
#[derive(Clone)]
pub struct AppState {
    pub(crate) inner: Arc<AppInner>,
}

impl AppState {
    /// Builds handler state.
    ///
    /// `public_base_url` is the externally reachable base of the API listener;
    /// `cdp_url` values are derived from it (`http` -> `ws`, `https` -> `wss`).
    pub fn new(
        pool: Pool,
        auth: Authenticator,
        public_base_url: &str,
        default_launch_profile: String,
        ready: ReadyProbe,
    ) -> Result<Self, Error> {
        let mut base = url::Url::parse(public_base_url)
            .map_err(|e| Error::InvalidRequest(format!("public_base_url: {e}")))?;
        let scheme = match base.scheme() {
            "http" | "ws" => "ws",
            "https" | "wss" => "wss",
            other => {
                return Err(Error::InvalidRequest(format!(
                    "public_base_url scheme {other} is not http(s)"
                )));
            }
        };
        base.set_scheme(scheme).map_err(|()| {
            Error::InvalidRequest("public_base_url scheme cannot be mapped to ws".into())
        })?;
        let ws_base = base.as_str().trim_end_matches('/').to_owned();
        Ok(Self {
            inner: Arc::new(AppInner {
                pool,
                auth,
                ws_base,
                default_launch_profile,
                ready,
                relay_stop: CancellationToken::new(),
            }),
        })
    }

    /// The scheduler.
    #[must_use]
    pub fn pool(&self) -> &Pool {
        &self.inner.pool
    }

    /// Closes every open relay connection.
    pub fn close_relays(&self) {
        self.inner.relay_stop.cancel();
    }

    pub(crate) fn cdp_url(&self, id: SessionId, token: &LeaseToken) -> String {
        format!(
            "{}/cdp/{}/{}",
            self.inner.ws_base,
            id.prefixed(),
            token.expose()
        )
    }
}

/// The authenticated owner (API key name).
pub struct Owner(pub String);

impl FromRequestParts<AppState> for Owner {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(Error::Unauthorized)?;
        let (scheme, key) = header.split_once(' ').ok_or(Error::Unauthorized)?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(Error::Unauthorized.into());
        }
        state
            .inner
            .auth
            .authenticate(key.trim())
            .map(|name| Self(name.to_owned()))
            .ok_or_else(|| Error::Unauthorized.into())
    }
}

fn token_from(headers: &HeaderMap) -> Result<Option<LeaseToken>, Error> {
    match headers.get(TOKEN_HEADER) {
        None => Ok(None),
        Some(v) => v
            .to_str()
            .map(|s| Some(LeaseToken::from_client(s.trim().to_owned())))
            .map_err(|_| Error::InvalidRequest("X-BrowserX-Token is not valid text".into())),
    }
}

fn required_token(headers: &HeaderMap) -> Result<LeaseToken, Error> {
    token_from(headers)?.ok_or_else(|| Error::Forbidden("missing X-BrowserX-Token header".into()))
}

fn parse_body<T: DeserializeOwned>(body: &Bytes, empty: &str) -> Result<T, Error> {
    let bytes: &[u8] = if body.iter().all(u8::is_ascii_whitespace) {
        empty.as_bytes()
    } else {
        body
    };
    serde_json::from_slice(bytes).map_err(|e| Error::InvalidRequest(format!("request body: {e}")))
}

fn session_id(raw: &str) -> Result<SessionId, Error> {
    SessionId::parse(raw)
}

fn profile_id(raw: &str) -> Result<ProfileId, Error> {
    ProfileId::parse(raw)
}

type ApiResult<T> = Result<T, ApiError>;

fn view(lease: &SessionLease) -> Value {
    json!(LeaseView::from(lease))
}

async fn create_session(
    State(app): State<AppState>,
    Owner(owner): Owner,
    body: Bytes,
) -> ApiResult<Response> {
    let spec: SessionSpec = parse_body(&body, "{}")?;
    let (lease, token) = app.pool().create(&owner, spec).await?;
    let body = json!({
        "session": view(&lease),
        "token": token.expose(),
        "cdp_url": app.cdp_url(lease.session_id, &token),
        "outcome": lease.last_recovery,
    });
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

#[derive(serde::Deserialize)]
struct ListQuery {
    status: Option<String>,
}

async fn list_sessions(
    State(app): State<AppState>,
    Owner(owner): Owner,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let statuses = match &query.status {
        None => None,
        Some(raw) => Some(
            raw.split(',')
                .map(|s| {
                    serde_json::from_value::<SessionStatus>(Value::String(s.trim().to_owned()))
                        .map_err(|_| Error::InvalidRequest(format!("unknown status {s:?}")))
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };
    let leases = app.pool().list(&owner, statuses.as_deref()).await?;
    let views: Vec<Value> = leases.iter().map(view).collect();
    Ok(Json(json!({ "sessions": views })))
}

async fn get_session(
    State(app): State<AppState>,
    Owner(owner): Owner,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let lease = app.pool().get(&owner, session_id(&id)?).await?;
    Ok(Json(json!({ "session": view(&lease) })))
}

async fn attach_session(
    State(app): State<AppState>,
    Owner(owner): Owner,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let token = required_token(&headers)?;
    let info = app.pool().attach(&owner, session_id(&id)?, &token).await?;
    Ok(Json(json!({
        "session": view(&info.lease),
        "cdp_url": app.cdp_url(info.lease.session_id, &token),
        "outcome": info.outcome,
        "generation": info.lease.generation.0,
    })))
}

async fn renew_session(
    State(app): State<AppState>,
    Owner(owner): Owner,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let token = required_token(&headers)?;
    let req: RenewBody = parse_body(&body, "")?;
    let ttl = req.ttl_secs.map(std::time::Duration::from_secs);
    let lease = app
        .pool()
        .renew(
            &owner,
            session_id(&id)?,
            &token,
            Generation(req.generation),
            ttl,
        )
        .await?;
    Ok(Json(json!({ "session": view(&lease) })))
}

async fn handoff_session(
    State(app): State<AppState>,
    Owner(owner): Owner,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let token = required_token(&headers)?;
    let req: HandoffBody = parse_body(&body, "")?;
    let (lease, fresh) = app
        .pool()
        .handoff(&owner, session_id(&id)?, &token, Generation(req.generation))
        .await?;
    Ok(Json(json!({
        "session": view(&lease),
        "token": fresh.expose(),
        "cdp_url": app.cdp_url(lease.session_id, &fresh),
    })))
}

async fn snapshot_session(
    State(app): State<AppState>,
    Owner(owner): Owner,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let token = required_token(&headers)?;
    let meta = app
        .pool()
        .snapshot_now(&owner, session_id(&id)?, &token)
        .await?;
    Ok(Json(json!({ "snapshot": SnapshotView::from(&meta) })))
}

#[derive(serde::Deserialize)]
struct ReleaseQuery {
    generation: Option<u64>,
}

async fn release_session(
    State(app): State<AppState>,
    Owner(owner): Owner,
    Path(id): Path<String>,
    Query(query): Query<ReleaseQuery>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let token = token_from(&headers)?;
    let lease = app
        .pool()
        .release(
            &owner,
            session_id(&id)?,
            token.as_ref(),
            query.generation.map(Generation),
        )
        .await?;
    Ok(Json(json!({ "session": view(&lease) })))
}

async fn list_profile_snapshots(
    State(app): State<AppState>,
    Owner(owner): Owner,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let metas = app
        .pool()
        .list_profile_snapshots(&owner, profile_id(&id)?)
        .await?;
    let views: Vec<SnapshotView> = metas.iter().map(SnapshotView::from).collect();
    Ok(Json(json!({ "snapshots": views })))
}

async fn delete_profile(
    State(app): State<AppState>,
    Owner(owner): Owner,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let deleted = app.pool().delete_profile(&owner, profile_id(&id)?).await?;
    Ok(Json(json!({ "deleted_snapshots": deleted })))
}

async fn launch_profiles(State(app): State<AppState>, _owner: Owner) -> Json<Value> {
    let mut names = app.pool().launch_profiles();
    names.sort();
    Json(json!({ "default": app.inner.default_launch_profile, "profiles": names }))
}

async fn not_found() -> ApiError {
    ApiError(Error::NotFound("no such route".into()))
}

/// Router of the public listener: `/v1/*` API and the `/cdp/*` relay.
pub fn api_router(state: AppState) -> Router {
    let v1 = Router::new()
        .route("/sessions", post(create_session).get(list_sessions))
        .route("/sessions/{id}", get(get_session).delete(release_session))
        .route("/sessions/{id}/attach", post(attach_session))
        .route("/sessions/{id}/renew", post(renew_session))
        .route("/sessions/{id}/handoff", post(handoff_session))
        .route("/sessions/{id}/snapshot", post(snapshot_session))
        .route("/profiles/{id}/snapshots", get(list_profile_snapshots))
        .route("/profiles/{id}", axum::routing::delete(delete_profile))
        .route("/launch-profiles", get(launch_profiles))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));
    Router::new()
        .nest("/v1", v1)
        .route("/cdp/{session_id}/{token}", get(crate::relay::cdp_ws))
        .fallback(not_found)
        .with_state(state)
}
