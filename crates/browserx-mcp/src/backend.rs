//! The client of the BrowserX HTTP API and operations listener.
//!
//! The API key goes only in the `Authorization` header, redirects are not followed and
//! responses are size-capped. Lease tokens and CDP URLs returned by the server are wrapped in
//! [`Secret`] immediately and never logged.

use std::time::{Duration, Instant};

use browserx_core::Secret;
use serde_json::{Value, json};

use crate::error::{FailKind, ToolError};

/// Largest response body read from the server.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Header carrying the session token.
const TOKEN_HEADER: &str = "X-BrowserX-Token";

/// Why a call to the server failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    /// The server could not be reached or timed out.
    Transport(String),
    /// The server answered with an error.
    Api {
        /// HTTP status.
        status: u16,
        /// BrowserX error code (`stale_generation`, `capacity`, ...).
        code: String,
        /// The server's message.
        message: String,
    },
    /// The answer was not what the API documents.
    Malformed(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(reason) => write!(f, "cannot reach the BrowserX server: {reason}"),
            Self::Api {
                status,
                code,
                message,
            } => write!(f, "BrowserX answered {status} {code}: {message}"),
            Self::Malformed(reason) => {
                write!(f, "unexpected answer from the BrowserX server: {reason}")
            }
        }
    }
}

impl std::error::Error for BackendError {}

impl From<BackendError> for ToolError {
    fn from(error: BackendError) -> Self {
        let detail = match &error {
            BackendError::Api { status, code, .. } => json!({ "status": status, "code": code }),
            _ => json!({}),
        };
        Self::new(FailKind::Backend, error.to_string()).with_detail(detail)
    }
}

/// A created session: the public view plus the secrets only this server may hold.
pub struct Created {
    /// The lease view (no token).
    pub session: Value,
    /// The controller token.
    pub token: Secret,
    /// The CDP WebSocket URL, which embeds the token.
    pub cdp_url: Secret,
}

/// An attach answer.
pub struct Attached {
    /// The lease view.
    pub session: Value,
    /// The CDP WebSocket URL.
    pub cdp_url: Secret,
    /// The recovery outcome reported by the server.
    pub outcome: String,
    /// The generation now held.
    pub generation: u64,
}

/// The result of an operations-listener probe.
#[derive(Debug, Clone)]
pub struct Probe {
    /// HTTP status, when the server answered.
    pub status: Option<u16>,
    /// Response body (empty on transport failure).
    pub body: String,
    /// Round trip in milliseconds.
    pub latency_ms: u64,
    /// Transport error, when there was no answer.
    pub error: Option<String>,
}

/// The BrowserX client.
#[derive(Clone)]
pub struct Backend {
    http: reqwest::Client,
    base: String,
    ops: Option<String>,
    key: Secret,
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backend")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

fn text_of<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, BackendError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| BackendError::Malformed(format!("missing {pointer}")))
}

impl Backend {
    /// A client for `base` (API) and optionally `ops` (operations listener).
    ///
    /// # Errors
    /// When the HTTP client cannot be built.
    pub fn new(
        base: &str,
        ops: Option<&str>,
        key: Secret,
        timeout: Duration,
    ) -> Result<Self, BackendError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("browserx-mcp/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_owned(),
            ops: ops.map(|url| url.trim_end_matches('/').to_owned()),
            key,
        })
    }

    /// Whether the operations listener is configured.
    #[must_use]
    pub fn has_ops(&self) -> bool {
        self.ops.is_some()
    }

    async fn read_capped(mut response: reqwest::Response) -> Result<(u16, String), BackendError> {
        let status = response.status().as_u16();
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| BackendError::Transport(format!("reading the response: {e}")))?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(BackendError::Malformed("the response is too large".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&Secret>,
        body: Option<&Value>,
    ) -> Result<Value, BackendError> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(self.key.expose());
        if let Some(token) = token {
            request = request.header(TOKEN_HEADER, token.expose());
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|e| {
            BackendError::Transport(if e.is_timeout() {
                "timed out".into()
            } else if e.is_connect() {
                "connection refused or unreachable".into()
            } else {
                "request failed".into()
            })
        })?;
        let (status, text) = Self::read_capped(response).await?;
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if (200..300).contains(&status) {
            return Ok(value);
        }
        Err(BackendError::Api {
            status,
            code: value
                .pointer("/error/code")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
            message: value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .map_or_else(|| text.chars().take(200).collect(), str::to_owned),
        })
    }

    /// `POST /v1/sessions`.
    ///
    /// # Errors
    /// When the call fails or the answer lacks the session, token or CDP URL.
    pub async fn create_session(&self, spec: &Value) -> Result<Created, BackendError> {
        let value = self
            .call(reqwest::Method::POST, "/v1/sessions", None, Some(spec))
            .await?;
        Ok(Created {
            session: value
                .get("session")
                .cloned()
                .ok_or_else(|| BackendError::Malformed("missing session".into()))?,
            token: Secret::new(text_of(&value, "/token")?),
            cdp_url: Secret::new(text_of(&value, "/cdp_url")?),
        })
    }

    /// `GET /v1/sessions[?status=...]`.
    ///
    /// # Errors
    /// When the call fails.
    pub async fn list_sessions(&self, status: Option<&str>) -> Result<Vec<Value>, BackendError> {
        let path = status.map_or_else(
            || "/v1/sessions".to_owned(),
            |s| format!("/v1/sessions?status={s}"),
        );
        let value = self.call(reqwest::Method::GET, &path, None, None).await?;
        Ok(value
            .get("sessions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// `GET /v1/sessions/{id}`.
    ///
    /// # Errors
    /// When the call fails or the session is unknown.
    pub async fn get_session(&self, id: &str) -> Result<Value, BackendError> {
        let value = self
            .call(
                reqwest::Method::GET,
                &format!("/v1/sessions/{id}"),
                None,
                None,
            )
            .await?;
        value
            .get("session")
            .cloned()
            .ok_or_else(|| BackendError::Malformed("missing session".into()))
    }

    /// `POST /v1/sessions/{id}/attach`.
    ///
    /// # Errors
    /// When the call fails.
    pub async fn attach(&self, id: &str, token: &Secret) -> Result<Attached, BackendError> {
        let value = self
            .call(
                reqwest::Method::POST,
                &format!("/v1/sessions/{id}/attach"),
                Some(token),
                None,
            )
            .await?;
        Ok(Attached {
            session: value.get("session").cloned().unwrap_or(Value::Null),
            cdp_url: Secret::new(text_of(&value, "/cdp_url")?),
            outcome: text_of(&value, "/outcome")?.to_owned(),
            generation: value.get("generation").and_then(Value::as_u64).unwrap_or(0),
        })
    }

    /// `POST /v1/sessions/{id}/renew`.
    ///
    /// # Errors
    /// When the call fails.
    pub async fn renew(
        &self,
        id: &str,
        token: &Secret,
        generation: u64,
        ttl_secs: Option<u64>,
    ) -> Result<Value, BackendError> {
        let mut body = json!({ "generation": generation });
        if let Some(ttl) = ttl_secs {
            body["ttl_secs"] = json!(ttl);
        }
        let value = self
            .call(
                reqwest::Method::POST,
                &format!("/v1/sessions/{id}/renew"),
                Some(token),
                Some(&body),
            )
            .await?;
        Ok(value.get("session").cloned().unwrap_or(Value::Null))
    }

    /// `POST /v1/sessions/{id}/handoff`: returns the lease view, the new token and CDP URL.
    ///
    /// # Errors
    /// When the call fails.
    pub async fn handoff(
        &self,
        id: &str,
        token: &Secret,
        generation: u64,
    ) -> Result<Created, BackendError> {
        let value = self
            .call(
                reqwest::Method::POST,
                &format!("/v1/sessions/{id}/handoff"),
                Some(token),
                Some(&json!({ "generation": generation })),
            )
            .await?;
        Ok(Created {
            session: value.get("session").cloned().unwrap_or(Value::Null),
            token: Secret::new(text_of(&value, "/token")?),
            cdp_url: Secret::new(text_of(&value, "/cdp_url")?),
        })
    }

    /// `POST /v1/sessions/{id}/snapshot`.
    ///
    /// # Errors
    /// When the call fails.
    pub async fn snapshot(&self, id: &str, token: &Secret) -> Result<Value, BackendError> {
        let value = self
            .call(
                reqwest::Method::POST,
                &format!("/v1/sessions/{id}/snapshot"),
                Some(token),
                None,
            )
            .await?;
        Ok(value.get("snapshot").cloned().unwrap_or(Value::Null))
    }

    /// `DELETE /v1/sessions/{id}`: with the token when known, as the owner otherwise.
    ///
    /// # Errors
    /// When the call fails.
    pub async fn release(
        &self,
        id: &str,
        token: Option<&Secret>,
        generation: Option<u64>,
    ) -> Result<Value, BackendError> {
        let path = generation.map_or_else(
            || format!("/v1/sessions/{id}"),
            |g| format!("/v1/sessions/{id}?generation={g}"),
        );
        let value = self
            .call(reqwest::Method::DELETE, &path, token, None)
            .await?;
        Ok(value.get("session").cloned().unwrap_or(Value::Null))
    }

    /// `GET /v1/launch-profiles`.
    ///
    /// # Errors
    /// When the call fails.
    pub async fn launch_profiles(&self) -> Result<Value, BackendError> {
        self.call(reqwest::Method::GET, "/v1/launch-profiles", None, None)
            .await
    }

    /// `GET /v1/profiles/{id}/snapshots`.
    ///
    /// # Errors
    /// When the call fails.
    pub async fn profile_snapshots(&self, profile_id: &str) -> Result<Vec<Value>, BackendError> {
        let value = self
            .call(
                reqwest::Method::GET,
                &format!("/v1/profiles/{profile_id}/snapshots"),
                None,
                None,
            )
            .await?;
        Ok(value
            .get("snapshots")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// Probes `path` on the operations listener; `None` when it is not configured.
    pub async fn probe_ops(&self, path: &str) -> Option<Probe> {
        let base = self.ops.as_ref()?;
        let started = Instant::now();
        let outcome = async {
            let response = self
                .http
                .get(format!("{base}{path}"))
                .send()
                .await
                .map_err(|e| {
                    if e.is_timeout() {
                        "timed out".to_owned()
                    } else {
                        "connection refused or unreachable".to_owned()
                    }
                })?;
            Self::read_capped(response).await.map_err(|e| e.to_string())
        }
        .await;
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Some(match outcome {
            Ok((status, body)) => Probe {
                status: Some(status),
                body,
                latency_ms,
                error: None,
            },
            Err(error) => Probe {
                status: None,
                body: String::new(),
                latency_ms,
                error: Some(error),
            },
        })
    }

    /// Whether the API answers and accepts the key, with its latency in milliseconds.
    pub async fn api_probe(&self) -> (Result<(), BackendError>, u64) {
        let started = Instant::now();
        let result = self.launch_profiles().await.map(|_| ());
        let latency = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        (result, latency)
    }
}
