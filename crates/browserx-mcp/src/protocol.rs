//! JSON-RPC 2.0 framing and the Model Context Protocol envelope.
//!
//! Protocol revisions `2026-07-28`, `2025-06-18` and `2025-03-26` are served by one engine.
//!
//! * **Modern** (`2026-07-28`): stateless. Every request carries its protocol version and the
//!   client's capabilities in `params._meta`, results carry `resultType`, lists carry `ttlMs`
//!   and `cacheScope`, and there is no handshake. A tool that needs a human answers with
//!   `input_required` and the client retries.
//! * **Legacy** (`2025-06-18`, `2025-03-26`): `initialize` first. The server keeps no
//!   per-connection state, so the handshake only negotiates the version it echoes back.
//!
//! The era of a request is a property of the request, never of the connection, so the same
//! server answers both on stdio and on streamable HTTP.

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// The frame is not valid JSON.
pub const PARSE_ERROR: i64 = -32700;
/// The JSON is not a valid JSON-RPC request.
pub const INVALID_REQUEST: i64 = -32600;
/// The method does not exist.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// The parameters are wrong.
pub const INVALID_PARAMS: i64 = -32602;
/// The server failed or is saturated.
pub const INTERNAL_ERROR: i64 = -32603;
/// A requested resource does not exist (legacy revisions).
pub const RESOURCE_NOT_FOUND: i64 = -32002;
/// HTTP headers do not match the request body (`2026-07-28`).
pub const HEADER_MISMATCH: i64 = -32020;
/// The request needs a client capability that was not declared (`2026-07-28`).
pub const MISSING_CAPABILITY: i64 = -32021;
/// The requested protocol version is not served (`2026-07-28`).
pub const UNSUPPORTED_VERSION: i64 = -32022;

/// Largest accepted message. A longer stdio line is discarded up to its newline and answered
/// with [`INVALID_REQUEST`], so a runaway client cannot grow the server's memory.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// Protocol versions that use per-request metadata and no handshake.
pub const MODERN_VERSIONS: [&str; 1] = ["2026-07-28"];
/// Protocol versions that use the `initialize` handshake, newest first.
pub const LEGACY_VERSIONS: [&str; 2] = ["2025-06-18", "2025-03-26"];

/// `_meta` key carrying the protocol version of a request.
pub const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
/// `_meta` key carrying the client identity.
pub const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
/// `_meta` key carrying the client capabilities.
pub const META_CLIENT_CAPS: &str = "io.modelcontextprotocol/clientCapabilities";
/// `_meta` key carrying the server identity in results.
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// Every version served, newest first.
#[must_use]
pub fn supported_versions() -> Vec<&'static str> {
    MODERN_VERSIONS
        .iter()
        .chain(LEGACY_VERSIONS.iter())
        .copied()
        .collect()
}

/// What a request's `_meta` says about the protocol in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMeta {
    /// The request uses per-request metadata (`2026-07-28`).
    pub modern: bool,
    /// The protocol version of the request.
    pub version: String,
    /// Client name, when sent.
    pub client_name: Option<String>,
    /// Client version, when sent.
    pub client_version: Option<String>,
    /// The client declared the `elicitation` capability (only knowable for modern requests).
    pub elicitation: bool,
    /// The trace id of a valid W3C `traceparent` in `_meta`.
    pub trace_id: Option<String>,
}

impl RequestMeta {
    /// Meta of a request without protocol metadata: legacy semantics.
    #[must_use]
    pub fn legacy() -> Self {
        Self {
            modern: false,
            version: LEGACY_VERSIONS[0].to_owned(),
            client_name: None,
            client_version: None,
            elicitation: false,
            trace_id: None,
        }
    }
}

/// The trace id (32 lowercase hex digits) of a W3C `traceparent`, when it is well formed.
#[must_use]
pub fn trace_id_of(traceparent: &str) -> Option<String> {
    let mut parts = traceparent.trim().split('-');
    let (version, trace, span, flags) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let hex = |text: &str, len: usize| {
        text.len() == len
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    (hex(version, 2)
        && version != "ff"
        && hex(trace, 32)
        && trace.bytes().any(|b| b != b'0')
        && hex(span, 16)
        && span.bytes().any(|b| b != b'0')
        && hex(flags, 2))
    .then(|| trace.to_owned())
}

fn client_identity(info: Option<&Value>) -> (Option<String>, Option<String>) {
    let text = |key: &str| {
        info.and_then(|info| info.get(key))
            .and_then(Value::as_str)
            .map(|text| text.chars().take(128).collect::<String>())
    };
    (text("name"), text("version"))
}

/// Reads and validates the per-request metadata.
///
/// A request with a protocol version in `_meta` is served per that revision; one without is
/// served with legacy semantics.
///
/// # Errors
/// [`UNSUPPORTED_VERSION`] for a version the server does not serve, `INVALID_PARAMS` (HTTP 400)
/// for a modern request without `clientCapabilities`.
pub fn read_meta(params: Option<&Value>) -> Result<RequestMeta, RpcError> {
    let Some(meta) = params
        .and_then(|params| params.get("_meta"))
        .and_then(Value::as_object)
    else {
        return Ok(RequestMeta::legacy());
    };
    let (client_name, client_version) = client_identity(meta.get(META_CLIENT_INFO));
    let trace_id = meta
        .get("traceparent")
        .and_then(Value::as_str)
        .and_then(trace_id_of);
    let Some(version) = meta.get(META_VERSION) else {
        let mut legacy = RequestMeta::legacy();
        legacy.client_name = client_name;
        legacy.client_version = client_version;
        legacy.trace_id = trace_id;
        return Ok(legacy);
    };
    let Some(version) = version.as_str() else {
        return Err(
            RpcError::invalid_params(format!("`_meta.{META_VERSION}` must be a string"))
                .with_status(400),
        );
    };
    let modern = MODERN_VERSIONS.contains(&version);
    if !modern && !LEGACY_VERSIONS.contains(&version) {
        return Err(unsupported_version(version));
    }
    let capabilities = meta.get(META_CLIENT_CAPS).and_then(Value::as_object);
    if modern && capabilities.is_none() {
        return Err(RpcError::invalid_params(format!(
            "`_meta.{META_CLIENT_CAPS}` is required and must be an object"
        ))
        .with_status(400));
    }
    Ok(RequestMeta {
        modern,
        version: version.to_owned(),
        client_name,
        client_version,
        elicitation: modern
            && capabilities.is_some_and(|c| c.get("elicitation").is_some_and(Value::is_object)),
        trace_id,
    })
}

/// The error for a version the server does not serve, listing the versions it does.
#[must_use]
pub fn unsupported_version(requested: &str) -> RpcError {
    RpcError::new(UNSUPPORTED_VERSION, "Unsupported protocol version")
        .with_data(json!({ "supported": supported_versions(), "requested": requested }))
        .with_status(400)
}

/// A JSON-RPC error object with the HTTP status the HTTP transport answers with.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcError {
    /// JSON-RPC error code.
    pub code: i64,
    /// Human-readable message.
    pub message: String,
    /// Optional structured data.
    pub data: Option<Value>,
    /// HTTP status for the HTTP transport; `None` means `200`.
    pub http_status: Option<u16>,
}

impl RpcError {
    /// An error with `code` and `message`.
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
            http_status: None,
        }
    }

    /// `-32602`.
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, message)
    }

    /// Attaches data.
    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Sets the HTTP status.
    #[must_use]
    pub fn with_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }

    /// The error object.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut error = Map::new();
        error.insert("code".into(), json!(self.code));
        error.insert("message".into(), json!(self.message));
        if let Some(data) = &self.data {
            error.insert("data".into(), data.clone());
        }
        Value::Object(error)
    }
}

/// A well-formed inbound message.
#[derive(Debug, PartialEq)]
pub enum Incoming {
    /// A request that wants an answer.
    Request {
        /// Request id (string or integer).
        id: Value,
        /// Method name.
        method: String,
        /// Parameters, when present.
        params: Option<Value>,
    },
    /// A notification: no answer.
    Notification {
        /// Method name.
        method: String,
        /// Parameters, when present.
        params: Option<Value>,
    },
    /// A response to a server request. The server sends none, so these are ignored.
    Response,
}

/// Classifies one decoded JSON value. The error carries the id to answer with (`null` when it
/// is unreadable) and the JSON-RPC error.
pub fn parse_incoming(value: Value) -> Result<Incoming, (Value, RpcError)> {
    let Value::Object(mut map) = value else {
        return Err((
            Value::Null,
            RpcError::new(INVALID_REQUEST, "a message must be a JSON object").with_status(400),
        ));
    };
    let id = match map.remove("id") {
        None => None,
        Some(id @ (Value::String(_) | Value::Number(_))) => Some(id),
        Some(_) => {
            return Err((
                Value::Null,
                RpcError::new(INVALID_REQUEST, "`id` must be a string or an integer")
                    .with_status(400),
            ));
        }
    };
    let reply_id = id.clone().unwrap_or(Value::Null);
    if map.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err((
            reply_id,
            RpcError::new(INVALID_REQUEST, "`jsonrpc` must be \"2.0\"").with_status(400),
        ));
    }
    let method = match map.remove("method") {
        Some(Value::String(method)) => Some(method),
        Some(_) => {
            return Err((
                reply_id,
                RpcError::new(INVALID_REQUEST, "`method` must be a string").with_status(400),
            ));
        }
        None => None,
    };
    let params = match map.remove("params") {
        None | Some(Value::Null) => None,
        Some(params @ Value::Object(_)) => Some(params),
        Some(_) => {
            return Err((
                reply_id,
                RpcError::new(INVALID_PARAMS, "`params` must be an object").with_status(400),
            ));
        }
    };
    match (id, method) {
        (Some(id), Some(method)) => Ok(Incoming::Request { id, method, params }),
        (None, Some(method)) => Ok(Incoming::Notification { method, params }),
        (Some(_), None) if map.contains_key("result") || map.contains_key("error") => {
            Ok(Incoming::Response)
        }
        _ => Err((
            reply_id,
            RpcError::new(INVALID_REQUEST, "a request needs a `method`").with_status(400),
        )),
    }
}

/// Success frame for request `id`.
#[must_use]
pub fn result_frame(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Error frame for request `id` (`null` when the id could not be read).
#[must_use]
pub fn error_frame(id: &Value, error: &RpcError) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": error.to_value() })
}

/// One line read from the client.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// A complete line.
    Message(Vec<u8>),
    /// A line longer than the limit, discarded.
    Oversized,
    /// End of input.
    Eof,
}

/// Reads the next non-blank line, keeping at most `max` bytes of it in memory. A final line
/// without a newline is still delivered.
pub async fn read_frame<R>(reader: &mut R, max: usize) -> std::io::Result<Frame>
where
    R: AsyncBufRead + Unpin,
{
    loop {
        let mut line: Vec<u8> = Vec::new();
        let mut oversized = false;
        let mut saw_any = false;
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                break;
            }
            saw_any = true;
            let (chunk, done) = match available.iter().position(|byte| *byte == b'\n') {
                Some(end) => (&available[..end], Some(end + 1)),
                None => (available, None),
            };
            if !oversized {
                if line.len() + chunk.len() > max {
                    oversized = true;
                    line.clear();
                } else {
                    line.extend_from_slice(chunk);
                }
            }
            let consumed = done.unwrap_or(chunk.len());
            reader.consume(consumed);
            if done.is_some() {
                break;
            }
        }
        if !saw_any {
            return Ok(Frame::Eof);
        }
        if oversized {
            return Ok(Frame::Oversized);
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        return Ok(Frame::Message(line));
    }
}

/// Writes `frame` as one line and flushes. `serde_json` escapes newlines inside strings, so the
/// output is always exactly one line.
pub async fn write_frame<W>(writer: &mut W, frame: &Value) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut bytes = serde_json::to_vec(frame).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use tokio::io::BufReader;

    #[test]
    fn classifies_messages() {
        let request = parse_incoming(json!({"jsonrpc":"2.0","id":1,"method":"ping"}));
        assert_eq!(
            request.ok(),
            Some(Incoming::Request {
                id: json!(1),
                method: "ping".into(),
                params: None
            })
        );
        let note = parse_incoming(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        assert!(matches!(note, Ok(Incoming::Notification { .. })));
        let response = parse_incoming(json!({"jsonrpc":"2.0","id":3,"result":{}}));
        assert_eq!(response.ok(), Some(Incoming::Response));
    }

    #[test]
    fn rejects_malformed_messages() {
        for bad in [
            json!([]),
            json!({"jsonrpc":"1.0","id":1,"method":"x"}),
            json!({"jsonrpc":"2.0","id":null,"method":"x","params":[]}),
            json!({"jsonrpc":"2.0","id":true,"method":"x"}),
            json!({"jsonrpc":"2.0","id":1}),
        ] {
            assert!(parse_incoming(bad).is_err());
        }
    }

    #[tokio::test]
    async fn frames_split_on_newlines_and_cap_the_size() {
        let input = b"{\"a\":1}\r\n\n{\"b\":2}\nxxxxxxxxxxxxxxxxxxxx\n{\"c\":3}";
        let mut reader = BufReader::new(&input[..]);
        assert_eq!(
            read_frame(&mut reader, 16).await.unwrap(),
            Frame::Message(b"{\"a\":1}".to_vec())
        );
        assert_eq!(
            read_frame(&mut reader, 16).await.unwrap(),
            Frame::Message(b"{\"b\":2}".to_vec())
        );
        assert_eq!(read_frame(&mut reader, 16).await.unwrap(), Frame::Oversized);
        assert_eq!(
            read_frame(&mut reader, 16).await.unwrap(),
            Frame::Message(b"{\"c\":3}".to_vec())
        );
        assert_eq!(read_frame(&mut reader, 16).await.unwrap(), Frame::Eof);
    }
}
