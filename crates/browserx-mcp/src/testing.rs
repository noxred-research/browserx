//! Test helpers: a [`Ctx`] over temporary files and an unreachable BrowserX server.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use serde_json::{Value, json};

use crate::config::Config;
use crate::ctx::Ctx;
use crate::server::{Server, Transport};

/// Creates a context from `extra` TOML appended to a minimal configuration.
pub(crate) fn ctx_from(extra: &str) -> (Arc<Ctx>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("key"), "bxk_test_synthetic_key_value\n").expect("key file");
    let text = format!(
        "[server]\nurl = \"http://127.0.0.1:1\"\napi_key_file = \"key\"\n[audit]\npath = \"audit.jsonl\"\n{extra}"
    );
    let config = Config::parse(&text, dir.path()).expect("valid test configuration");
    (Ctx::build(config).expect("context"), dir)
}

/// A JSON-RPC call through the protocol engine.
pub(crate) async fn rpc(
    server: &Server,
    method: &str,
    params: Value,
) -> Result<Value, crate::protocol::RpcError> {
    server
        .handle(
            method,
            Some(params),
            &Transport {
                name: "stdio",
                remote: None,
            },
        )
        .await
}

/// A `tools/call` that must not be a protocol error.
pub(crate) async fn call_tool(server: &Server, name: &str, arguments: Value) -> Value {
    rpc(
        server,
        "tools/call",
        json!({ "name": name, "arguments": arguments }),
    )
    .await
    .expect("tools/call returns a result")
}

/// The names in a `tools/list` result.
pub(crate) async fn tool_names(server: &Server) -> Vec<String> {
    let listed = rpc(server, "tools/list", json!({}))
        .await
        .expect("tools/list");
    listed["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().expect("name").to_owned())
        .collect()
}

/// What a mock chat-completions endpoint received.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub authorization: Option<String>,
    pub body: Value,
}

/// Serves `POST /v1/chat/completions`, answering with `status` and a completion whose content
/// is `content`. Returns the base URL and the requests seen.
pub(crate) async fn mock_completions(
    status: u16,
    content: &str,
) -> (String, Arc<std::sync::Mutex<Vec<Seen>>>) {
    use axum::Json;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;

    let seen: Arc<std::sync::Mutex<Vec<Seen>>> = Arc::default();
    let log = Arc::clone(&seen);
    let content = content.to_owned();
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        post(move |headers: HeaderMap, Json(body): Json<Value>| {
            let log = Arc::clone(&log);
            let content = content.clone();
            async move {
                log.lock().expect("log").push(Seen {
                    authorization: headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned),
                    body,
                });
                (
                    StatusCode::from_u16(status).expect("status"),
                    Json(json!({"choices": [{"message": {"content": content}}]})),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/v1"), seen)
}
