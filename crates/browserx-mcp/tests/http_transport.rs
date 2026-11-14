//! The streamable HTTP transport over a real socket: authentication, origin checks, framing and
//! protocol behavior.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use browserx_mcp::http::{HttpOptions, parse_digest, router, serve};
use browserx_mcp::{Config, Ctx, Server};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const TOKEN: &str = "bxm_synthetic_http_token_for_tests";

struct Fixture {
    base: String,
    client: reqwest::Client,
    cancel: CancellationToken,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("key"), "bxk_synthetic\n").unwrap();
    let text = "[server]\nurl = \"http://127.0.0.1:1\"\napi_key_file = \"key\"\n[audit]\npath = \"audit.jsonl\"\n";
    let ctx = Ctx::build(Config::parse(text, dir.path()).unwrap()).unwrap();
    let server = Arc::new(Server::new(ctx));
    let digest = hex::encode(Sha256::digest(TOKEN.as_bytes()));
    let options = HttpOptions {
        path: "/mcp".into(),
        token_sha256: parse_digest(&digest).unwrap(),
        allowed_origins: vec!["https://console.example.test".into()],
        loopback_bind: true,
        max_body_bytes: 64 * 1024,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let cancel = CancellationToken::new();
    tokio::spawn(serve(listener, router(server, options), cancel.clone()));
    Fixture {
        base,
        client: reqwest::Client::new(),
        cancel,
        _dir: dir,
    }
}

impl Fixture {
    fn raw(&self) -> reqwest::RequestBuilder {
        self.client.post(format!("{}/mcp", self.base))
    }

    fn post(&self) -> reqwest::RequestBuilder {
        self.client
            .post(format!("{}/mcp", self.base))
            .bearer_auth(TOKEN)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
    }
}

fn request(id: u64, method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

#[tokio::test]
async fn a_bearer_token_is_required_and_compared_by_digest() {
    let f = fixture().await;
    let body = request(1, "ping", json!({}));
    let no_token = f
        .client
        .post(format!("{}/mcp", f.base))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(no_token.status(), StatusCode::UNAUTHORIZED);
    assert!(
        no_token.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .starts_with("Bearer")
    );
    for wrong in ["wrong", &TOKEN[..TOKEN.len() - 1], &format!("{TOKEN}x"), ""] {
        let response = f
            .raw()
            .bearer_auth(wrong)
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{wrong:?}");
    }
    let ok = f.post().body(body).send().await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(ok.json::<Value>().await.unwrap()["result"], json!({}));
    f.cancel.cancel();
}

#[tokio::test]
async fn origins_are_checked_against_rebinding() {
    let f = fixture().await;
    let body = request(1, "ping", json!({}));
    for (origin, expected) in [
        ("http://localhost:3000", StatusCode::OK),
        ("http://127.0.0.1:9", StatusCode::OK),
        ("https://console.example.test", StatusCode::OK),
        ("https://evil.example.test", StatusCode::FORBIDDEN),
        ("http://127.0.0.1.evil.test", StatusCode::FORBIDDEN),
        ("null", StatusCode::FORBIDDEN),
    ] {
        let response = f
            .post()
            .header("origin", origin)
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{origin}");
    }
    f.cancel.cancel();
}

#[tokio::test]
async fn the_protocol_works_over_post_and_bad_requests_are_refused() {
    let f = fixture().await;
    let init = f
        .post()
        .header("mcp-protocol-version", "2025-06-18")
        .body(request(1, "initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "h", "version": "1"}})))
        .send()
        .await
        .unwrap();
    assert_eq!(init.status(), StatusCode::OK);
    assert_eq!(init.headers()["content-type"], "application/json");
    assert_eq!(
        init.json::<Value>().await.unwrap()["result"]["serverInfo"]["name"],
        "browserx-mcp"
    );

    let tools = f
        .post()
        .body(request(2, "tools/list", json!({})))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "capabilities")
    );
    let call = f
        .post()
        .body(request(
            3,
            "tools/call",
            json!({"name": "explain_error", "arguments": {"code": "capacity"}}),
        ))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        call["result"]["structuredContent"]["title"],
        "Capacity exhausted"
    );
    let unknown = f
        .post()
        .body(request(4, "nope", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        unknown.json::<Value>().await.unwrap()["error"]["code"],
        -32601
    );

    // Notifications are accepted without a body; anything that is not one JSON-RPC object is refused.
    let note = f
        .post()
        .body(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(note.status(), StatusCode::ACCEPTED);
    let batch = f
        .post()
        .body(format!("[{}]", request(5, "ping", json!({}))))
        .send()
        .await
        .unwrap();
    assert_eq!(batch.status(), StatusCode::BAD_REQUEST);
    let garbage = f.post().body("{not json").send().await.unwrap();
    assert_eq!(garbage.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        garbage.json::<Value>().await.unwrap()["error"]["code"],
        -32700
    );
    let wrong_type = f
        .raw()
        .bearer_auth(TOKEN)
        .header("content-type", "text/plain")
        .body(request(6, "ping", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_type.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let not_acceptable = f
        .raw()
        .bearer_auth(TOKEN)
        .header("content-type", "application/json")
        .header("accept", "text/html")
        .body(request(7, "ping", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(not_acceptable.status(), StatusCode::NOT_ACCEPTABLE);
    let old = f
        .post()
        .header("mcp-protocol-version", "1999-01-01")
        .body(request(8, "ping", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(old.status(), StatusCode::BAD_REQUEST);
    let huge = f
        .post()
        .body(format!("{{\"pad\": \"{}\"}}", "x".repeat(70 * 1024)))
        .send()
        .await
        .unwrap();
    assert_eq!(huge.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // No server-initiated stream and no session to delete.
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let response = f
            .client
            .request(method, format!("{}/mcp", f.base))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
    let health = f
        .client
        .get(format!("{}/healthz", f.base))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    f.cancel.cancel();
}
