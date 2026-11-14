//! Relay and listener limits, checked against the in-process fake browser.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use browserx_core::SessionId;
use browserx_pool::testing::FakeRuntime;
use common::{KEY, TestServer, start_with_limits, test_pool_config};
use futures_util::{SinkExt, StreamExt};
use reqwest::Method;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn start(tune: impl FnOnce(&mut browserx_server::ServerLimits)) -> TestServer {
    let fake = FakeRuntime::new();
    start_with_limits(
        Arc::new(fake.clone()),
        Some(fake),
        test_pool_config(),
        16,
        tune,
    )
    .await
}

async fn rpc(ws: &mut Ws, id: u64, method: &str, params: Value) -> Value {
    ws.send(Message::text(
        json!({"id": id, "method": method, "params": params}).to_string(),
    ))
    .await
    .unwrap();
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("timed out")
            .expect("relay closed")
            .unwrap();
        if let Message::Text(t) = msg {
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            if v["id"] == id {
                return v;
            }
        }
    }
}

fn status_of(err: &tokio_tungstenite::tungstenite::Error) -> Option<u16> {
    match err {
        tokio_tungstenite::tungstenite::Error::Http(r) => Some(r.status().as_u16()),
        _ => None,
    }
}

async fn closed_within(ws: &mut Ws, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        if let Ok(None | Some(Err(_) | Ok(Message::Close(_)))) =
            tokio::time::timeout(Duration::from_millis(200), ws.next()).await
        {
            return true;
        }
    }
    false
}

/// Finding 14: connections per session are capped, and a slot frees up on close.
#[tokio::test]
async fn relay_connections_per_session_are_capped() {
    let s = start(|l| l.relay_connections_per_session = 2).await;
    let created = s.create(json!({})).await;
    let url = created["cdp_url"].as_str().unwrap().to_owned();
    let (mut a, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (b, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let err = tokio_tungstenite::connect_async(&url).await.unwrap_err();
    assert_eq!(status_of(&err), Some(429), "{err}");
    // The refused attempt must not disturb the open ones.
    let v = rpc(&mut a, 1, "Runtime.evaluate", json!({})).await;
    assert!(v.get("result").is_some(), "{v}");
    drop(b);
    let mut reopened = None;
    for _ in 0..50 {
        match tokio_tungstenite::connect_async(&url).await {
            Ok((ws, _)) => {
                reopened = Some(ws);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(reopened.is_some(), "closing a relay must free its slot");
}

/// Finding 20: a wrong token, an unknown session and a malformed id all look the same.
#[tokio::test]
async fn relay_answers_401_for_every_bad_credential() {
    let s = start(|_| {}).await;
    let created = s.create(json!({})).await;
    let id = created["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = created["token"].as_str().unwrap().to_owned();
    let unknown = SessionId::new().prefixed();
    for path in [
        format!("/cdp/{id}/bxt_wrong"),
        format!("/cdp/{unknown}/{token}"),
        format!("/cdp/{unknown}/bxt_wrong"),
        format!("/cdp/not-a-session/{token}"),
    ] {
        let err = tokio_tungstenite::connect_async(format!("{}{path}", s.ws))
            .await
            .unwrap_err();
        assert_eq!(status_of(&err), Some(401), "{path}: {err}");
    }
    // Once the session is gone, only the token holder learns that.
    let resp = s
        .req(Method::DELETE, &format!("/v1/sessions/{id}"))
        .header("X-BrowserX-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let err = tokio_tungstenite::connect_async(format!("{}/cdp/{id}/bxt_wrong", s.ws))
        .await
        .unwrap_err();
    assert_eq!(status_of(&err), Some(401), "{err}");
}

/// Finding 14: the scoped relay rejects messages above its (configurable) limit.
#[tokio::test]
async fn scoped_relay_message_limit_is_enforced() {
    let s = start(|l| l.scoped_relay_max_message_bytes = 64 * 1024).await;
    let shared = s.create(json!({"isolation": "shared_browser"})).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(shared["cdp_url"].as_str().unwrap())
        .await
        .unwrap();
    let ok = rpc(&mut ws, 1, "Browser.getVersion", json!({})).await;
    assert!(ok.get("result").is_some(), "{ok}");
    let big = "x".repeat(200 * 1024);
    ws.send(Message::text(
        json!({"id": 2, "method": "Browser.getVersion", "params": {"pad": big}}).to_string(),
    ))
    .await
    .unwrap();
    assert!(
        closed_within(&mut ws, Duration::from_secs(5)).await,
        "an oversized message must close the relay"
    );
    // A dedicated relay keeps the larger limit.
    let dedicated = s.create(json!({})).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(dedicated["cdp_url"].as_str().unwrap())
        .await
        .unwrap();
    let v = rpc(
        &mut ws,
        1,
        "Runtime.evaluate",
        json!({"expression": "x", "pad": "y".repeat(200 * 1024)}),
    )
    .await;
    assert!(v.get("result").is_some(), "{v}");
}

/// Finding 18: the download path is forced into the per-session directory, in both modes.
#[tokio::test]
async fn download_behavior_is_forced_into_the_session_directory() {
    let s = start(|_| {}).await;
    let root = s.state.limits().download_root.clone();
    for body in [json!({}), json!({"isolation": "shared_browser"})] {
        let created = s.create(body).await;
        let id = created["session"]["session_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let (mut ws, _) = tokio_tungstenite::connect_async(created["cdp_url"].as_str().unwrap())
            .await
            .unwrap();
        let v = rpc(
            &mut ws,
            1,
            "Browser.setDownloadBehavior",
            json!({"behavior": "allowAndName", "downloadPath": "/etc/cron.d"}),
        )
        .await;
        assert!(v.get("result").is_some(), "{v}");
        let expected = root.join(&id).to_string_lossy().into_owned();
        let forced = s
            .fake
            .as_ref()
            .unwrap()
            .browsers()
            .iter()
            .flat_map(|b| b.calls())
            .any(|c| {
                c.method == "Browser.setDownloadBehavior"
                    && c.params["downloadPath"].as_str() == Some(expected.as_str())
            });
        assert!(forced, "{id}: the browser must get {expected}");
    }
}

async fn raw_head(addr: &str, partial: &[u8]) -> TcpStream {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(partial).await.unwrap();
    tcp
}

async fn closed_by_server(tcp: &mut TcpStream, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    let mut buf = [0u8; 256];
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, tcp.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => return true,
            Ok(Ok(_)) => {}
            Err(_) => return false,
        }
    }
}

fn host(url: &str) -> String {
    url.trim_start_matches("http://").to_owned()
}

/// Finding 29: a connection that never completes its request head is closed.
#[tokio::test]
async fn slow_request_heads_are_cut_off_but_websockets_keep_working() {
    let s = start(|l| l.header_read_timeout = Duration::from_secs(1)).await;
    for addr in [host(&s.api), host(&s.ops)] {
        let mut slow = raw_head(&addr, b"GET /healthz HTTP/1.1\r\nHost: x\r\n").await;
        assert!(
            closed_by_server(&mut slow, Duration::from_secs(8)).await,
            "{addr}: an incomplete head must be closed"
        );
        let mut silent = TcpStream::connect(&addr).await.unwrap();
        assert!(
            closed_by_server(&mut silent, Duration::from_secs(8)).await,
            "{addr}: a silent connection must be closed"
        );
    }
    // A prompt client is unaffected, and an upgraded relay outlives the head timeout.
    let created = s.create(json!({})).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(created["cdp_url"].as_str().unwrap())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let v = rpc(&mut ws, 1, "Runtime.evaluate", json!({})).await;
    assert!(v.get("result").is_some(), "{v}");
    let r = s
        .client
        .get(format!("{}/v1/launch-profiles", s.api))
        .bearer_auth(KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

/// Finding 29: beyond `max_connections` new connections are closed at once.
#[tokio::test]
async fn open_connections_are_capped() {
    let s = start(|l| {
        l.max_connections = 2;
        l.header_read_timeout = Duration::from_secs(60);
    })
    .await;
    let addr = host(&s.api);
    let _one = TcpStream::connect(&addr).await.unwrap();
    let _two = TcpStream::connect(&addr).await.unwrap();
    // Give the accept loop time to take both.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut third = TcpStream::connect(&addr).await.unwrap();
    assert!(
        closed_by_server(&mut third, Duration::from_secs(3)).await,
        "the third connection must be closed"
    );
    drop(_one);
    let mut served = false;
    for _ in 0..50 {
        let mut tcp = TcpStream::connect(&addr).await.unwrap();
        tcp.write_all(b"GET /v1/launch-profiles HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), tcp.read_to_end(&mut out)).await;
        if String::from_utf8_lossy(&out).starts_with("HTTP/1.1 401") {
            served = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(served, "a freed slot must be usable again");
}
