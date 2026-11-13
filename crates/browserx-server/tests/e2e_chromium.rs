//! End-to-end test against a real Chromium. Skipped (with a note) when none is found.
//! Hosts with restricted user namespaces need `BROWSERX_TEST_BROWSER_ARGS="--no-sandbox --disable-gpu"`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use browserx_core::SessionId;
use browserx_pool::PoolConfig;
use browserx_runtime::{ChromiumRuntime, LaunchProfile, RuntimeConfig, discover_chromium};
use common::{TestServer, start_with};
use futures_util::{SinkExt, StreamExt};
use reqwest::Method;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn start_real(dir: &std::path::Path) -> Option<TestServer> {
    let Some(exe) = discover_chromium() else {
        eprintln!(
            "SKIP: no Chromium found (set BROWSERX_CHROMIUM_PATH to run the end-to-end test)"
        );
        return None;
    };
    let args: Vec<String> = std::env::var("BROWSERX_TEST_BROWSER_ARGS")
        .unwrap_or_else(|_| "--no-sandbox --disable-gpu".into())
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let profile = LaunchProfile {
        executable: Some(exe),
        args,
        ..LaunchProfile::default()
    };
    let cfg = RuntimeConfig {
        launch_profiles: BTreeMap::from([("default".to_owned(), profile)]),
        temp_root: dir.join("tmp"),
        startup_timeout: Duration::from_secs(60),
        ..RuntimeConfig::default()
    }
    .validated()
    .unwrap();
    std::fs::create_dir_all(dir.join("tmp")).unwrap();
    let runtime = ChromiumRuntime::new(cfg).unwrap();
    let pool_cfg = PoolConfig {
        operation_timeout: Duration::from_secs(90),
        queue_timeout: Duration::from_secs(30),
        ..common::test_pool_config()
    };
    Some(start_with(Arc::new(runtime), None, pool_cfg, 8).await)
}

async fn rpc(ws: &mut Ws, id: u64, method: &str, params: Value) -> Value {
    ws.send(Message::text(
        json!({"id": id, "method": method, "params": params}).to_string(),
    ))
    .await
    .unwrap();
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(30), ws.next())
            .await
            .expect("timed out waiting for the browser")
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

async fn wait_closed(ws: &mut Ws) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline {
        if let Ok(None | Some(Err(_) | Ok(Message::Close(_)))) =
            tokio::time::timeout(Duration::from_millis(500), ws.next()).await
        {
            return true;
        }
    }
    false
}

fn sigkill(pid: u32) {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    kill(Pid::from_raw(i32::try_from(pid).unwrap()), Signal::SIGKILL).unwrap();
}

async fn attach(s: &TestServer, id: &str, token: &str) -> Value {
    let resp = s
        .req(Method::POST, &format!("/v1/sessions/{id}/attach"))
        .header("X-BrowserX-Token", token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    resp.json().await.unwrap()
}

/// Creates a session, opens a page through the relay, kills the browser, and
/// attaches again. Returns `(outcome, new session body, token)`.
async fn crash_and_reattach(s: &TestServer, body: Value) -> (String, String, String, Ws) {
    let created = s.create(body).await;
    let id = created["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = created["token"].as_str().unwrap().to_owned();
    let (mut ws, _) = tokio_tungstenite::connect_async(created["cdp_url"].as_str().unwrap())
        .await
        .unwrap();
    let target = rpc(
        &mut ws,
        1,
        "Target.createTarget",
        json!({"url": "about:blank"}),
    )
    .await;
    assert!(target["result"]["targetId"].is_string(), "{target}");
    let pid = s
        .pool
        .browser_pid(SessionId::parse(&id).unwrap())
        .expect("local browser has a pid");
    sigkill(pid);
    assert!(
        wait_closed(&mut ws).await,
        "relay must close when the browser dies"
    );
    let attached = attach(s, &id, &token).await;
    let outcome = attached["outcome"].as_str().unwrap().to_owned();
    assert_eq!(attached["generation"], 2);
    let url = attached["cdp_url"].as_str().unwrap().to_owned();
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let version = rpc(&mut ws, 1, "Browser.getVersion", json!({})).await;
    assert!(
        version["result"]["product"]
            .as_str()
            .unwrap()
            .contains("hrom"),
        "{version}"
    );
    (outcome, id, token, ws)
}

#[tokio::test]
async fn real_browser_crash_recovery_matrix() {
    let dir = tempfile::tempdir().unwrap();
    let Some(s) = start_real(dir.path()).await else {
        return;
    };

    // Ephemeral: nothing survives, a fresh process is reported.
    let (outcome, id, token, _ws) =
        crash_and_reattach(&s, json!({"persistence": "ephemeral"})).await;
    assert_eq!(outcome, "fresh_process");
    let resp = s
        .req(Method::DELETE, &format!("/v1/sessions/{id}"))
        .header("X-BrowserX-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Profile persistence: the same user-data directory is reused.
    let (outcome, id, token, _ws) = crash_and_reattach(&s, json!({"persistence": "profile"})).await;
    assert_eq!(outcome, "restored_from_profile");
    let resp = s
        .req(Method::DELETE, &format!("/v1/sessions/{id}"))
        .header("X-BrowserX-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn real_browser_snapshot_round_trip_after_crash() {
    let dir = tempfile::tempdir().unwrap();
    let Some(s) = start_real(dir.path()).await else {
        return;
    };

    let created = s.create(json!({"persistence": "snapshot"})).await;
    let id = created["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = created["token"].as_str().unwrap().to_owned();
    let (mut ws, _) = tokio_tungstenite::connect_async(created["cdp_url"].as_str().unwrap())
        .await
        .unwrap();
    let set = rpc(
        &mut ws,
        1,
        "Storage.setCookies",
        json!({"cookies": [{"name": "bx_sid", "value": "synthetic-value", "domain": "example.test", "path": "/", "expires": 4_102_444_800_u64}]}),
    )
    .await;
    assert!(set.get("error").is_none(), "{set}");
    let resp = s
        .req(Method::POST, &format!("/v1/sessions/{id}/snapshot"))
        .header("X-BrowserX-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    sigkill(s.pool.browser_pid(SessionId::parse(&id).unwrap()).unwrap());
    assert!(wait_closed(&mut ws).await);
    let attached = attach(&s, &id, &token).await;
    assert_eq!(attached["outcome"], "restored_from_snapshot");
    let (mut ws, _) = tokio_tungstenite::connect_async(attached["cdp_url"].as_str().unwrap())
        .await
        .unwrap();
    let cookies = rpc(&mut ws, 1, "Storage.getCookies", json!({})).await;
    let names: Vec<&str> = cookies["result"]["cookies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"bx_sid"),
        "cookie must be restored from the snapshot: {cookies}"
    );

    // Releasing takes a final snapshot and stops the browser with confirmation.
    let resp = s
        .req(Method::DELETE, &format!("/v1/sessions/{id}"))
        .header("X-BrowserX-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(s.pool.browser_pid(SessionId::parse(&id).unwrap()).is_none());
}

#[tokio::test]
async fn real_shared_browser_isolates_contexts() {
    let dir = tempfile::tempdir().unwrap();
    let Some(s) = start_real(dir.path()).await else {
        return;
    };
    let a = s.create(json!({"isolation": "shared_browser"})).await;
    let b = s.create(json!({"isolation": "shared_browser"})).await;
    let (mut wa, _) = tokio_tungstenite::connect_async(a["cdp_url"].as_str().unwrap())
        .await
        .unwrap();
    let (mut wb, _) = tokio_tungstenite::connect_async(b["cdp_url"].as_str().unwrap())
        .await
        .unwrap();
    let ta = rpc(
        &mut wa,
        1,
        "Target.createTarget",
        json!({"url": "about:blank"}),
    )
    .await;
    let tb = rpc(
        &mut wb,
        1,
        "Target.createTarget",
        json!({"url": "about:blank"}),
    )
    .await;
    let target_a = ta["result"]["targetId"].as_str().unwrap().to_owned();
    let target_b = tb["result"]["targetId"].as_str().unwrap().to_owned();
    let listed = rpc(&mut wa, 2, "Target.getTargets", json!({})).await;
    let ids: Vec<&str> = listed["result"]["targetInfos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["targetId"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&target_a.as_str()),
        "client A must see its own page: {listed}"
    );
    assert!(
        !ids.contains(&target_b.as_str()),
        "client A must not see B's page: {listed}"
    );
    let contexts: std::collections::BTreeSet<&str> = listed["result"]["targetInfos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["browserContextId"].as_str().unwrap())
        .collect();
    assert_eq!(
        contexts.len(),
        1,
        "every listed target belongs to A's context: {listed}"
    );
    let refused = rpc(
        &mut wa,
        3,
        "Target.attachToTarget",
        json!({"targetId": target_b}),
    )
    .await;
    assert!(refused.get("error").is_some(), "{refused}");
    let refused = rpc(&mut wa, 4, "Browser.close", json!({})).await;
    assert!(refused.get("error").is_some(), "{refused}");
    let attached = rpc(
        &mut wa,
        5,
        "Target.attachToTarget",
        json!({"targetId": target_a}),
    )
    .await;
    assert!(attached["result"]["sessionId"].is_string(), "{attached}");
    let cookies = rpc(&mut wa, 6, "Storage.getCookies", json!({})).await;
    assert!(cookies.get("error").is_none(), "{cookies}");
}
