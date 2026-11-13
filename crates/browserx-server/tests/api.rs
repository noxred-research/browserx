#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::{KEY, OTHER_KEY, TestServer, start, start_with, test_pool_config};
use futures_util::{SinkExt, StreamExt};
use reqwest::Method;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

async fn json_of(resp: reqwest::Response) -> (u16, Value) {
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn call(
    s: &TestServer,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let mut req = s.req(method, path);
    if let Some(t) = token {
        req = req.header("X-BrowserX-Token", t);
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    json_of(req.send().await.unwrap()).await
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn rpc(ws: &mut Ws, id: u64, method: &str, params: Value) -> Value {
    ws.send(Message::text(
        json!({"id": id, "method": method, "params": params}).to_string(),
    ))
    .await
    .unwrap();
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for a CDP reply")
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline {
        if let Ok(None | Some(Err(_) | Ok(Message::Close(_)))) =
            tokio::time::timeout(Duration::from_millis(500), ws.next()).await
        {
            return true;
        }
    }
    false
}

#[tokio::test]
async fn authentication_is_required() {
    let s = start().await;
    let r = s
        .client
        .get(format!("{}/v1/sessions", s.api))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["www-authenticate"], "Bearer");
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "unauthorized");
    let r = s
        .client
        .get(format!("{}/v1/sessions", s.api))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = s
        .client
        .get(format!("{}/v1/sessions", s.api))
        .header("Authorization", "Basic abc")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = s.req(Method::GET, "/v1/sessions").send().await.unwrap();
    assert_eq!(r.status(), 200);
    // The relay does not accept API keys: its credential is the session token.
    let r = s
        .client
        .get(format!("{}/v1/launch-profiles", s.api))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn session_lifecycle_over_http() {
    let s = start().await;
    let created = s.create(json!({"labels": {"job": "t1"}})).await;
    let id = created["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = created["token"].as_str().unwrap().to_owned();
    assert!(id.starts_with("ses_"));
    assert!(token.starts_with("bxt_"));
    assert_eq!(created["outcome"], "fresh_process");
    assert_eq!(created["session"]["status"], "idle");
    assert_eq!(created["session"]["generation"], 1);
    assert_eq!(created["session"]["labels"]["job"], "t1");
    let cdp = created["cdp_url"].as_str().unwrap();
    assert!(cdp.starts_with("ws://127.0.0.1:"), "{cdp}");
    assert!(cdp.ends_with(&format!("/cdp/{id}/{token}")), "{cdp}");
    let text = created.to_string();
    for hidden in ["token_digest", "worker_id", "context_id", "browser_ws"] {
        assert!(!text.contains(hidden), "{hidden} leaked");
    }

    let (code, got) = call(&s, Method::GET, &format!("/v1/sessions/{id}"), None, None).await;
    assert_eq!(code, 200);
    assert_eq!(got["session"]["session_id"], id.as_str());
    assert!(
        !got.to_string().contains("bxt_"),
        "GET must never return the token"
    );

    let (_, listed) = call(&s, Method::GET, "/v1/sessions", None, None).await;
    assert_eq!(listed["sessions"].as_array().unwrap().len(), 1);
    let (_, none) = call(&s, Method::GET, "/v1/sessions?status=closed", None, None).await;
    assert!(none["sessions"].as_array().unwrap().is_empty());
    let (code, _) = call(&s, Method::GET, "/v1/sessions?status=bogus", None, None).await;
    assert_eq!(code, 400);

    // attach
    let (code, body) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{id}/attach"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["outcome"], "resumed_same_process");
    assert_eq!(body["generation"], 1);
    assert_eq!(body["session"]["status"], "active");
    let (code, body) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{id}/attach"),
        None,
        None,
    )
    .await;
    assert_eq!((code, &body["error"]["code"]), (403, &json!("forbidden")));
    let (code, _) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{id}/attach"),
        Some("bxt_wrong"),
        None,
    )
    .await;
    assert_eq!(code, 403);

    // renew
    let (code, body) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{id}/renew"),
        Some(&token),
        Some(json!({"generation": 1, "ttl_secs": 120})),
    )
    .await;
    assert_eq!(code, 200, "{body}");
    let (code, body) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{id}/renew"),
        Some(&token),
        Some(json!({"generation": 7})),
    )
    .await;
    assert_eq!(
        (code, &body["error"]["code"]),
        (409, &json!("stale_generation"))
    );
    let (code, _) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{id}/renew"),
        Some(&token),
        Some(json!({"generation": 1, "ttl_secs": 99_999_999})),
    )
    .await;
    assert_eq!(code, 400);
    let (code, _) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{id}/renew"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(code, 400);

    // release
    let (code, body) = call(
        &s,
        Method::DELETE,
        &format!("/v1/sessions/{id}?generation=1"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["session"]["status"], "closed");
    let (code, body) = call(
        &s,
        Method::DELETE,
        &format!("/v1/sessions/{id}"),
        None,
        None,
    )
    .await;
    assert_eq!((code, &body["session"]["status"]), (200, &json!("closed")));
    assert!(s.fake.as_ref().unwrap().alive().is_empty());
}

#[tokio::test]
async fn error_mapping() {
    let s = start_with_quota(1).await;
    // 400: malformed body / unknown field / bad id
    let r = s
        .req(Method::POST, "/v1/sessions")
        .body("{nope")
        .header("content-type", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(json_of(r).await.0, 400);
    let (code, body) = call(
        &s,
        Method::POST,
        "/v1/sessions",
        None,
        Some(json!({"persistent": true})),
    )
    .await;
    assert_eq!(
        (code, &body["error"]["code"]),
        (400, &json!("invalid_request"))
    );
    let (code, _) = call(&s, Method::GET, "/v1/sessions/not-an-id", None, None).await;
    assert_eq!(code, 400);
    let (code, _) = call(
        &s,
        Method::POST,
        "/v1/sessions",
        None,
        Some(json!({"persistence": "profile", "isolation": "shared_browser"})),
    )
    .await;
    assert_eq!(code, 400);
    // 404
    let (code, body) = call(
        &s,
        Method::GET,
        &format!("/v1/sessions/{}", browserx_core::SessionId::new()),
        None,
        None,
    )
    .await;
    assert_eq!((code, &body["error"]["code"]), (404, &json!("not_found")));
    let (code, body) = call(&s, Method::GET, "/v1/nothing", None, None).await;
    assert_eq!((code, &body["error"]["code"]), (404, &json!("not_found")));
    // 429 quota with Retry-After
    s.create(json!({})).await;
    let r = s
        .req(Method::POST, "/v1/sessions")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 429);
    assert_eq!(r.headers()["retry-after"], "1");
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "capacity");
    // Another owner has its own quota and cannot see the first one's sessions.
    let other = s
        .client
        .post(format!("{}/v1/sessions", s.api))
        .bearer_auth(OTHER_KEY)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), 201);
    let (_, mine) = call(&s, Method::GET, "/v1/sessions", None, None).await;
    assert_eq!(mine["sessions"].as_array().unwrap().len(), 1);
    let foreign_id = {
        let body: Value = other.json().await.unwrap();
        body["session"]["session_id"].as_str().unwrap().to_owned()
    };
    let (code, _) = call(
        &s,
        Method::GET,
        &format!("/v1/sessions/{foreign_id}"),
        None,
        None,
    )
    .await;
    assert_eq!(code, 404);
    let (code, _) = call(
        &s,
        Method::DELETE,
        &format!("/v1/sessions/{foreign_id}"),
        None,
        None,
    )
    .await;
    assert_eq!(code, 404);
}

async fn start_with_quota(max: usize) -> TestServer {
    let fake = browserx_pool::testing::FakeRuntime::new();
    start_with(
        std::sync::Arc::new(fake.clone()),
        Some(fake),
        test_pool_config(),
        max,
    )
    .await
}

#[tokio::test]
async fn capacity_timeout_maps_to_429_and_launch_failure_to_502() {
    let fake = browserx_pool::testing::FakeRuntime::new();
    let cfg = browserx_pool::PoolConfig {
        max_browsers: 1,
        ..test_pool_config()
    };
    let s = start_with(
        std::sync::Arc::new(fake.clone()),
        Some(fake.clone()),
        cfg,
        16,
    )
    .await;
    s.create(json!({})).await;
    let r = s
        .req(Method::POST, "/v1/sessions")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 429);
    let (_, listed) = call(&s, Method::GET, "/v1/sessions", None, None).await;
    let id = listed["sessions"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    call(
        &s,
        Method::DELETE,
        &format!("/v1/sessions/{id}"),
        None,
        None,
    )
    .await;
    fake.fail_next_launches(1);
    let (code, body) = call(&s, Method::POST, "/v1/sessions", None, Some(json!({}))).await;
    assert_eq!((code, &body["error"]["code"]), (502, &json!("browser")));
}

#[tokio::test]
async fn handoff_rotates_token_and_closes_old_relay() {
    let s = start().await;
    let created = s.create(json!({})).await;
    let id = created["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = created["token"].as_str().unwrap().to_owned();
    let old_url = created["cdp_url"].as_str().unwrap().to_owned();

    let (mut old_ws, _) = tokio_tungstenite::connect_async(&old_url).await.unwrap();
    let echoed = rpc(
        &mut old_ws,
        1,
        "Runtime.evaluate",
        json!({"expression": "1"}),
    )
    .await;
    assert_eq!(echoed["result"]["echo"], "Runtime.evaluate");

    let (code, body) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{id}/handoff"),
        Some(&token),
        Some(json!({"generation": 1})),
    )
    .await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["session"]["generation"], 2);
    let new_token = body["token"].as_str().unwrap().to_owned();
    assert_ne!(new_token, token);
    let new_url = body["cdp_url"].as_str().unwrap().to_owned();
    assert!(new_url.ends_with(&new_token));

    assert!(
        wait_closed(&mut old_ws).await,
        "old relay must be closed by the handoff"
    );
    // The old token no longer opens relays or attaches.
    let err = tokio_tungstenite::connect_async(&old_url)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == 403),
        "{err}"
    );
    let (code, _) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{id}/attach"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(code, 403);
    let (code, body) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{id}/handoff"),
        Some(&new_token),
        Some(json!({"generation": 1})),
    )
    .await;
    assert_eq!(
        (code, &body["error"]["code"]),
        (409, &json!("stale_generation"))
    );

    let (mut new_ws, _) = tokio_tungstenite::connect_async(&new_url).await.unwrap();
    let echoed = rpc(&mut new_ws, 1, "Page.enable", json!({})).await;
    assert_eq!(echoed["result"]["echo"], "Page.enable");
}

#[tokio::test]
async fn dedicated_relay_is_a_transparent_byte_relay() {
    let s = start().await;
    let created = s.create(json!({})).await;
    let id = created["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (mut ws, _) = tokio_tungstenite::connect_async(created["cdp_url"].as_str().unwrap())
        .await
        .unwrap();
    // Anything goes through, including methods a shared session would refuse.
    let v = rpc(&mut ws, 1, "Browser.close", json!({"a": 1})).await;
    assert_eq!(v["result"]["params"], json!({"a": 1}));
    let v = rpc(&mut ws, 2, "Target.createBrowserContext", json!({})).await;
    assert_eq!(v["result"]["echo"], "Target.createBrowserContext");

    let (_, got) = call(&s, Method::GET, &format!("/v1/sessions/{id}"), None, None).await;
    assert_eq!(got["session"]["status"], "active");
    let metrics = s
        .client
        .get(format!("{}/metrics", s.ops))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("browserx_relay_connections 1"),
        "{metrics}"
    );
    ws.close(None).await.unwrap();
    drop(ws);
    let mut idle = false;
    for _ in 0..80 {
        let (_, got) = call(&s, Method::GET, &format!("/v1/sessions/{id}"), None, None).await;
        if got["session"]["status"] == "idle" {
            idle = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(idle, "closing the last relay must mark the session idle");
}

#[tokio::test]
async fn relay_rejects_bad_credentials_and_non_websocket_requests() {
    let s = start().await;
    let created = s.create(json!({})).await;
    let url = created["cdp_url"].as_str().unwrap().to_owned();
    let id = created["session"]["session_id"].as_str().unwrap();
    let bad = format!("{}/cdp/{id}/bxt_wrong", s.ws);
    let err = tokio_tungstenite::connect_async(&bad).await.unwrap_err();
    assert!(
        matches!(&err, tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == 403),
        "{err}"
    );
    let missing = format!(
        "{}/cdp/{}/{}",
        s.ws,
        browserx_core::SessionId::new(),
        "bxt_x"
    );
    let err = tokio_tungstenite::connect_async(&missing)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == 404),
        "{err}"
    );
    // A plain GET (no upgrade) is not a valid relay request.
    let r = s
        .client
        .get(url.replace("ws://", "http://"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_client_error());
}

#[tokio::test]
async fn shared_relay_scopes_a_client_to_its_context() {
    let s = start().await;
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
    let target_a = ta["result"]["targetId"].as_str().unwrap().to_owned();
    let tb = rpc(
        &mut wb,
        1,
        "Target.createTarget",
        json!({"url": "about:blank"}),
    )
    .await;
    let target_b = tb["result"]["targetId"].as_str().unwrap().to_owned();

    // The browser saw each request pinned to a different context.
    let browser = s.fake.as_ref().unwrap().browsers()[0].clone();
    let contexts: Vec<String> = browser
        .calls()
        .iter()
        .filter(|c| c.method == "Target.createTarget")
        .map(|c| c.params["browserContextId"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(contexts.len(), 2);
    assert_ne!(contexts[0], contexts[1]);

    // getTargets only shows the caller's own target.
    let got = rpc(&mut wa, 2, "Target.getTargets", json!({})).await;
    let ids: Vec<&str> = got["result"]["targetInfos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["targetId"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![target_a.as_str()]);

    // Foreign targets cannot be attached; own ones can.
    let refused = rpc(
        &mut wa,
        3,
        "Target.attachToTarget",
        json!({"targetId": target_b, "flatten": true}),
    )
    .await;
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .contains("another session"),
        "{refused}"
    );
    let attached = rpc(
        &mut wa,
        4,
        "Target.attachToTarget",
        json!({"targetId": target_a, "flatten": true}),
    )
    .await;
    let page_session = attached["result"]["sessionId"].as_str().unwrap().to_owned();
    ws_send_session(&mut wa, 5, &page_session, "Page.enable").await;

    for (n, method) in [
        "Target.createBrowserContext",
        "Target.disposeBrowserContext",
        "Browser.close",
        "Browser.crash",
        "SystemInfo.getInfo",
    ]
    .iter()
    .enumerate()
    {
        let r = rpc(&mut wa, 10 + n as u64, method, json!({})).await;
        assert_eq!(r["error"]["code"], -32000, "{method}: {r}");
    }
    // None of the refused calls reached the browser.
    let reached: Vec<String> = browser.calls().iter().map(|c| c.method.clone()).collect();
    for banned in [
        "Target.createBrowserContext",
        "Browser.close",
        "SystemInfo.getInfo",
    ] {
        assert!(
            !reached.iter().any(|m| m == banned),
            "{banned} reached the browser"
        );
    }
    assert!(browser.is_alive());
}

async fn ws_send_session(ws: &mut Ws, id: u64, session: &str, method: &str) {
    ws.send(Message::text(
        json!({"id": id, "sessionId": session, "method": method}).to_string(),
    ))
    .await
    .unwrap();
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Message::Text(t) = msg else {
        panic!("expected text")
    };
    let v: Value = serde_json::from_str(t.as_str()).unwrap();
    assert_eq!(v["id"], id);
    assert_eq!(v["sessionId"], session);
    assert_eq!(v["result"]["echo"], method);
}

#[tokio::test]
async fn snapshot_and_profile_endpoints() {
    let s = start().await;
    let created = s.create(json!({"persistence": "snapshot"})).await;
    let id = created["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = created["token"].as_str().unwrap().to_owned();
    let profile = created["session"]["profile_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(profile.starts_with("prf_"));

    let (code, body) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{id}/snapshot"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["snapshot"]["version"], 1);
    assert_eq!(body["snapshot"]["profile_id"], profile.as_str());
    let (code, body) = call(
        &s,
        Method::GET,
        &format!("/v1/profiles/{profile}/snapshots"),
        None,
        None,
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(body["snapshots"].as_array().unwrap().len(), 1);
    assert!(!body.to_string().contains("sealed"));

    // Erasure is refused while a session uses the profile, then succeeds.
    let (code, _) = call(
        &s,
        Method::DELETE,
        &format!("/v1/profiles/{profile}"),
        None,
        None,
    )
    .await;
    assert_eq!(code, 409);
    call(
        &s,
        Method::DELETE,
        &format!("/v1/sessions/{id}"),
        Some(&token),
        None,
    )
    .await;
    let other = s
        .client
        .get(format!("{}/v1/profiles/{profile}/snapshots", s.api))
        .bearer_auth(OTHER_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), 404);
    let (code, body) = call(
        &s,
        Method::DELETE,
        &format!("/v1/profiles/{profile}"),
        None,
        None,
    )
    .await;
    assert_eq!(code, 200, "{body}");
    assert!(body["deleted_snapshots"].as_u64().unwrap() >= 1);

    // Non-snapshot sessions refuse snapshot requests with 409.
    let plain = s.create(json!({})).await;
    let pid = plain["session"]["session_id"].as_str().unwrap().to_owned();
    let ptoken = plain["token"].as_str().unwrap().to_owned();
    let (code, _) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{pid}/snapshot"),
        Some(&ptoken),
        None,
    )
    .await;
    assert_eq!(code, 409);
}

#[tokio::test]
async fn launch_profiles_are_listed() {
    let s = start().await;
    let (code, body) = call(&s, Method::GET, "/v1/launch-profiles", None, None).await;
    assert_eq!(code, 200);
    assert_eq!(body["default"], "default");
    assert_eq!(body["profiles"], json!(["alt", "default"]));
}

#[tokio::test]
async fn ops_endpoints_and_metrics() {
    let s = start().await;
    let r = s
        .client
        .get(format!("{}/healthz", s.ops))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = s
        .client
        .get(format!("{}/readyz", s.ops))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // The ops listener does not serve the API.
    assert_eq!(
        s.client
            .get(format!("{}/v1/sessions", s.ops))
            .bearer_auth(KEY)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let created = s.create(json!({})).await;
    let id = created["session"]["session_id"].as_str().unwrap();
    let text = s
        .client
        .get(format!("{}/metrics", s.ops))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for needle in [
        "browserx_sessions{status=\"idle\"} 1",
        "browserx_browsers{isolation=\"dedicated_browser\"} 1",
        "browserx_admissions_total{result=\"accepted\"} 1",
        "browserx_queue_depth 0",
        "browserx_recoveries_total{outcome=\"fresh_process\"} 0",
        "browserx_launch_seconds_bucket{le=\"+Inf\"} 1",
        "browserx_launch_seconds_count 1",
        "browserx_relay_connections 0",
        "browserx_snapshots_total{result=\"ok\"} 0",
        "browserx_egress_refused_total 0",
        "# TYPE browserx_launch_seconds histogram",
    ] {
        assert!(text.contains(needle), "missing `{needle}` in:\n{text}");
    }
    assert!(
        !text.contains("bxt_") && !text.contains(id),
        "metrics must not carry session identifiers"
    );

    s.pool.stop_admission();
    let r = s
        .client
        .get(format!("{}/readyz", s.ops))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["problems"][0], "draining");
    assert_eq!(
        s.client
            .get(format!("{}/healthz", s.ops))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let (code, body) = call(&s, Method::POST, "/v1/sessions", None, Some(json!({}))).await;
    assert_eq!(
        (code, &body["error"]["code"]),
        (503, &json!("shutting_down"))
    );
}

#[tokio::test]
async fn graceful_shutdown_closes_relays_and_stops_browsers() {
    let mut s = start().await;
    let created = s.create(json!({"persistence": "snapshot"})).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(created["cdp_url"].as_str().unwrap())
        .await
        .unwrap();
    rpc(&mut ws, 1, "Runtime.enable", json!({})).await;
    let fake = s.fake.clone().unwrap();
    assert_eq!(fake.alive().len(), 1);
    s.stop().await.unwrap();
    assert!(
        wait_closed(&mut ws).await,
        "relay must be closed on shutdown"
    );
    assert!(
        fake.alive().is_empty(),
        "browsers must be stopped on shutdown"
    );
    assert!(s.pool.is_draining());
}

#[tokio::test]
async fn crash_is_recovered_and_reported_on_attach() {
    let s = start().await;
    let created = s.create(json!({})).await;
    let id = created["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = created["token"].as_str().unwrap().to_owned();
    let (mut ws, _) = tokio_tungstenite::connect_async(created["cdp_url"].as_str().unwrap())
        .await
        .unwrap();
    rpc(&mut ws, 1, "Runtime.enable", json!({})).await;
    s.fake.as_ref().unwrap().last().unwrap().kill();
    assert!(wait_closed(&mut ws).await);
    let (code, body) = call(
        &s,
        Method::POST,
        &format!("/v1/sessions/{id}/attach"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["outcome"], "fresh_process");
    assert_eq!(body["generation"], 2);
    let metrics = s
        .client
        .get(format!("{}/metrics", s.ops))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("browserx_recoveries_total{outcome=\"fresh_process\"} 1"),
        "{metrics}"
    );
}
