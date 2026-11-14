//! The lease token travels in the relay URL path and in one header; it must not leak into
//! logs, error bodies or metrics, and a wrong token must look like a wrong session.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use browserx_core::SessionId;
use common::{KEY, OTHER_KEY, start};
use reqwest::Method;
use serde_json::json;
use tokio_tungstenite::tungstenite::Error as WsError;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn status_of(err: &WsError) -> Option<u16> {
    match err {
        WsError::Http(resp) => Some(resp.status().as_u16()),
        _ => None,
    }
}

/// One test per binary: the subscriber is global, so it sees every task of the server.
#[tokio::test]
async fn the_token_never_reaches_logs_error_bodies_or_metrics() {
    let logs = Capture::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish(),
    )
    .unwrap();

    let s = start().await;
    let created = s.create(json!({})).await;
    let id = created["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = created["token"].as_str().unwrap().to_owned();
    let cdp_url = created["cdp_url"].as_str().unwrap().to_owned();
    assert!(cdp_url.contains(&token), "the relay URL carries the token");

    // A real relay connection, then closed by the client.
    let (mut ws, _) = tokio_tungstenite::connect_async(&cdp_url).await.unwrap();
    ws.close(None).await.unwrap();

    // Every kind of bad relay credential ends in the same 401.
    let unknown = SessionId::new().prefixed();
    let mut statuses = Vec::new();
    for path in [
        format!("/cdp/{id}/bxt_wrong"),
        format!("/cdp/{unknown}/{token}"),
        format!("/cdp/{unknown}/bxt_wrong"),
        format!("/cdp/{id}/{token}x"),
    ] {
        let err = tokio_tungstenite::connect_async(format!("{}{path}", s.ws))
            .await
            .unwrap_err();
        statuses.push(status_of(&err));
    }
    assert!(
        statuses.iter().all(|st| *st == Some(401)),
        "wrong token and wrong session are indistinguishable: {statuses:?}"
    );

    // Error bodies of requests that present the token (header) or the session id.
    let mut bodies = Vec::new();
    for (method, path, key) in [
        (Method::GET, format!("/v1/sessions/{id}"), OTHER_KEY),
        (Method::DELETE, format!("/v1/sessions/{id}"), OTHER_KEY),
        (Method::POST, format!("/v1/sessions/{id}/handoff"), KEY),
        (Method::DELETE, format!("/v1/sessions/{unknown}"), KEY),
    ] {
        let resp = s
            .client
            .request(method, format!("{}{path}", s.api))
            .bearer_auth(key)
            .header("X-BrowserX-Token", "bxt_wrong")
            .send()
            .await
            .unwrap();
        assert!(!resp.status().is_success(), "{path}");
        bodies.push(resp.text().await.unwrap());
    }
    let metrics = s
        .client
        .get(format!("{}/metrics", s.ops))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let mut stopped = s;
    stopped.stop().await.unwrap();

    for body in &bodies {
        assert!(!body.contains(&token), "token in an error body: {body}");
    }
    assert!(!metrics.contains(&token) && !metrics.contains(&id));
    assert!(
        !metrics.contains("/cdp") && !metrics.contains("path=") && !metrics.contains("route="),
        "no path or route labels on any metric"
    );
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        logged.contains("relay"),
        "the capture saw the relay: {logged}"
    );
    assert!(!logged.contains(&token), "token in the logs");
    assert!(!logged.contains("bxt_"), "a token-shaped value in the logs");
    assert!(!logged.contains("/cdp/"), "a relay path in the logs");
}
