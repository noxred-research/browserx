//! Relay security checks against a real Chromium. Skipped (with a note) when none is found.
//! Hosts with restricted user namespaces need `BROWSERX_TEST_BROWSER_ARGS="--no-sandbox --disable-gpu"`
//! (that is also the default here).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use browserx_pool::PoolConfig;
use browserx_runtime::{ChromiumRuntime, LaunchProfile, RuntimeConfig, discover_chromium};
use common::{TestServer, start_with};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn start_real(dir: &std::path::Path) -> Option<TestServer> {
    let Some(exe) = discover_chromium() else {
        eprintln!(
            "SKIP: no Chromium found (set BROWSERX_CHROMIUM_PATH to run the relay security tests)"
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

/// A relay connection that keeps every event it sees while waiting for replies.
struct Cdp {
    ws: Ws,
    next_id: u64,
    events: Vec<Value>,
}

impl Cdp {
    async fn open(url: &str) -> Self {
        let (ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        Self {
            ws,
            next_id: 1,
            events: Vec::new(),
        }
    }

    async fn send(&mut self, session: Option<&str>, method: &str, params: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.send_with_id(id, session, method, params).await;
        id
    }

    async fn send_with_id(&mut self, id: u64, session: Option<&str>, method: &str, params: Value) {
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        self.ws.send(Message::text(msg.to_string())).await.unwrap();
    }

    /// Next text message, or `None` after `wait`.
    async fn next(&mut self, wait: Duration) -> Option<Value> {
        loop {
            let msg = tokio::time::timeout(wait, self.ws.next()).await.ok()?;
            match msg? {
                Ok(Message::Text(t)) => return serde_json::from_str(t.as_str()).ok(),
                Ok(_) => {}
                Err(_) => return None,
            }
        }
    }

    async fn call_in(&mut self, session: Option<&str>, method: &str, params: Value) -> Value {
        let id = self.send(session, method, params).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let v = self
                .next(left)
                .await
                .unwrap_or_else(|| panic!("no reply to {method}"));
            if v["id"] == id && v.get("sessionId").and_then(Value::as_str) == session {
                return v;
            }
            if v.get("id").is_none() {
                self.events.push(v);
            }
        }
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.call_in(None, method, params).await
    }

    /// Reads and keeps events for `window`.
    async fn collect_events(&mut self, window: Duration) {
        let deadline = tokio::time::Instant::now() + window;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.next(left).await {
                Some(v) if v.get("id").is_none() => self.events.push(v),
                Some(_) => {}
                None => return,
            }
        }
    }

    /// Opens a blank page and attaches to it; returns `(target id, session id)`.
    async fn page(&mut self) -> (String, String) {
        let t = self
            .call("Target.createTarget", json!({"url": "about:blank"}))
            .await;
        let target = t["result"]["targetId"].as_str().unwrap().to_owned();
        let a = self
            .call(
                "Target.attachToTarget",
                json!({"targetId": target, "flatten": true}),
            )
            .await;
        let session = a["result"]["sessionId"].as_str().unwrap().to_owned();
        (target, session)
    }

    async fn eval(&mut self, session: &str, expression: &str) -> Value {
        self.call_in(
            Some(session),
            "Runtime.evaluate",
            json!({"expression": expression, "returnByValue": true, "userGesture": true}),
        )
        .await
    }
}

fn refused(v: &Value) -> bool {
    v["error"]["code"] == -32000
        && v["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("refused by the"))
}

/// A loopback HTTP server that counts connections.
async fn counting_server() -> (String, Arc<AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = tcp.read(&mut buf).await;
                let _ = tcp
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    (url, hits)
}

/// Finding 2: a dedicated client cannot lift the egress forwarder with a new
/// browser context, and finding 1: it cannot reach the host's files or the
/// browser's internal pages.
#[tokio::test]
async fn dedicated_relay_protects_the_host() {
    let dir = tempfile::tempdir().unwrap();
    let Some(s) = start_real(dir.path()).await else {
        return;
    };
    let (loopback, hits) = counting_server().await;
    let created = s.create(json!({})).await;
    let mut c = Cdp::open(created["cdp_url"].as_str().unwrap()).await;

    // The attack: a context that connects directly.
    for params in [
        json!({"proxyServer": "direct://"}),
        json!({"proxyServer": "direct://", "proxyBypassList": "*"}),
        json!({"proxyBypassList": "127.0.0.1"}),
    ] {
        let r = c.call("Target.createBrowserContext", params).await;
        assert!(refused(&r), "{r}");
    }
    // An ordinary context is fine and inherits the forwarder: loopback stays unreachable.
    let ctx = c.call("Target.createBrowserContext", json!({})).await;
    let ctx = ctx["result"]["browserContextId"]
        .as_str()
        .unwrap()
        .to_owned();
    let t = c
        .call(
            "Target.createTarget",
            json!({"url": "about:blank", "browserContextId": ctx}),
        )
        .await;
    let target = t["result"]["targetId"].as_str().unwrap().to_owned();
    let a = c
        .call(
            "Target.attachToTarget",
            json!({"targetId": target, "flatten": true}),
        )
        .await;
    let session = a["result"]["sessionId"].as_str().unwrap().to_owned();
    c.call_in(Some(&session), "Page.enable", json!({})).await;
    c.call_in(Some(&session), "Page.navigate", json!({"url": loopback}))
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0, "loopback must stay blocked");

    // Navigation to anything but web content is refused, on every path that takes a URL.
    for url in [
        "file:///etc/hostname",
        "FILE:///etc/hostname",
        " file:///etc/hostname",
        "view-source:http://example.test/",
        "chrome://version",
        "about:version",
        "devtools://devtools/bundled/inspector.html",
        "filesystem:http://example.test/temporary/x",
    ] {
        let r = c
            .call_in(Some(&session), "Page.navigate", json!({"url": url}))
            .await;
        assert!(refused(&r), "{url}: {r}");
        let r = c.call("Target.createTarget", json!({"url": url})).await;
        assert!(refused(&r), "{url}: {r}");
        let r = c
            .call_in(
                Some(&session),
                "Network.loadNetworkResource",
                json!({"url": url, "options": {"disableCache": true, "includeCredentials": false}}),
            )
            .await;
        assert!(refused(&r), "{url}: {r}");
    }
    // The state directory's files stay out of reach: nothing loaded file: content.
    let r = c
        .call_in(
            Some(&session),
            "DOM.setFileInputFiles",
            json!({"files": ["/etc/hostname"], "objectId": "x"}),
        )
        .await;
    assert!(refused(&r), "{r}");
    for method in [
        "Tracing.start",
        "Memory.getDOMCounters",
        "SystemInfo.getInfo",
        "Browser.close",
    ] {
        let r = c.call(method, json!({})).await;
        assert!(refused(&r), "{method}: {r}");
    }

    // Everything else keeps working.
    let r = c.eval(&session, "6 * 7").await;
    assert_eq!(r["result"]["result"]["value"], 42, "{r}");
    let r = c
        .call_in(
            Some(&session),
            "Page.navigate",
            json!({"url": "data:text/html,<title>ok</title>"}),
        )
        .await;
    assert!(r.get("error").is_none(), "{r}");
    let v = c.call("Browser.getVersion", json!({})).await;
    assert!(
        v["result"]["product"].as_str().unwrap().contains("hrom"),
        "{v}"
    );
}

/// A dedicated relay refuses the commands that would hand a page (or the
/// client) a browser-level channel the relay cannot see, and the host-reaching
/// commands stay refused on it. Every refusal is answered by the relay and
/// leaves the browser unchanged.
#[tokio::test]
async fn dedicated_relay_refuses_cdp_escape_hatches() {
    let dir = tempfile::tempdir().unwrap();
    let Some(s) = start_real(dir.path()).await else {
        return;
    };
    let created = s.create(json!({})).await;
    let mut c = Cdp::open(created["cdp_url"].as_str().unwrap()).await;
    let (target, session) = c.page().await;

    // Browser-level and page-session addressing are both refused.
    for (method, params) in [
        (
            "Target.exposeDevToolsProtocol",
            json!({"targetId": target, "bindingName": "cdpEscape"}),
        ),
        ("Target.openDevTools", json!({"targetId": target})),
        (
            "Target.setRemoteLocations",
            json!({"locations": [{"host": "127.0.0.1", "port": 9}]}),
        ),
        ("Browser.getBrowserCommandLine", json!({})),
        (
            "Browser.executeBrowserCommand",
            json!({"commandId": "openTabSearch"}),
        ),
        ("Tethering.bind", json!({"port": 1})),
        ("NoSuchDomain.run", json!({})),
        // Host files and the local network through the app and cast domains.
        (
            "PWA.install",
            json!({"manifestId": "file:///", "installUrlOrBundleUrl": "file:///etc/hostname"}),
        ),
        (
            "PWA.launchFilesInApp",
            json!({"manifestId": "http://example.test/", "files": ["/etc/hostname"]}),
        ),
        (
            "PWA.openCurrentPageInApp",
            json!({"manifestId": "http://example.test/"}),
        ),
        (
            "PWA.getOsAppState",
            json!({"manifestId": "http://example.test/"}),
        ),
        ("Cast.enable", json!({})),
        ("Cast.setSinkToUse", json!({"sinkName": "x"})),
        ("Cast.startTabMirroring", json!({"sinkName": "x"})),
    ] {
        let r = c.call(method, params.clone()).await;
        assert!(refused(&r), "{method}: {r}");
        let r = c.call_in(Some(&session), method, params).await;
        assert!(refused(&r), "{method} (page session): {r}");
    }

    // The binding was never installed, so page script has no channel to the browser.
    let r = c.eval(&session, "typeof window.cdpEscape").await;
    assert_eq!(r["result"]["result"]["value"], "undefined", "{r}");

    // The earlier host protections still hold on the same relay.
    let r = c
        .call(
            "Target.createBrowserContext",
            json!({"proxyServer": "direct://"}),
        )
        .await;
    assert!(refused(&r), "{r}");
    let r = c
        .call_in(
            Some(&session),
            "Page.navigate",
            json!({"url": "file:///etc/hostname"}),
        )
        .await;
    assert!(refused(&r), "{r}");

    // Ordinary clients keep working.
    let r = c.eval(&session, "6 * 7").await;
    assert_eq!(r["result"]["result"]["value"], 42, "{r}");
    let r = c
        .call("Browser.getWindowForTarget", json!({"targetId": target}))
        .await;
    assert!(r.get("error").is_none() || !refused(&r), "{r}");
}

/// Finding 18: downloads land in the per-session directory whatever path the client names,
/// and the directory goes away with the last relay connection.
#[tokio::test]
async fn downloads_are_confined_to_the_session_directory() {
    let dir = tempfile::tempdir().unwrap();
    let Some(s) = start_real(dir.path()).await else {
        return;
    };
    let root = s.state.limits().download_root.clone();
    for body in [json!({}), json!({"isolation": "shared_browser"})] {
        let created = s.create(body).await;
        let id = created["session"]["session_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let session_dir = root.join(&id);
        let evil = dir.path().join(format!("evil-{id}"));
        let mut c = Cdp::open(created["cdp_url"].as_str().unwrap()).await;
        let r = c
            .call(
                "Browser.setDownloadBehavior",
                json!({"behavior": "allow", "downloadPath": evil.to_string_lossy()}),
            )
            .await;
        assert!(r.get("error").is_none(), "{r}");
        let (_target, page) = c.page().await;
        c.eval(
            &page,
            "const a = document.createElement('a'); \
             a.href = URL.createObjectURL(new Blob(['payload'])); \
             a.download = 'dropped.txt'; document.body.appendChild(a); a.click(); 1",
        )
        .await;
        let landed = session_dir.join("dropped.txt");
        let mut found = false;
        for _ in 0..100 {
            if landed.is_file() {
                found = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            found,
            "{id}: the download must land in {}",
            session_dir.display()
        );
        assert!(!evil.exists(), "{id}: the requested path must not be used");

        drop(c);
        let mut cleaned = false;
        for _ in 0..50 {
            if !session_dir.exists() {
                cleaned = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            cleaned,
            "{id}: the download directory goes with the last relay"
        );
    }
}

/// Starts two shared sessions of one browser and gives each a page.
async fn two_shared(s: &TestServer) -> (Cdp, (String, String), Cdp, (String, String)) {
    let a = s.create(json!({"isolation": "shared_browser"})).await;
    let b = s.create(json!({"isolation": "shared_browser"})).await;
    let mut ca = Cdp::open(a["cdp_url"].as_str().unwrap()).await;
    let mut cb = Cdp::open(b["cdp_url"].as_str().unwrap()).await;
    let pa = ca.page().await;
    let pb = cb.page().await;
    (ca, pa, cb, pb)
}

/// Finding 4: a client's browser-wide auto-attach must not stall a sibling's popup.
#[tokio::test]
async fn browser_wide_auto_attach_does_not_stall_a_sibling() {
    let dir = tempfile::tempdir().unwrap();
    let Some(s) = start_real(dir.path()).await else {
        return;
    };
    let (mut ca, _pa, mut cb, (_tb, sb)) = two_shared(&s).await;
    let r = ca
        .call(
            "Target.setAutoAttach",
            json!({"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}),
        )
        .await;
    assert!(r.get("error").is_none(), "{r}");

    let opened = cb
        .eval(&sb, "window.open('about:blank', '_blank') !== null")
        .await;
    assert_eq!(opened["result"]["result"]["value"], true, "{opened}");
    let mut popup = None;
    for _ in 0..50 {
        let t = cb.call("Target.getTargets", json!({})).await;
        let pages: Vec<&Value> = t["result"]["targetInfos"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["type"] == "page")
            .collect();
        if pages.len() >= 2 {
            popup = pages
                .iter()
                .find(|i| i["openerId"].is_string())
                .map(|i| i["targetId"].as_str().unwrap().to_owned());
            if popup.is_some() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let popup = popup.expect("the popup must appear among the sibling's targets");
    let a = cb
        .call(
            "Target.attachToTarget",
            json!({"targetId": popup, "flatten": true}),
        )
        .await;
    let session = a["result"]["sessionId"].as_str().unwrap().to_owned();
    let r = tokio::time::timeout(Duration::from_secs(15), cb.eval(&session, "1 + 1"))
        .await
        .expect("the popup must not hang waiting for a debugger");
    assert_eq!(r["result"]["result"]["value"], 2, "{r}");
    let r = cb.eval(&sb, "2 + 2").await;
    assert_eq!(r["result"]["result"]["value"], 4, "{r}");
}

/// Findings 5, 8 and 9: page-session leaks and request-id confusion.
#[tokio::test]
async fn shared_relay_does_not_leak_siblings_through_page_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let Some(s) = start_real(dir.path()).await else {
        return;
    };
    let (mut ca, (ta, sa), mut cb, (tb, _sb)) = two_shared(&s).await;

    // 5: tracing and memory commands on a page session.
    for method in [
        "Tracing.start",
        "Tracing.end",
        "Memory.getDOMCounters",
        "SystemInfo.getInfo",
    ] {
        let r = ca.call_in(Some(&sa), method, json!({})).await;
        assert!(refused(&r), "{method}: {r}");
    }
    // Storage commands naming another context.
    let other = cb
        .call("Target.getTargets", json!({}))
        .await["result"]["targetInfos"][0]["browserContextId"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = ca
        .call_in(
            Some(&sa),
            "Storage.getCookies",
            json!({"browserContextId": other}),
        )
        .await;
    assert!(refused(&r), "{r}");

    // 9: target discovery on a page session reports only the caller's targets.
    let r = ca
        .call_in(
            Some(&sa),
            "Target.setDiscoverTargets",
            json!({"discover": true}),
        )
        .await;
    assert!(r.get("error").is_none(), "{r}");
    ca.collect_events(Duration::from_secs(2)).await;
    let text = serde_json::to_string(&ca.events).unwrap();
    assert!(!text.contains(&tb), "a sibling's target leaked: {text}");
    assert!(!text.contains(&other), "a sibling's context leaked: {text}");
    assert!(
        text.contains(&ta),
        "the caller's own target is reported: {text}"
    );

    // 8: a reused request id cannot turn one answer into another.
    ca.send_with_id(7, None, "Target.getTargets", json!({}))
        .await;
    ca.send_with_id(7, None, "Browser.getVersion", json!({}))
        .await;
    let mut replies = Vec::new();
    while let Some(v) = ca.next(Duration::from_secs(3)).await {
        if v["id"] == 7 {
            replies.push(v);
        }
    }
    assert!(!replies.is_empty());
    let text = serde_json::to_string(&replies).unwrap();
    assert!(!text.contains(&tb), "a sibling's target leaked: {text}");
    assert!(!text.contains(&other), "a sibling's context leaked: {text}");

    // The sibling is unaffected throughout.
    let (_t, sb2) = cb.page().await;
    let r = cb.eval(&sb2, "1 + 1").await;
    assert_eq!(r["result"]["result"]["value"], 2, "{r}");
}
