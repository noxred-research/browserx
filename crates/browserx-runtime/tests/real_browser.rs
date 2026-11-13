//! Integration tests against a real Chromium. They run when `discover_chromium()`
//! finds one (set `BROWSERX_CHROMIUM_PATH` to pick a binary) and otherwise print a
//! note and pass.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use browserx_cdp::{CdpClient, CdpLimits};
use browserx_core::snapshot::{CookieRecord, OriginStorage, STATE_FORMAT_VERSION};
use browserx_core::{
    BrowserHandle, BrowserId, BrowserRuntime, ContextId, Error, LaunchRequest, RuntimeHealth,
    StateSnapshot,
};
use browserx_runtime::{
    ChromiumRuntime, LaunchProfile, ProfileLock, RuntimeConfig, discover_chromium,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn chromium() -> Option<PathBuf> {
    let found = discover_chromium();
    if found.is_none() {
        println!(
            "SKIP: no Chromium discoverable (set BROWSERX_CHROMIUM_PATH); real-browser test not run"
        );
    }
    found
}

fn runtime(executable: &Path, temp_root: &Path) -> ChromiumRuntime {
    let mut cfg = RuntimeConfig {
        temp_root: temp_root.to_path_buf(),
        ..RuntimeConfig::default()
    };
    cfg.launch_profiles.insert(
        "default".into(),
        LaunchProfile {
            executable: Some(executable.to_path_buf()),
            // Test hosts (containers, restricted user namespaces) often cannot run
            // the sandbox.
            args: vec!["--no-sandbox".into(), "--disable-gpu".into()],
            ..LaunchProfile::default()
        },
    );
    ChromiumRuntime::new(cfg).unwrap()
}

fn request(user_data_dir: Option<PathBuf>) -> LaunchRequest {
    LaunchRequest {
        browser_id: BrowserId::new(),
        launch_profile: None,
        user_data_dir,
        proxy_server: None,
        persona_seed: "12345".to_owned(),
    }
}

async fn connect(handle: &dyn BrowserHandle) -> CdpClient {
    CdpClient::connect(handle.browser_ws_url(), CdpLimits::default())
        .await
        .unwrap()
}

async fn eventually<T, Fut>(what: &str, mut probe: impl FnMut() -> Fut) -> T
where
    Fut: Future<Output = Option<T>>,
{
    for _ in 0..150 {
        if let Some(value) = probe().await {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

/// A tiny HTTP server that answers every request with a static page and counts hits.
async fn serve() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                if socket.read(&mut buf).await.unwrap_or(0) == 0 {
                    return;
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let body = "<html><body>browserx test page</body></html>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (addr, hits)
}

async fn open_page(cdp: &CdpClient, url: &str, context: Option<&ContextId>) -> String {
    let mut params = json!({ "url": url });
    if let Some(c) = context {
        params["browserContextId"] = json!(c.0);
    }
    let reply = cdp.call("Target.createTarget", params, None).await.unwrap();
    reply["targetId"].as_str().unwrap().to_owned()
}

async fn evaluate(cdp: &CdpClient, target_id: &str, expression: &str) -> Value {
    let attached = cdp
        .call(
            "Target.attachToTarget",
            json!({"targetId": target_id, "flatten": true}),
            None,
        )
        .await
        .unwrap();
    let session = attached["sessionId"].as_str().unwrap().to_owned();
    let reply = cdp
        .call(
            "Runtime.evaluate",
            json!({"expression": expression, "returnByValue": true}),
            Some(&session),
        )
        .await
        .unwrap();
    cdp.call(
        "Target.detachFromTarget",
        json!({"sessionId": session}),
        None,
    )
    .await
    .unwrap();
    reply["result"]["value"].clone()
}

fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn dir_is_empty(dir: &Path) -> bool {
    std::fs::read_dir(dir).map_or(true, |mut entries| entries.next().is_none())
}

#[tokio::test]
async fn launch_health_version_and_confirmed_shutdown() {
    let Some(exe) = chromium() else { return };
    let temp = tempfile::tempdir().unwrap();
    let rt = runtime(&exe, temp.path());
    assert_eq!(rt.launch_profiles(), vec!["default".to_owned()]);

    let handle = rt.launch(request(None)).await.unwrap();
    let pid = handle.pid().unwrap();
    assert!(
        handle.browser_ws_url().starts_with("ws://127.0.0.1:"),
        "{}",
        handle.browser_ws_url()
    );
    assert!(
        handle.version().contains("Chrom"),
        "version: {}",
        handle.version()
    );
    assert_eq!(handle.health().await, RuntimeHealth::Healthy);
    assert!(pid_alive(pid));
    assert!(
        !dir_is_empty(temp.path()),
        "temp user-data dir should exist while running"
    );

    handle.shutdown_confirmed().await.unwrap();
    assert!(
        !pid_alive(pid),
        "process must be gone once shutdown returns"
    );
    assert!(
        dir_is_empty(temp.path()),
        "temp user-data dir must be removed"
    );
    assert!(matches!(
        handle.health().await,
        RuntimeHealth::Exited { .. }
    ));
    // Idempotent.
    handle.shutdown_confirmed().await.unwrap();
}

#[tokio::test]
async fn health_reports_exit_after_the_process_is_killed() {
    let Some(exe) = chromium() else { return };
    let temp = tempfile::tempdir().unwrap();
    let handle = runtime(&exe, temp.path())
        .launch(request(None))
        .await
        .unwrap();
    let pid = handle.pid().unwrap();
    assert_eq!(handle.health().await, RuntimeHealth::Healthy);
    let status = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    eventually("exited health", || async {
        matches!(handle.health().await, RuntimeHealth::Exited { .. }).then_some(())
    })
    .await;
    handle.shutdown_confirmed().await.unwrap();
    assert!(dir_is_empty(temp.path()));
}

#[tokio::test]
async fn dropping_a_handle_kills_the_browser() {
    let Some(exe) = chromium() else { return };
    let temp = tempfile::tempdir().unwrap();
    let handle = runtime(&exe, temp.path())
        .launch(request(None))
        .await
        .unwrap();
    let pid = handle.pid().unwrap();
    drop(handle);
    eventually("process exit after drop", || async {
        (!pid_alive(pid)).then_some(())
    })
    .await;
}

#[tokio::test]
async fn contexts_can_be_created_and_disposed() {
    let Some(exe) = chromium() else { return };
    let temp = tempfile::tempdir().unwrap();
    let handle = runtime(&exe, temp.path())
        .launch(request(None))
        .await
        .unwrap();
    let cdp = connect(handle.as_ref()).await;

    let a = handle.create_context().await.unwrap();
    let b = handle.create_context().await.unwrap();
    assert_ne!(a, b);
    let listed = cdp
        .call("Target.getBrowserContexts", json!({}), None)
        .await
        .unwrap();
    let ids: Vec<&str> = listed["browserContextIds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(ids.contains(&a.0.as_str()) && ids.contains(&b.0.as_str()));

    handle.dispose_context(&a).await.unwrap();
    let listed = cdp
        .call("Target.getBrowserContexts", json!({}), None)
        .await
        .unwrap();
    let ids: Vec<&str> = listed["browserContextIds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(!ids.contains(&a.0.as_str()) && ids.contains(&b.0.as_str()));
    assert!(
        handle.dispose_context(&a).await.is_err(),
        "double dispose must fail"
    );

    cdp.close().await;
    handle.shutdown_confirmed().await.unwrap();
}

fn cookie<'a>(state: &'a StateSnapshot, name: &str) -> Option<&'a CookieRecord> {
    state.cookies.iter().find(|c| c.name == name)
}

fn local_storage<'a>(state: &'a StateSnapshot, origin: &str) -> Option<&'a [(String, String)]> {
    state
        .origins
        .iter()
        .find(|o| o.origin == origin)
        .map(|o| o.local_storage.as_slice())
}

#[tokio::test]
async fn cookies_and_local_storage_round_trip_between_browsers() {
    let Some(exe) = chromium() else { return };
    let temp = tempfile::tempdir().unwrap();
    let rt = runtime(&exe, temp.path());
    let (addr, _hits) = serve().await;
    let origin = format!("http://{addr}");
    let page = format!("{origin}/index.html");

    // Source browser: build state in an isolated context.
    let source = rt.launch(request(None)).await.unwrap();
    let cdp = connect(source.as_ref()).await;
    let ctx = source.create_context().await.unwrap();
    let target = open_page(&cdp, &page, Some(&ctx)).await;
    eventually("page origin", || async {
        let value = evaluate(&cdp, &target, "location.origin").await;
        (value == json!(origin)).then_some(())
    })
    .await;
    evaluate(&cdp, &target, "localStorage.setItem('theme','dark'); localStorage.setItem('k2','v 2 \"quoted\" \u{e9}'); 1").await;
    cdp.call(
        "Storage.setCookies",
        json!({
            "browserContextId": ctx.0,
            "cookies": [
                {"name": "session_c", "value": "s-1", "domain": "127.0.0.1", "path": "/"},
                {"name": "persist_c", "value": "p-2", "domain": "127.0.0.1", "path": "/",
                 "expires": 4_102_444_800.0, "httpOnly": true, "sameSite": "Lax"},
            ],
        }),
        None,
    )
    .await
    .unwrap();

    let captured = source.capture_state(Some(&ctx)).await.unwrap();
    assert_eq!(captured.format_version, STATE_FORMAT_VERSION);
    assert!(captured.browser_version.contains("Chrom"));
    let session_c = cookie(&captured, "session_c").expect("session cookie captured");
    assert_eq!(session_c.value, "s-1");
    assert_eq!(session_c.expires, None);
    let persist_c = cookie(&captured, "persist_c").expect("persistent cookie captured");
    assert!(persist_c.http_only);
    assert_eq!(persist_c.same_site.as_deref(), Some("Lax"));
    // Chromium may clamp far-future expiries; only persistence matters here.
    assert!(persist_c.expires.is_some_and(|e| e > 1_700_000_000.0));
    let storage = local_storage(&captured, &origin).expect("origin storage captured");
    assert!(storage.contains(&("theme".to_owned(), "dark".to_owned())));
    assert!(
        storage
            .iter()
            .any(|(k, v)| k == "k2" && v.contains("\"quoted\""))
    );
    assert_eq!(captured.open_urls, vec![page.clone()]);
    // The default context's cookie jar is separate.
    assert!(cookie(&source.capture_state(None).await.unwrap(), "session_c").is_none());

    cdp.close().await;
    source.shutdown_confirmed().await.unwrap();

    // Target browser: restore into a fresh context, then into the default context.
    let dest = rt.launch(request(None)).await.unwrap();
    let ctx2 = dest.create_context().await.unwrap();
    dest.restore_state(Some(&ctx2), &captured).await.unwrap();
    let restored = eventually("restored origin storage", || async {
        let state = dest.capture_state(Some(&ctx2)).await.unwrap();
        local_storage(&state, &origin)
            .is_some_and(|s| !s.is_empty())
            .then_some(state)
    })
    .await;
    assert_eq!(
        cookie(&restored, "session_c").map(|c| c.value.as_str()),
        Some("s-1")
    );
    let persist = cookie(&restored, "persist_c").expect("persistent cookie restored");
    assert!(persist.http_only && persist.same_site.as_deref() == Some("Lax"));
    let storage = local_storage(&restored, &origin).unwrap();
    assert!(storage.contains(&("theme".to_owned(), "dark".to_owned())));
    assert!(
        storage
            .iter()
            .any(|(k, v)| k == "k2" && v.contains("\"quoted\""))
    );
    assert!(
        restored.open_urls.contains(&page),
        "open pages are reopened: {:?}",
        restored.open_urls
    );

    dest.restore_state(None, &captured).await.unwrap();
    let default_state = eventually("default context restore", || async {
        let state = dest.capture_state(None).await.unwrap();
        (cookie(&state, "session_c").is_some()
            && local_storage(&state, &origin).is_some_and(|s| !s.is_empty()))
        .then_some(state)
    })
    .await;
    assert_eq!(
        cookie(&default_state, "persist_c").map(|c| c.value.as_str()),
        Some("p-2")
    );

    dest.shutdown_confirmed().await.unwrap();
    assert!(dir_is_empty(temp.path()));
}

#[tokio::test]
async fn restoring_storage_does_not_contact_the_origin() {
    let Some(exe) = chromium() else { return };
    let temp = tempfile::tempdir().unwrap();
    let rt = runtime(&exe, temp.path());
    let (addr, hits) = serve().await;
    let origin = format!("http://{addr}");

    let state = StateSnapshot {
        format_version: STATE_FORMAT_VERSION,
        browser_version: "test".into(),
        cookies: Vec::new(),
        origins: vec![OriginStorage {
            origin: origin.clone(),
            local_storage: vec![("seeded".into(), "yes".into())],
        }],
        open_urls: Vec::new(),
    };
    let handle = rt.launch(request(None)).await.unwrap();
    let ctx = handle.create_context().await.unwrap();
    handle.restore_state(Some(&ctx), &state).await.unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "seeding must be answered locally"
    );

    let cdp = connect(handle.as_ref()).await;
    let target = open_page(&cdp, &format!("{origin}/"), Some(&ctx)).await;
    let value = eventually("seeded value", || async {
        let read = evaluate(
            &cdp,
            &target,
            &format!("location.origin === '{origin}' ? localStorage.getItem('seeded') : undefined"),
        )
        .await;
        read.as_str().map(str::to_owned)
    })
    .await;
    assert_eq!(value, "yes");
    assert!(hits.load(Ordering::SeqCst) >= 1);

    // Bounds are enforced.
    let mut too_many = state.clone();
    too_many.origins = (0..65)
        .map(|i| OriginStorage {
            origin: format!("http://127.0.0.1:{}", 10_000 + i),
            local_storage: vec![("a".into(), "b".into())],
        })
        .collect();
    assert!(matches!(
        handle.restore_state(Some(&ctx), &too_many).await,
        Err(Error::InvalidRequest(_))
    ));
    let mut newer = state;
    newer.format_version = STATE_FORMAT_VERSION + 1;
    assert!(matches!(
        handle.restore_state(None, &newer).await,
        Err(Error::InvalidRequest(_))
    ));

    cdp.close().await;
    handle.shutdown_confirmed().await.unwrap();
}

#[tokio::test]
async fn profile_directory_reuse_keeps_cookies_and_the_lock_is_exclusive() {
    let temp = tempfile::tempdir().unwrap();
    let profile_dir = temp.path().join("profiles").join("alpha");
    let lock = ProfileLock::acquire(&profile_dir).unwrap();
    assert!(matches!(
        ProfileLock::acquire(&profile_dir),
        Err(Error::ProfileLocked(_))
    ));

    let Some(exe) = chromium() else { return };
    let rt = runtime(&exe, &temp.path().join("tmp"));

    let first = rt.launch(request(Some(profile_dir.clone()))).await.unwrap();
    let cdp = connect(first.as_ref()).await;
    cdp.call(
        "Storage.setCookies",
        json!({"cookies": [{"name": "keep", "value": "me", "domain": "example.test",
                            "path": "/", "expires": 4_102_444_800.0}]}),
        None,
    )
    .await
    .unwrap();
    cdp.close().await;
    first.shutdown_confirmed().await.unwrap();
    assert!(
        profile_dir.exists(),
        "a caller-owned profile dir must survive shutdown"
    );

    let second = rt.launch(request(Some(profile_dir.clone()))).await.unwrap();
    let state = second.capture_state(None).await.unwrap();
    assert_eq!(cookie(&state, "keep").map(|c| c.value.as_str()), Some("me"));
    second.shutdown_confirmed().await.unwrap();

    drop(lock);
    assert!(ProfileLock::acquire(&profile_dir).is_ok());
}

#[tokio::test]
async fn proxy_flags_reach_the_browser() {
    let Some(exe) = chromium() else { return };
    let temp = tempfile::tempdir().unwrap();
    let handle = runtime(&exe, temp.path())
        .launch(LaunchRequest {
            proxy_server: Some("http://127.0.0.1:9".into()),
            persona_seed: "12345".to_owned(),
            ..request(None)
        })
        .await
        .unwrap();
    // WebRTC must not open UDP paths around the proxy (and so around the
    // egress policy behind it).
    // (Chromium may rewrite its own command line into one space-joined string.)
    let cmdline = std::fs::read(format!("/proc/{}/cmdline", handle.pid().unwrap())).unwrap();
    let cmdline = String::from_utf8_lossy(&cmdline).replace('\0', " ");
    assert!(
        cmdline.contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"),
        "missing WebRTC policy flag in {cmdline}"
    );
    let cdp = connect(handle.as_ref()).await;
    // Chromium reports its command line through SystemInfo.
    let info = cdp
        .call("Browser.getVersion", json!({}), None)
        .await
        .unwrap();
    assert!(info["product"].is_string());
    let (addr, hits) = serve().await;
    // The proxy points at a dead port and `<-loopback>` removes Chromium's implicit
    // loopback bypass, so a request to the local server must go to the proxy and
    // fail: the server never sees it.
    let target = open_page(&cdp, &format!("http://{addr}/"), None).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let url = eventually("target url", || async {
        let targets = cdp
            .call("Target.getTargets", json!({}), None)
            .await
            .unwrap();
        targets["targetInfos"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["targetId"] == json!(target))
            .and_then(|t| t["url"].as_str().map(str::to_owned))
    })
    .await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "loopback must not bypass the proxy (url: {url})"
    );
    cdp.close().await;
    handle.shutdown_confirmed().await.unwrap();
}

// ---------------------------------------------------------------- capture integrity

/// A page can override `JSON.stringify`, `Object.entries` and friends. Capture
/// must not depend on any script that runs in the page: the origin and the
/// entries come from the browser.
#[tokio::test]
async fn capture_ignores_page_script_forging_origin_and_storage() {
    let Some(exe) = chromium() else { return };
    let temp = tempfile::tempdir().unwrap();
    let rt = runtime(&exe, temp.path());
    let (addr, _hits) = serve().await;
    let origin = format!("http://{addr}");

    let browser = rt.launch(request(None)).await.unwrap();
    let cdp = connect(browser.as_ref()).await;
    let ctx = browser.create_context().await.unwrap();
    let target = open_page(&cdp, &format!("{origin}/index.html"), Some(&ctx)).await;
    eventually("page origin", || async {
        (evaluate(&cdp, &target, "location.origin").await == json!(origin)).then_some(())
    })
    .await;
    // Real state, then a hostile page that rewrites every primitive a
    // script-based reader would use to claim another origin with chosen entries.
    evaluate(&cdp, &target, "localStorage.setItem('real','yes'); 1").await;
    evaluate(
        &cdp,
        &target,
        r#"(() => {
            const forged = JSON.stringify(['http://victim.example', [['planted', '1']]]);
            JSON.stringify = () => forged;
            Object.entries = () => [['planted', '1']];
            Object.defineProperty(window, 'location', { value: { origin: 'http://victim.example' } });
            return 1;
        })()"#,
    )
    .await;

    let captured = browser.capture_state(Some(&ctx)).await.unwrap();
    assert!(
        captured
            .origins
            .iter()
            .all(|o| o.origin != "http://victim.example"),
        "forged origin captured: {:?}",
        captured.origins
    );
    let storage = local_storage(&captured, &origin).expect("the real origin is captured");
    assert_eq!(storage, [("real".to_owned(), "yes".to_owned())]);
    assert!(
        captured
            .origins
            .iter()
            .flat_map(|o| &o.local_storage)
            .all(|(k, _)| k != "planted"),
        "forged entry captured"
    );

    cdp.close().await;
    browser.shutdown_confirmed().await.unwrap();
}

/// Sets `localStorage.big` to `chars` characters on a fresh origin in `context`.
async fn fill_origin(cdp: &CdpClient, context: &ContextId, chars: usize) -> String {
    let (addr, _hits) = serve().await;
    let origin = format!("http://{addr}");
    let target = open_page(cdp, &format!("{origin}/"), Some(context)).await;
    eventually("page origin", || async {
        (evaluate(cdp, &target, "location.origin").await == json!(origin)).then_some(())
    })
    .await;
    evaluate(
        cdp,
        &target,
        &format!("localStorage.setItem('big', 'x'.repeat({chars})); 1"),
    )
    .await;
    origin
}

#[tokio::test]
async fn capture_beyond_the_total_byte_budget_is_a_typed_error() {
    let Some(exe) = chromium() else { return };
    let temp = tempfile::tempdir().unwrap();
    let rt = runtime(&exe, temp.path());
    let browser = rt.launch(request(None)).await.unwrap();
    let cdp = connect(browser.as_ref()).await;
    let ctx = browser.create_context().await.unwrap();

    // Each origin is under the 5 MiB per-origin limit; together they pass the
    // 48 MiB capture budget (and so would pass the 64 MiB sealed limit soon).
    const CHARS: usize = 4_500_000;
    let mut origins = Vec::new();
    for _ in 0..3 {
        origins.push(fill_origin(&cdp, &ctx, CHARS).await);
    }
    let small = browser.capture_state(Some(&ctx)).await.unwrap();
    assert_eq!(
        small.origins.len(),
        3,
        "within budget everything is captured"
    );

    for _ in 0..9 {
        origins.push(fill_origin(&cdp, &ctx, CHARS).await);
    }
    match browser.capture_state(Some(&ctx)).await {
        Err(Error::InvalidRequest(message)) => {
            assert!(message.contains("snapshot budget"), "{message}");
        }
        other => panic!("expected a budget error, got {other:?}"),
    }
    // The browser is fine; state within budget can still be captured elsewhere.
    assert!(matches!(browser.health().await, RuntimeHealth::Healthy));
    assert!(browser.capture_state(None).await.is_ok());

    cdp.close().await;
    browser.shutdown_confirmed().await.unwrap();
}

#[tokio::test]
async fn an_oversized_reply_closes_the_control_connection_but_not_the_browser() {
    let Some(exe) = chromium() else { return };
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = RuntimeConfig {
        temp_root: temp.path().to_path_buf(),
        cdp_max_message_bytes: 1024 * 1024,
        ..RuntimeConfig::default()
    };
    cfg.launch_profiles.insert(
        "default".into(),
        LaunchProfile {
            executable: Some(exe.clone()),
            args: vec!["--no-sandbox".into(), "--disable-gpu".into()],
            ..LaunchProfile::default()
        },
    );
    let rt = ChromiumRuntime::new(cfg).unwrap();
    let browser = rt.launch(request(None)).await.unwrap();
    let cdp = connect(browser.as_ref()).await;
    let ctx = browser.create_context().await.unwrap();

    let big = fill_origin(&cdp, &ctx, 2_000_000).await;
    let (addr, _hits) = serve().await;
    let small = format!("http://{addr}");
    let target = open_page(&cdp, &format!("{small}/"), Some(&ctx)).await;
    eventually("page origin", || async {
        (evaluate(&cdp, &target, "location.origin").await == json!(small)).then_some(())
    })
    .await;
    evaluate(&cdp, &target, "localStorage.setItem('ok','1'); 1").await;

    // The big origin's reply passes the 1 MiB limit: that origin is skipped, the
    // connection is replaced mid-capture and the small origin is still captured.
    let captured = browser.capture_state(Some(&ctx)).await.unwrap();
    assert!(local_storage(&captured, &big).is_none());
    assert_eq!(
        local_storage(&captured, &small).unwrap(),
        [("ok".to_owned(), "1".to_owned())]
    );
    // And again: nothing is permanently broken.
    assert!(browser.capture_state(Some(&ctx)).await.is_ok());
    assert!(matches!(browser.health().await, RuntimeHealth::Healthy));
    let second = browser.create_context().await.unwrap();
    browser.dispose_context(&second).await.unwrap();

    cdp.close().await;
    browser.shutdown_confirmed().await.unwrap();
}

// ---------------------------------------------------------------- worker crash

/// Not a test of its own: the child half of
/// [`sweep_kills_a_browser_orphaned_by_a_crashed_worker`]. It launches a browser,
/// announces the pid and then waits to be killed like a crashing worker.
#[tokio::test]
async fn orphan_launcher_helper() {
    let Ok(root) = std::env::var("BROWSERX_ORPHAN_HELPER_TEMP") else {
        return;
    };
    let Some(exe) = chromium() else { return };
    let handle = runtime(&exe, Path::new(&root))
        .launch(request(None))
        .await
        .unwrap();
    println!("ORPHAN_PID={}", handle.pid().unwrap());
    tokio::time::sleep(Duration::from_secs(120)).await;
    drop(handle);
}

#[tokio::test]
async fn sweep_kills_a_browser_orphaned_by_a_crashed_worker() {
    use std::io::BufRead;
    use std::process::{Command, Stdio};

    let Some(exe) = chromium() else { return };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("tmp");

    // A worker process that launches a browser and is then killed outright.
    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let worker = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "orphan_launcher_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("BROWSERX_ORPHAN_HELPER_TEMP", &root)
        .env("BROWSERX_CHROMIUM_PATH", &exe)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut worker = KillOnDrop(worker);
    let stdout = worker.0.stdout.take().unwrap();
    let pid: u32 = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
                // libtest has already printed "test <name> ... " on this line
                .find_map(|line| {
                    line.split_once("ORPHAN_PID=")
                        .map(|(_, pid)| pid.to_owned())
                })
        }),
    )
    .await
    .expect("the helper announced a browser in time")
    .unwrap()
    .expect("helper output")
    .parse()
    .unwrap();
    worker.0.kill().unwrap();
    worker.0.wait().unwrap();

    // The browser outlives the worker, and the worker left its traces.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(pid_alive(pid), "browser did not survive the worker crash");
    assert!(!dir_is_empty(&root));

    let report = runtime(&exe, &root).sweep_orphans().await.unwrap();
    assert_eq!(report.killed, 1, "{report:?}");
    assert_eq!(report.removed_dirs, 1, "{report:?}");
    eventually("orphan to die", || async {
        (!pid_alive(pid)).then_some(())
    })
    .await;
    assert!(dir_is_empty(&root), "stale directory or record left behind");

    // Nothing left: a second sweep is a no-op.
    let again = runtime(&exe, &root).sweep_orphans().await.unwrap();
    assert_eq!(again, browserx_runtime::SweepReport::default());
}

#[tokio::test]
async fn sweep_leaves_a_running_workers_browsers_alone() {
    let Some(exe) = chromium() else { return };
    let temp = tempfile::tempdir().unwrap();
    let rt = runtime(&exe, temp.path());
    let handle = rt.launch(request(None)).await.unwrap();
    let pid = handle.pid().unwrap();

    let report = rt.sweep_orphans().await.unwrap();
    assert_eq!(report, browserx_runtime::SweepReport::default());
    assert!(pid_alive(pid));
    assert!(matches!(handle.health().await, RuntimeHealth::Healthy));

    handle.shutdown_confirmed().await.unwrap();
    assert!(dir_is_empty(temp.path()), "shutdown removes dir and record");
}
