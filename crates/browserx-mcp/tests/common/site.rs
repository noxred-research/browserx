#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A tiny loopback fixture site with an access log, and a Chromium runtime for tests.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use browserx_runtime::{ChromiumRuntime, LaunchProfile, RuntimeConfig, discover_chromium};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A running fixture site.
pub struct Site {
    /// `http://127.0.0.1:<port>`.
    pub base: String,
    /// The port.
    pub port: u16,
    log: Arc<Mutex<Vec<String>>>,
}

impl Site {
    /// Every request seen, as `METHOD /path?query`.
    pub fn hits(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    /// How many requests contain `needle`.
    pub fn count(&self, needle: &str) -> usize {
        self.hits().iter().filter(|h| h.contains(needle)).count()
    }
}

/// Serves `pages` (path -> HTML body). A path that is not listed answers 404. Every request is
/// logged. A `POST` to a listed path answers with a small confirmation page.
pub async fn serve(pages: Vec<(&str, String)>) -> Site {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log: Arc<Mutex<Vec<String>>> = Arc::default();
    let table: Arc<BTreeMap<String, String>> = Arc::new(
        pages
            .into_iter()
            .map(|(path, body)| (path.to_owned(), body))
            .collect(),
    );
    let seen = Arc::clone(&log);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let table = Arc::clone(&table);
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                let n = stream.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..n]).into_owned();
                let mut parts = request.split_whitespace();
                let method = parts.next().unwrap_or("GET").to_owned();
                let target = parts.next().unwrap_or("/").to_owned();
                if target != "/favicon.ico" {
                    seen.lock().unwrap().push(format!("{method} {target}"));
                }
                let path = target.split('?').next().unwrap_or("/");
                let (status, body) = match table.get(path) {
                    Some(body) if method == "POST" => (
                        200,
                        format!(
                            "<!doctype html><html><head><title>Done</title></head><body><main><h1>Done</h1><p>{path} accepted</p>{}</main></body></html>",
                            if body.is_empty() {
                                ""
                            } else {
                                "<a href=\"/\">Back</a>"
                            }
                        ),
                    ),
                    Some(body) => (
                        200,
                        format!(
                            "<!doctype html><html><head><title>Fixture</title></head><body>{body}</body></html>"
                        ),
                    ),
                    None => (
                        404,
                        "<!doctype html><title>Not found</title><p>missing</p>".to_owned(),
                    ),
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Site {
        base: format!("http://{addr}"),
        port: addr.port(),
        log,
    }
}

/// A Chromium runtime, or `None` (with a `SKIP:` note) when no browser is found.
pub fn chromium_runtime(dir: &std::path::Path) -> Option<ChromiumRuntime> {
    let Some(exe) = discover_chromium() else {
        eprintln!("SKIP: no Chromium found (set BROWSERX_CHROMIUM_PATH to run this test)");
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
    std::fs::create_dir_all(dir.join("tmp")).unwrap();
    let cfg = RuntimeConfig {
        launch_profiles: BTreeMap::from([("default".to_owned(), profile)]),
        temp_root: dir.join("tmp"),
        startup_timeout: Duration::from_secs(60),
        ..RuntimeConfig::default()
    }
    .validated()
    .unwrap();
    Some(ChromiumRuntime::new(cfg).unwrap())
}
