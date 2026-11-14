#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Helpers of the audit export tests: a flaky TCP proxy (to simulate an outage of a service),
//! audit entries, and chain verification of received records.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use browserx_mcp::audit::{self, Audit, Caller, Entry, Phase};
use browserx_mcp::backends::export::Exporter;
use browserx_mcp::{Config, Ctx};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// A loopback TCP forwarder that can be switched off: while it is down, connections are closed
/// at once and open ones are cut, which is what a stopped service looks like to a client.
pub struct Proxy {
    pub port: u16,
    target: Arc<AtomicU16>,
    down: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Proxy {
    /// Listens on a free loopback port; set the target before use.
    pub async fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = Arc::new(AtomicU16::new(0));
        let (down, watcher) = watch::channel(false);
        let task = {
            let target = Arc::clone(&target);
            tokio::spawn(async move {
                loop {
                    let Ok((mut inbound, _)) = listener.accept().await else {
                        return;
                    };
                    if *watcher.borrow() {
                        continue;
                    }
                    let target = target.load(Ordering::Relaxed);
                    let mut watcher = watcher.clone();
                    tokio::spawn(async move {
                        let Ok(mut outbound) = TcpStream::connect(("127.0.0.1", target)).await
                        else {
                            return;
                        };
                        tokio::select! {
                            _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {}
                            _ = watcher.wait_for(|down| *down) => {}
                        }
                    });
                }
            })
        };
        Self {
            port,
            target,
            down,
            task,
        }
    }

    /// The host port the connections are forwarded to.
    pub fn set_target(&self, port: u16) {
        self.target.store(port, Ordering::Relaxed);
    }

    /// Switches the service off (`true`) or on.
    pub fn set_down(&self, down: bool) {
        self.down.send_replace(down);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A configuration with the standard required sections, an engagement identity and an audit
/// log `<name>.jsonl`, followed by `extra`.
pub fn config(dir: &Path, name: &str, engagement: &str, extra: &str) -> Config {
    std::fs::write(dir.join("key"), "bxk_test_synthetic_key_value\n").unwrap();
    let text = format!(
        "[server]\nurl = \"http://127.0.0.1:1\"\napi_key_file = \"key\"\n\
         [audit]\npath = \"{name}.jsonl\"\n\
         [engagement]\nid = \"{engagement}\"\noperator = \"alice\"\nauthorization_note = \"ticket 7\"\n\
         {extra}"
    );
    Config::parse(&text, dir).unwrap()
}

/// A started server context (real audit log with the configured export sinks).
pub fn start_ctx(cfg: Config) -> Arc<Ctx> {
    let ctx = Ctx::build(cfg).unwrap();
    ctx.start();
    ctx
}

/// Writes a secret file (mode 0600) and returns its path.
pub fn secret_file(dir: &Path, name: &str, value: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    std::fs::write(&path, format!("{value}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// Appends `count` entries (alternating intent and result) and returns their sequence numbers.
pub fn write_entries(audit: &Audit, tag: &str, count: usize) -> Vec<u64> {
    let caller = Caller {
        transport: "stdio",
        client_name: Some("export-test".into()),
        remote: None,
        principal: None,
    };
    let tools = ["open_page", "click", "snapshot"];
    (0..count)
        .map(|i| {
            let arguments = json!({"url": format!("https://app.example.test/{tag}/{i}"),
                                   "needle": format!("zebra-{tag}-{i}")});
            let extra = json!({"reason": "out_of_scope", "action_class": "read",
                               "trace_id": format!("trace-{tag}-{i}")});
            audit
                .record(&Entry {
                    phase: if i % 2 == 0 {
                        Phase::Intent
                    } else {
                        Phase::Result
                    },
                    caller: &caller,
                    tool: tools[i % tools.len()],
                    arguments: &arguments,
                    outcome: if i % 2 == 0 { "intent" } else { "refused" },
                    detail: Some("synthetic detail"),
                    duration_ms: Some(i as u64),
                    extra: Some(&extra),
                })
                .unwrap()
        })
        .collect()
}

/// The records of a local log, in order.
pub fn local_records(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// Recomputes the hash chain of `records` (sorted by `seq`, duplicates removed): panics unless
/// the chain is intact and holds `expected` entries.
pub fn assert_chain(records: &[Value], expected: usize) {
    let mut sorted: Vec<&Value> = records.iter().collect();
    sorted.sort_by_key(|r| r["seq"].as_u64().unwrap());
    sorted.dedup_by_key(|r| {
        (
            r["seq"].as_u64().unwrap(),
            r["hash"].as_str().unwrap().to_owned(),
        )
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("received.jsonl");
    let text: String = sorted.iter().map(|r| format!("{r}\n")).collect();
    std::fs::write(&path, text).unwrap();
    let report = audit::verify(&path).unwrap();
    assert_eq!(report.broken, None, "the received records break the chain");
    assert_eq!(report.entries as usize, expected);
}

/// Polls `check` until it returns `Some` or `timeout` passes.
pub async fn eventually<T, F, Fut>(what: &str, timeout: Duration, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = check().await {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The statistics of the first sink.
pub fn stats(exporter: &Exporter) -> browserx_mcp::backends::export::SinkStats {
    exporter.stats().remove(0)
}

/// Runs `body` and returns the slowest single call, to check that recording stays fast while a
/// sink is down.
pub fn slowest<F: FnMut()>(count: usize, mut body: F) -> Duration {
    let mut worst = Duration::ZERO;
    for _ in 0..count {
        let start = Instant::now();
        body();
        worst = worst.max(start.elapsed());
    }
    worst
}
