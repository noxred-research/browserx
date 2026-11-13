#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Shared harness: an in-process BrowserX server and an MCP client that speaks JSON-RPC over the
//! stdio transport through an in-memory pipe.

use std::sync::Arc;
use std::time::Duration;

use browserx_core::BrowserRuntime;
use browserx_core::clock::SystemClock;
use browserx_egress::EgressPolicy;
use browserx_mcp::{Config, Ctx, Server, stdio};
use browserx_pool::{Pool, PoolConfig};
use browserx_server::{ApiKeyConfig, AppState, Authenticator, ServerLimits, key_digest, serve};
use browserx_store::{MemoryLeaseStore, MemorySnapshotStore, Sealer};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// A synthetic BrowserX API key.
pub const KEY: &str = "bxk_test_mcp_not_a_real_key";

/// A BrowserX server on loopback listeners.
pub struct TestServer {
    pub api: String,
    pub ops: String,
    pub pool: Pool,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<browserx_core::Result<()>>>,
    pub dir: tempfile::TempDir,
}

pub fn pool_config() -> PoolConfig {
    PoolConfig {
        queue_timeout: Duration::from_millis(500),
        recovery_backoff: Duration::from_millis(10),
        operation_timeout: Duration::from_secs(90),
        ..PoolConfig::default()
    }
}

/// Starts a server over `runtime`. `egress` is the destination policy browsers are held to.
pub async fn start_server(
    runtime: Arc<dyn BrowserRuntime>,
    cfg: PoolConfig,
    egress: EgressPolicy,
) -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let api_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ops_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    let ops_addr = ops_listener.local_addr().unwrap();
    let keys = vec![ApiKeyConfig {
        name: "mcp".into(),
        sha256: key_digest(KEY),
        max_sessions: 16,
    }];
    let mut cfg = cfg;
    cfg.maintenance_interval = Duration::from_millis(200);
    cfg.owner_quotas = keys
        .iter()
        .map(|k| (k.name.clone(), k.max_sessions))
        .collect();
    let pool = Pool::new(
        cfg,
        runtime,
        Arc::new(MemoryLeaseStore::new()),
        Arc::new(MemorySnapshotStore::new()),
        Arc::new(Sealer::new(
            "test0001".into(),
            &browserx_store::Zeroizing::new([9u8; 32]),
        )),
        Arc::new(SystemClock),
        egress,
        dir.path().join("profiles"),
    )
    .unwrap();
    pool.start().await.unwrap();
    let state = AppState::new(
        pool.clone(),
        Authenticator::new(&keys).unwrap(),
        &format!("http://{api_addr}"),
        "default".into(),
        Arc::new(|| Ok(())),
    )
    .unwrap();
    state.set_limits(ServerLimits {
        download_root: dir.path().join("downloads"),
        ..ServerLimits::default()
    });
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(serve(state, api_listener, ops_listener, async move {
        let _ = stopped.await;
    }));
    TestServer {
        api: format!("http://{api_addr}"),
        ops: format!("http://{ops_addr}"),
        pool,
        stop: Some(stop),
        handle: Some(handle),
        dir,
    }
}

impl TestServer {
    /// MCP configuration text for this server, plus `extra` sections.
    pub fn mcp_config(&self, extra: &str) -> Config {
        let key = self.dir.path().join("mcp-api-key");
        std::fs::write(&key, format!("{KEY}\n")).unwrap();
        let text = format!(
            "[server]\nurl = \"{}\"\nops_url = \"{}\"\napi_key_file = \"{}\"\n\
             [audit]\npath = \"{}\"\n{extra}",
            self.api,
            self.ops,
            key.display(),
            self.dir.path().join("mcp-audit.jsonl").display(),
        );
        Config::parse(&text, self.dir.path()).unwrap()
    }

    pub async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// An MCP client over an in-memory pipe running the stdio transport.
pub struct McpClient {
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    reader: BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    served: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    next_id: u64,
    pub ctx: Arc<Ctx>,
}

impl McpClient {
    pub fn start(config: Config) -> Self {
        let ctx = Ctx::build(config).unwrap();
        ctx.start();
        let server = Arc::new(Server::new(Arc::clone(&ctx)));
        let (client_io, server_io) = tokio::io::duplex(16 * 1024 * 1024);
        let (server_read, server_write) = tokio::io::split(server_io);
        let served = tokio::spawn(stdio::serve(
            BufReader::new(server_read),
            server_write,
            server,
        ));
        let (client_read, client_write) = tokio::io::split(client_io);
        Self {
            writer: client_write,
            reader: BufReader::new(client_read),
            served: Some(served),
            next_id: 0,
            ctx,
        }
    }

    /// Sends one request and returns the whole response frame.
    pub async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.send_line(&frame.to_string()).await;
        loop {
            let mut line = String::new();
            let n =
                tokio::time::timeout(Duration::from_secs(120), self.reader.read_line(&mut line))
                    .await
                    .expect("timed out waiting for a reply")
                    .unwrap();
            assert!(n > 0, "the server closed the stream");
            let value: Value =
                serde_json::from_str(line.trim()).expect("stdout carries only JSON-RPC frames");
            if value["id"] == json!(id) {
                return value;
            }
        }
    }

    pub async fn send_line(&mut self, line: &str) {
        self.writer.write_all(line.as_bytes()).await.unwrap();
        self.writer.write_all(b"\n").await.unwrap();
        self.writer.flush().await.unwrap();
    }

    pub async fn notify(&mut self, method: &str) {
        let frame = json!({"jsonrpc": "2.0", "method": method});
        self.send_line(&frame.to_string()).await;
    }

    /// Initializes the session the way an MCP client does.
    pub async fn initialize(&mut self) -> Value {
        let reply = self
            .request(
                "initialize",
                json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp-test", "version": "1"}}),
            )
            .await;
        self.notify("notifications/initialized").await;
        reply["result"].clone()
    }

    /// Calls a tool and returns the `tools/call` result.
    pub async fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let reply = self
            .request("tools/call", json!({"name": name, "arguments": arguments}))
            .await;
        assert!(
            reply.get("error").is_none(),
            "{name}: protocol error {reply}"
        );
        reply["result"].clone()
    }

    /// Calls a tool that must succeed; returns its structured content.
    pub async fn ok(&mut self, name: &str, arguments: Value) -> Value {
        let result = self.tool(name, arguments).await;
        assert_eq!(result["isError"], false, "{name} failed: {result}");
        result["structuredContent"].clone()
    }

    /// Calls a tool that must fail; returns the failure text.
    pub async fn fails(&mut self, name: &str, arguments: Value) -> String {
        let result = self.tool(name, arguments).await;
        assert_eq!(
            result["isError"], true,
            "{name} should have failed: {result}"
        );
        result["content"][0]["text"].as_str().unwrap().to_owned()
    }

    /// Closes stdin and waits for the server to finish.
    pub async fn finish(mut self) {
        let _ = self.writer.shutdown().await;
        if let Some(served) = self.served.take() {
            tokio::time::timeout(Duration::from_secs(30), served)
                .await
                .expect("the server stops when stdin closes")
                .unwrap()
                .unwrap();
        }
        self.ctx.shutdown().await;
    }
}

/// The text of every content block of a tool result, joined.
pub fn all_text(result: &Value) -> String {
    result["content"]
        .as_array()
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| b["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}
