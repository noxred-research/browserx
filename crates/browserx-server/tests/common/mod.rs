#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use browserx_core::BrowserRuntime;
use browserx_core::clock::SystemClock;
use browserx_egress::EgressPolicy;
use browserx_pool::testing::FakeRuntime;
use browserx_pool::{Pool, PoolConfig};
use browserx_server::{ApiKeyConfig, AppState, Authenticator, key_digest, serve};
use browserx_store::{MemoryLeaseStore, MemorySnapshotStore, Sealer};
use serde_json::Value;
use tokio::net::TcpListener;

pub const KEY: &str = "bxk_test_alpha_not_a_real_key";
pub const OTHER_KEY: &str = "bxk_test_beta_not_a_real_key";

pub struct TestServer {
    pub api: String,
    pub ops: String,
    pub ws: String,
    pub client: reqwest::Client,
    pub pool: Pool,
    pub state: AppState,
    pub fake: Option<FakeRuntime>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<browserx_core::Result<()>>>,
    _dir: tempfile::TempDir,
}

pub fn keys(max_sessions: usize) -> Vec<ApiKeyConfig> {
    vec![
        ApiKeyConfig {
            name: "dev".into(),
            sha256: key_digest(KEY),
            max_sessions,
        },
        ApiKeyConfig {
            name: "other".into(),
            sha256: key_digest(OTHER_KEY),
            max_sessions,
        },
    ]
}

pub async fn start_with(
    runtime: Arc<dyn BrowserRuntime>,
    fake: Option<FakeRuntime>,
    cfg: PoolConfig,
    max_sessions: usize,
) -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let api_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ops_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    let ops_addr = ops_listener.local_addr().unwrap();
    let mut cfg = cfg;
    cfg.maintenance_interval = Duration::from_millis(200);
    cfg.owner_quotas = keys(max_sessions)
        .into_iter()
        .map(|k| (k.name, k.max_sessions))
        .collect();
    let pool = Pool::new(
        cfg,
        runtime,
        Arc::new(MemoryLeaseStore::new()),
        Arc::new(MemorySnapshotStore::new()),
        Arc::new(Sealer::new("test0001".into(), [9u8; 32])),
        Arc::new(SystemClock),
        EgressPolicy::default(),
        dir.path().join("profiles"),
    )
    .unwrap();
    pool.start().await.unwrap();
    let state = AppState::new(
        pool.clone(),
        Authenticator::new(&keys(max_sessions)).unwrap(),
        &format!("http://{api_addr}"),
        "default".into(),
        Arc::new(|| Ok(())),
    )
    .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(serve(
        state.clone(),
        api_listener,
        ops_listener,
        async move {
            let _ = stopped.await;
        },
    ));
    TestServer {
        api: format!("http://{api_addr}"),
        ops: format!("http://{ops_addr}"),
        ws: format!("ws://{api_addr}"),
        client: reqwest::Client::new(),
        pool,
        state,
        fake,
        stop: Some(stop),
        handle: Some(handle),
        _dir: dir,
    }
}

pub async fn start() -> TestServer {
    let fake = FakeRuntime::new();
    start_with(Arc::new(fake.clone()), Some(fake), test_pool_config(), 16).await
}

pub fn test_pool_config() -> PoolConfig {
    PoolConfig {
        queue_timeout: Duration::from_millis(300),
        recovery_backoff: Duration::from_millis(10),
        ..PoolConfig::default()
    }
}

impl TestServer {
    pub fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{path}", self.api))
            .bearer_auth(KEY)
    }

    pub async fn create(&self, body: Value) -> Value {
        let resp = self
            .req(reqwest::Method::POST, "/v1/sessions")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{:?}", resp.text().await);
        resp.json().await.unwrap()
    }

    pub async fn stop(&mut self) -> browserx_core::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.handle.take() {
            Some(handle) => handle.await.unwrap(),
            None => Ok(()),
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
