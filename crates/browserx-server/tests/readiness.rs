//! `/readyz` reports an unreachable lease registry; `/healthz` keeps answering.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use browserx_core::clock::SystemClock;
use browserx_core::{
    Error, Generation, LeaseStore, Result, SessionId, SessionLease, SessionStatus,
};
use browserx_egress::EgressPolicy;
use browserx_pool::testing::FakeRuntime;
use browserx_server::{AppState, Authenticator, serve};
use browserx_store::{MemoryLeaseStore, MemorySnapshotStore, Sealer, Zeroizing};
use serde_json::Value;
use tokio::net::TcpListener;

/// A registry that stops answering when `down` is set.
struct Flaky {
    inner: MemoryLeaseStore,
    down: Arc<AtomicBool>,
}

impl Flaky {
    fn check(&self) -> Result<()> {
        if self.down.load(Ordering::SeqCst) {
            Err(Error::Storage("registry unreachable".into()))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl LeaseStore for Flaky {
    async fn insert(&self, lease: &SessionLease) -> Result<()> {
        self.check()?;
        self.inner.insert(lease).await
    }
    async fn get(&self, id: SessionId) -> Result<Option<SessionLease>> {
        self.check()?;
        self.inner.get(id).await
    }
    async fn compare_and_swap(&self, expected: Generation, lease: &SessionLease) -> Result<()> {
        self.check()?;
        self.inner.compare_and_swap(expected, lease).await
    }
    async fn list(
        &self,
        owner: Option<&str>,
        statuses: Option<&[SessionStatus]>,
    ) -> Result<Vec<SessionLease>> {
        self.check()?;
        self.inner.list(owner, statuses).await
    }
    async fn purge_terminal(&self, older_than: time::OffsetDateTime) -> Result<u64> {
        self.check()?;
        self.inner.purge_terminal(older_than).await
    }
}

#[tokio::test]
async fn readyz_reports_an_unreachable_lease_registry() {
    let dir = tempfile::tempdir().unwrap();
    let down = Arc::new(AtomicBool::new(false));
    let fake = FakeRuntime::new();
    let pool = browserx_pool::Pool::new(
        common::test_pool_config(),
        Arc::new(fake),
        Arc::new(Flaky {
            inner: MemoryLeaseStore::new(),
            down: down.clone(),
        }),
        Arc::new(MemorySnapshotStore::new()),
        Arc::new(Sealer::new("test0001".into(), &Zeroizing::new([9u8; 32]))),
        Arc::new(SystemClock),
        EgressPolicy::default(),
        dir.path().join("profiles"),
    )
    .unwrap();
    pool.start().await.unwrap();
    let api = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ops = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ops_url = format!("http://{}", ops.local_addr().unwrap());
    let state = AppState::new(
        pool,
        Authenticator::new(&common::keys(4)).unwrap(),
        &format!("http://{}", api.local_addr().unwrap()),
        "default".into(),
        Arc::new(|| Ok(())),
    )
    .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(state, api, ops, async move {
        let _ = stopped.await;
    }));
    let client = reqwest::Client::new();
    let get = |path: &'static str| {
        let (client, url) = (client.clone(), format!("{ops_url}{path}"));
        async move { client.get(url).send().await.unwrap() }
    };

    assert_eq!(get("/readyz").await.status(), 200);

    down.store(true, Ordering::SeqCst);
    let resp = get("/readyz").await;
    assert_eq!(resp.status(), 503);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ready"], false);
    assert!(
        body["problems"][0]
            .as_str()
            .unwrap()
            .starts_with("lease store unreachable"),
        "{body}"
    );
    // Liveness does not depend on the registry.
    assert_eq!(get("/healthz").await.status(), 200);

    down.store(false, Ordering::SeqCst);
    assert_eq!(get("/readyz").await.status(), 200);

    let _ = stop.send(());
    server.await.unwrap().unwrap();
}
