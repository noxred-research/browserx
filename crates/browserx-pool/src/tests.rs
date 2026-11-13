#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use browserx_core::clock::ManualClock;
use browserx_core::{
    Error, Generation, Isolation, LeaseToken, PersistenceMode, ProxyRoute, RecoveryOutcome,
    RecoveryPolicy, SessionId, SessionSpec, SessionStatus, SnapshotStore,
};
use browserx_egress::EgressPolicy;
use browserx_store::{MemoryLeaseStore, MemorySnapshotStore, Sealer};
use time::OffsetDateTime;

use crate::testing::FakeRuntime;
use crate::{Pool, PoolConfig};

const OWNER: &str = "dev";

struct H {
    pool: Pool,
    rt: FakeRuntime,
    clock: Arc<ManualClock>,
    leases: Arc<MemoryLeaseStore>,
    snaps: Arc<MemorySnapshotStore>,
    sealer: Arc<Sealer>,
    dir: tempfile::TempDir,
}

fn test_cfg() -> PoolConfig {
    PoolConfig {
        recovery_backoff: Duration::from_millis(5),
        queue_timeout: Duration::from_millis(300),
        operation_timeout: Duration::from_secs(10),
        probe_timeout: Duration::from_millis(500),
        ..PoolConfig::default()
    }
}

fn harness(cfg: PoolConfig) -> H {
    let clock = Arc::new(ManualClock::new(OffsetDateTime::now_utc()));
    let leases = Arc::new(MemoryLeaseStore::with_clock(clock.clone()));
    let snaps = Arc::new(MemorySnapshotStore::new());
    let sealer = Arc::new(Sealer::new("test0001".into(), [7u8; 32]));
    let rt = FakeRuntime::new();
    let dir = tempfile::tempdir().unwrap();
    let pool = build_pool(cfg, &rt, &leases, &snaps, &sealer, &clock, &dir);
    H {
        pool,
        rt,
        clock,
        leases,
        snaps,
        sealer,
        dir,
    }
}

fn build_pool(
    cfg: PoolConfig,
    rt: &FakeRuntime,
    leases: &Arc<MemoryLeaseStore>,
    snaps: &Arc<MemorySnapshotStore>,
    sealer: &Arc<Sealer>,
    clock: &Arc<ManualClock>,
    dir: &tempfile::TempDir,
) -> Pool {
    Pool::new(
        cfg,
        Arc::new(rt.clone()),
        leases.clone(),
        snaps.clone(),
        sealer.clone(),
        clock.clone(),
        EgressPolicy::default(),
        dir.path().join("profiles"),
    )
    .unwrap()
}

fn spec(persistence: PersistenceMode) -> SessionSpec {
    SessionSpec {
        persistence,
        ..SessionSpec::default()
    }
}

fn shared() -> SessionSpec {
    SessionSpec {
        isolation: Isolation::SharedBrowser,
        ..SessionSpec::default()
    }
}

async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..200 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for: {what}");
}

#[tokio::test]
async fn create_release_dedicated_session() {
    let h = harness(test_cfg());
    let (lease, token) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    assert_eq!(lease.status, SessionStatus::Idle);
    assert_eq!(lease.generation, Generation(1));
    assert_eq!(lease.last_recovery, Some(RecoveryOutcome::FreshProcess));
    assert_eq!(lease.token_digest, Some(token.digest()));
    let browser = h.rt.last().unwrap();
    let proxy = browser.request.proxy_server.clone().unwrap();
    assert!(proxy.starts_with("http://127.0.0.1:"), "{proxy}");

    let closed = h
        .pool
        .release(OWNER, lease.session_id, Some(&token), Some(Generation(1)))
        .await
        .unwrap();
    assert_eq!(closed.status, SessionStatus::Closed);
    assert!(!browser.is_alive());
    assert_eq!(browser.shutdown_calls(), 1);
    // Idempotent.
    let again = h
        .pool
        .release(OWNER, lease.session_id, None, None)
        .await
        .unwrap();
    assert_eq!(again.status, SessionStatus::Closed);
    let m = h.pool.metrics().await;
    assert_eq!(m.browsers["dedicated_browser"], 0);
}

#[tokio::test]
async fn sticky_key_is_stable_hex() {
    let id = SessionId::new();
    let key = crate::alloc::sticky_key(id);
    assert_eq!(key.len(), 24);
    assert!(
        key.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(key, crate::alloc::sticky_key(id));
    assert!(!key.contains(&id.0.simple().to_string()));
}

#[tokio::test]
async fn owner_quota_is_enforced_per_owner() {
    let mut cfg = test_cfg();
    cfg.default_owner_quota = 1;
    let h = harness(cfg);
    let (a, token) = h
        .pool
        .create("alice", SessionSpec::default())
        .await
        .unwrap();
    let err = h
        .pool
        .create("alice", SessionSpec::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Capacity(_)), "{err}");
    // Another owner is unaffected.
    h.pool.create("bob", SessionSpec::default()).await.unwrap();
    h.pool
        .release("alice", a.session_id, Some(&token), None)
        .await
        .unwrap();
    h.pool
        .create("alice", SessionSpec::default())
        .await
        .unwrap();
    assert_eq!(h.pool.metrics().await.admissions["quota"], 1);
}

#[tokio::test]
async fn admission_times_out_when_full() {
    let mut cfg = test_cfg();
    cfg.max_browsers = 1;
    let h = harness(cfg);
    h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    let started = std::time::Instant::now();
    let err = h
        .pool
        .create(OWNER, SessionSpec::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Capacity(_)), "{err}");
    assert!(started.elapsed() >= Duration::from_millis(250));
    let m = h.pool.metrics().await;
    assert_eq!(m.admissions["timeout"], 1);
    assert_eq!(m.queue_depth, 0);
}

#[tokio::test]
async fn full_queue_refuses_immediately() {
    let mut cfg = test_cfg();
    cfg.max_browsers = 1;
    cfg.queue_capacity = 1;
    cfg.queue_timeout = Duration::from_secs(5);
    let h = harness(cfg);
    let (first, token) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    let pool = h.pool.clone();
    let waiter = tokio::spawn(async move { pool.create("b", SessionSpec::default()).await });
    eventually("waiter queued", || async {
        h.pool.metrics().await.queue_depth == 1
    })
    .await;
    let err = h
        .pool
        .create("c", SessionSpec::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Capacity(_)), "{err}");
    assert_eq!(h.pool.metrics().await.admissions["queue_full"], 1);
    h.pool
        .release(OWNER, first.session_id, Some(&token), None)
        .await
        .unwrap();
    waiter.await.unwrap().unwrap();
}

#[tokio::test]
async fn admission_queue_is_fifo() {
    let mut cfg = test_cfg();
    cfg.max_browsers = 1;
    cfg.queue_timeout = Duration::from_secs(10);
    let h = harness(cfg);
    let (first, token) = h.pool.create("o0", SessionSpec::default()).await.unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut tasks = Vec::new();
    for i in 1..=3 {
        let pool = h.pool.clone();
        let tx = tx.clone();
        tasks.push(tokio::spawn(async move {
            let (lease, token) = pool
                .create(&format!("o{i}"), SessionSpec::default())
                .await
                .unwrap();
            tx.send(i).await.unwrap();
            pool.release(&format!("o{i}"), lease.session_id, Some(&token), None)
                .await
                .unwrap();
        }));
        eventually("queued", || async {
            h.pool.metrics().await.queue_depth == i
        })
        .await;
    }
    drop(tx);
    h.pool
        .release("o0", first.session_id, Some(&token), None)
        .await
        .unwrap();
    let mut order = Vec::new();
    while let Some(i) = rx.recv().await {
        order.push(i);
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(order, vec![1, 2, 3]);
}

#[tokio::test]
async fn validation_and_bounds() {
    let h = harness(test_cfg());
    let too_long = SessionSpec {
        ttl_secs: Some(10_000_000),
        ..SessionSpec::default()
    };
    assert!(matches!(
        h.pool.create(OWNER, too_long).await,
        Err(Error::InvalidRequest(_))
    ));
    let lifetime = SessionSpec {
        max_lifetime_secs: Some(10_000_000),
        ..SessionSpec::default()
    };
    assert!(matches!(
        h.pool.create(OWNER, lifetime).await,
        Err(Error::InvalidRequest(_))
    ));
    let unknown = SessionSpec {
        launch_profile: Some("nope".into()),
        ..SessionSpec::default()
    };
    assert!(matches!(
        h.pool.create(OWNER, unknown).await,
        Err(Error::InvalidRequest(_))
    ));
    let proxy_shared = SessionSpec {
        isolation: Isolation::SharedBrowser,
        proxy: Some(ProxyRoute {
            url: "http://p.test:1".into(),
            username: None,
            password: None,
        }),
        ..SessionSpec::default()
    };
    assert!(matches!(
        h.pool.create(OWNER, proxy_shared).await,
        Err(Error::InvalidRequest(_))
    ));
    let orphan_profile = SessionSpec {
        profile_id: Some(browserx_core::ProfileId::new()),
        ..SessionSpec::default()
    };
    assert!(matches!(
        h.pool.create(OWNER, orphan_profile).await,
        Err(Error::InvalidRequest(_))
    ));
    // Failed validation must not consume the owner's quota.
    assert_eq!(h.pool.metrics().await.browsers["dedicated_browser"], 0);
}

#[tokio::test]
async fn ownership_hides_foreign_sessions() {
    let h = harness(test_cfg());
    let (lease, token) = h
        .pool
        .create("alice", SessionSpec::default())
        .await
        .unwrap();
    assert!(matches!(
        h.pool.get("bob", lease.session_id).await,
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        h.pool.attach("bob", lease.session_id, &token).await,
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        h.pool.release("bob", lease.session_id, None, None).await,
        Err(Error::NotFound(_))
    ));
    assert!(h.pool.list("bob", None).await.unwrap().is_empty());
    // The owner can release without the token.
    h.pool
        .release("alice", lease.session_id, None, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn attach_reports_outcome_once() {
    let h = harness(test_cfg());
    let (lease, token) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    let info = h
        .pool
        .attach(OWNER, lease.session_id, &token)
        .await
        .unwrap();
    assert_eq!(info.outcome, RecoveryOutcome::ResumedSameProcess);
    assert_eq!(info.lease.status, SessionStatus::Active);
    assert!(info.lease.last_attach_at.is_some());

    h.rt.last().unwrap().kill();
    let info = h
        .pool
        .attach(OWNER, lease.session_id, &token)
        .await
        .unwrap();
    assert_eq!(info.outcome, RecoveryOutcome::FreshProcess);
    assert_eq!(info.lease.generation, Generation(2));
    assert_eq!(info.lease.recoveries, 1);
    let again = h
        .pool
        .attach(OWNER, lease.session_id, &token)
        .await
        .unwrap();
    assert_eq!(again.outcome, RecoveryOutcome::ResumedSameProcess);
    assert_eq!(again.lease.generation, Generation(2));
    assert_eq!(h.rt.launch_count(), 2);
    assert_eq!(h.pool.metrics().await.recoveries["fresh_process"], 1);
}

#[tokio::test]
async fn wrong_token_is_forbidden() {
    let h = harness(test_cfg());
    let (lease, _token) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    let wrong = LeaseToken::generate();
    assert!(matches!(
        h.pool.attach(OWNER, lease.session_id, &wrong).await,
        Err(Error::Forbidden(_))
    ));
    assert!(matches!(
        h.pool
            .renew(OWNER, lease.session_id, &wrong, Generation(1), None)
            .await,
        Err(Error::Forbidden(_))
    ));
    assert!(matches!(
        h.pool
            .release(OWNER, lease.session_id, Some(&wrong), None)
            .await,
        Err(Error::Forbidden(_))
    ));
}

#[tokio::test]
async fn renew_extends_but_never_past_max_lifetime() {
    let h = harness(test_cfg());
    let s = SessionSpec {
        ttl_secs: Some(60),
        max_lifetime_secs: Some(100),
        ..SessionSpec::default()
    };
    let (lease, token) = h.pool.create(OWNER, s).await.unwrap();
    h.clock.advance(time::Duration::seconds(50));
    let renewed = h
        .pool
        .renew(
            OWNER,
            lease.session_id,
            &token,
            Generation(1),
            Some(Duration::from_secs(3600)),
        )
        .await
        .unwrap();
    assert_eq!(renewed.expires_at, renewed.max_expires_at);
    assert!(matches!(
        h.pool
            .renew(
                OWNER,
                lease.session_id,
                &token,
                Generation(1),
                Some(Duration::from_secs(10_000_000))
            )
            .await,
        Err(Error::InvalidRequest(_))
    ));
    assert!(matches!(
        h.pool
            .renew(OWNER, lease.session_id, &token, Generation(9), None)
            .await,
        Err(Error::StaleGeneration { .. })
    ));
}

#[tokio::test]
async fn handoff_fences_old_token_and_generation() {
    let h = harness(test_cfg());
    let (lease, token) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    let id = lease.session_id;
    let (handed, fresh) = h
        .pool
        .handoff(OWNER, id, &token, Generation(1))
        .await
        .unwrap();
    assert_eq!(handed.generation, Generation(2));
    assert_ne!(fresh.digest(), token.digest());
    assert!(matches!(
        h.pool.attach(OWNER, id, &token).await,
        Err(Error::Forbidden(_))
    ));
    assert!(matches!(
        h.pool.handoff(OWNER, id, &token, Generation(1)).await,
        Err(Error::Forbidden(_))
    ));
    assert!(matches!(
        h.pool.handoff(OWNER, id, &fresh, Generation(1)).await,
        Err(Error::StaleGeneration { .. })
    ));
    assert!(!h.pool.relay_valid(id, Generation(1)).await);
    assert!(h.pool.relay_valid(id, Generation(2)).await);
    h.pool.attach(OWNER, id, &fresh).await.unwrap();
}

#[tokio::test]
async fn concurrent_handoffs_have_one_winner() {
    let h = harness(test_cfg());
    let (lease, token) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let pool = h.pool.clone();
        let token = token.clone();
        tasks.push(tokio::spawn(async move {
            pool.handoff(OWNER, lease.session_id, &token, Generation(1))
                .await
        }));
    }
    let mut ok = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => ok += 1,
            Err(Error::Forbidden(_) | Error::StaleGeneration { .. }) => {}
            Err(e) => panic!("unexpected {e}"),
        }
    }
    assert_eq!(ok, 1);
    assert_eq!(
        h.pool
            .get(OWNER, lease.session_id)
            .await
            .unwrap()
            .generation,
        Generation(2)
    );
}

#[tokio::test]
async fn recovery_ephemeral_is_fresh_and_loses_cookies() {
    let h = harness(test_cfg());
    let (lease, token) = h
        .pool
        .create(OWNER, spec(PersistenceMode::Ephemeral))
        .await
        .unwrap();
    h.rt.last().unwrap().set_cookie(None, "sid", "1");
    h.rt.last().unwrap().kill();
    let info = h
        .pool
        .attach(OWNER, lease.session_id, &token)
        .await
        .unwrap();
    assert_eq!(info.outcome, RecoveryOutcome::FreshProcess);
    assert!(h.rt.last().unwrap().cookie_names(None).is_empty());
}

#[tokio::test]
async fn recovery_profile_reuses_directory() {
    let h = harness(test_cfg());
    let (lease, token) = h
        .pool
        .create(OWNER, spec(PersistenceMode::Profile))
        .await
        .unwrap();
    let profile = lease.profile_id.unwrap();
    h.rt.last().unwrap().set_cookie(None, "sid", "1");
    h.rt.last().unwrap().kill();
    let info = h
        .pool
        .attach(OWNER, lease.session_id, &token)
        .await
        .unwrap();
    assert_eq!(info.outcome, RecoveryOutcome::RestoredFromProfile);
    assert_eq!(
        h.rt.last().unwrap().cookie_names(None),
        vec!["sid".to_owned()]
    );
    assert_eq!(
        h.pool.metrics().await.recoveries["restored_from_profile"],
        1
    );
    // The same profile cannot be opened by a second session while this one lives.
    let again = SessionSpec {
        profile_id: Some(profile),
        ..spec(PersistenceMode::Profile)
    };
    assert!(matches!(
        h.pool.create(OWNER, again.clone()).await,
        Err(Error::Conflict(_))
    ));
    h.pool
        .release(OWNER, lease.session_id, Some(&token), None)
        .await
        .unwrap();
    let (second, _) = h.pool.create(OWNER, again).await.unwrap();
    assert_eq!(
        second.last_recovery,
        Some(RecoveryOutcome::RestoredFromProfile)
    );
    // Someone else's profile id looks like a missing one.
    let foreign = SessionSpec {
        profile_id: Some(profile),
        ..spec(PersistenceMode::Profile)
    };
    assert!(matches!(
        h.pool.create("mallory", foreign).await,
        Err(Error::NotFound(_))
    ));
}

#[tokio::test]
async fn recovery_snapshot_replays_cookies() {
    let h = harness(test_cfg());
    let (lease, token) = h
        .pool
        .create(OWNER, spec(PersistenceMode::Snapshot))
        .await
        .unwrap();
    h.rt.last().unwrap().set_cookie(None, "sid", "abc");
    let meta = h
        .pool
        .snapshot_now(OWNER, lease.session_id, &token)
        .await
        .unwrap();
    assert_eq!(meta.version, 1);
    assert_eq!(meta.generation, Generation(1));
    h.rt.last().unwrap().kill();
    let info = h
        .pool
        .attach(OWNER, lease.session_id, &token)
        .await
        .unwrap();
    assert_eq!(info.outcome, RecoveryOutcome::RestoredFromSnapshot);
    assert_eq!(info.lease.generation, Generation(2));
    assert_eq!(
        h.rt.last().unwrap().cookie_names(None),
        vec!["sid".to_owned()]
    );
    // The stored bytes are sealed: no plaintext cookie value inside.
    let stored = h
        .snaps
        .latest(lease.profile_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(!String::from_utf8_lossy(&stored.sealed).contains("abc"));
    assert_eq!(h.sealer.open(&stored).unwrap().cookies.len(), 1);
    assert_eq!(
        h.pool.metrics().await.recoveries["restored_from_snapshot"],
        1
    );
}

#[tokio::test]
async fn snapshot_now_needs_snapshot_persistence_and_prunes() {
    let mut cfg = test_cfg();
    cfg.snapshot_keep = 2;
    let h = harness(cfg);
    let (plain, plain_token) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    assert!(matches!(
        h.pool
            .snapshot_now(OWNER, plain.session_id, &plain_token)
            .await,
        Err(Error::Conflict(_))
    ));
    let (lease, token) = h
        .pool
        .create(OWNER, spec(PersistenceMode::Snapshot))
        .await
        .unwrap();
    for expected in 1..=4 {
        let meta = h
            .pool
            .snapshot_now(OWNER, lease.session_id, &token)
            .await
            .unwrap();
        assert_eq!(meta.version, expected);
    }
    let listed = h
        .pool
        .list_profile_snapshots(OWNER, lease.profile_id.unwrap())
        .await
        .unwrap();
    assert_eq!(
        listed.iter().map(|m| m.version).collect::<Vec<_>>(),
        vec![4, 3]
    );
    assert_eq!(
        h.pool
            .get(OWNER, lease.session_id)
            .await
            .unwrap()
            .snapshot_version,
        Some(4)
    );
    assert!(matches!(
        h.pool
            .list_profile_snapshots("mallory", lease.profile_id.unwrap())
            .await,
        Err(Error::NotFound(_))
    ));
}

#[tokio::test]
async fn recovery_none_marks_session_lost() {
    let h = harness(test_cfg());
    let s = SessionSpec {
        recovery: RecoveryPolicy::None,
        ..SessionSpec::default()
    };
    let (lease, token) = h.pool.create(OWNER, s).await.unwrap();
    h.rt.last().unwrap().kill();
    let err = h
        .pool
        .attach(OWNER, lease.session_id, &token)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Conflict(_)), "{err}");
    let stored = h.pool.get(OWNER, lease.session_id).await.unwrap();
    assert_eq!(stored.status, SessionStatus::Lost);
    assert_eq!(h.rt.launch_count(), 1);
    assert_eq!(h.pool.metrics().await.recoveries["lost"], 1);
    // The owner's quota slot is returned.
    assert_eq!(h.pool.metrics().await.sessions["lost"], 1);
}

#[tokio::test]
async fn recovery_gives_up_after_attempts() {
    let h = harness(test_cfg());
    let (lease, token) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    h.rt.fail_next_launches(100);
    h.rt.last().unwrap().kill();
    let err = h
        .pool
        .attach(OWNER, lease.session_id, &token)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Conflict(_)), "{err}");
    assert_eq!(
        h.pool.get(OWNER, lease.session_id).await.unwrap().status,
        SessionStatus::Lost
    );
}

#[tokio::test]
async fn recovery_succeeds_after_transient_launch_failure() {
    let h = harness(test_cfg());
    let (lease, token) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    h.rt.fail_next_launches(2);
    h.rt.last().unwrap().kill();
    let info = h
        .pool
        .attach(OWNER, lease.session_id, &token)
        .await
        .unwrap();
    assert_eq!(info.lease.generation, Generation(2));
}

#[tokio::test]
async fn health_monitor_recovers_crashed_and_unresponsive_browsers() {
    let h = harness(test_cfg());
    let (crashed, _t1) = h.pool.create("a", SessionSpec::default()).await.unwrap();
    let crashed_browser = h.rt.last().unwrap();
    let (hung, _t2) = h.pool.create("b", SessionSpec::default()).await.unwrap();
    let hung_browser = h.rt.last().unwrap();
    crashed_browser.kill();
    hung_browser.set_unresponsive(true);

    h.pool.run_maintenance().await;
    assert_eq!(
        h.pool
            .get("a", crashed.session_id)
            .await
            .unwrap()
            .generation,
        Generation(2)
    );
    // Two strikes so far for the hung one: still the original browser.
    assert_eq!(
        h.pool.get("b", hung.session_id).await.unwrap().generation,
        Generation(1)
    );
    h.pool.run_maintenance().await;
    assert_eq!(
        h.pool.get("b", hung.session_id).await.unwrap().generation,
        Generation(1)
    );
    h.pool.run_maintenance().await;
    let recovered = h.pool.get("b", hung.session_id).await.unwrap();
    assert_eq!(recovered.generation, Generation(2));
    assert_eq!(recovered.recoveries, 1);
    assert!(
        !hung_browser.is_alive(),
        "unresponsive browser must be killed before replacement"
    );
}

#[tokio::test]
async fn expired_leases_are_reaped() {
    let h = harness(test_cfg());
    let s = SessionSpec {
        ttl_secs: Some(60),
        ..SessionSpec::default()
    };
    let (lease, token) = h.pool.create(OWNER, s).await.unwrap();
    let browser = h.rt.last().unwrap();
    h.clock.advance(time::Duration::seconds(30));
    h.pool.run_maintenance().await;
    assert_eq!(
        h.pool.get(OWNER, lease.session_id).await.unwrap().status,
        SessionStatus::Idle
    );
    h.pool
        .renew(
            OWNER,
            lease.session_id,
            &token,
            Generation(1),
            Some(Duration::from_secs(60)),
        )
        .await
        .unwrap();
    h.clock.advance(time::Duration::seconds(61));
    h.pool.run_maintenance().await;
    let closed = h.pool.get(OWNER, lease.session_id).await.unwrap();
    assert_eq!(closed.status, SessionStatus::Closed);
    assert_eq!(closed.reason.as_deref(), Some("lease expired"));
    assert!(!browser.is_alive());
}

#[tokio::test]
async fn idle_sessions_are_released_but_attached_ones_are_not() {
    let h = harness(test_cfg());
    let s = SessionSpec {
        idle_timeout_secs: Some(30),
        ttl_secs: Some(3600),
        ..SessionSpec::default()
    };
    let (idle, _t1) = h.pool.create(OWNER, s.clone()).await.unwrap();
    let (held, t2) = h.pool.create("other", s).await.unwrap();
    let (_info, access) = h.pool.open_relay(held.session_id, &t2).await.unwrap();
    assert_eq!(h.pool.metrics().await.relay_connections, 1);
    h.clock.advance(time::Duration::seconds(31));
    h.pool.run_maintenance().await;
    assert_eq!(
        h.pool.get(OWNER, idle.session_id).await.unwrap().status,
        SessionStatus::Closed
    );
    assert_eq!(
        h.pool
            .get(OWNER, idle.session_id)
            .await
            .unwrap()
            .reason
            .as_deref(),
        Some("idle timeout")
    );
    assert_eq!(
        h.pool.get("other", held.session_id).await.unwrap().status,
        SessionStatus::Active
    );
    // Closing the relay makes the session idle again.
    drop(access);
    eventually("session idle after relay closes", || async {
        h.pool.get("other", held.session_id).await.unwrap().status == SessionStatus::Idle
    })
    .await;
    assert_eq!(h.pool.metrics().await.relay_connections, 0);
}

#[tokio::test]
async fn startup_reconciliation_recovers_orphans() {
    let h = harness(test_cfg());
    let (ephemeral, _t1) = h
        .pool
        .create("a", spec(PersistenceMode::Ephemeral))
        .await
        .unwrap();
    let (snapshot, t2) = h
        .pool
        .create("a", spec(PersistenceMode::Snapshot))
        .await
        .unwrap();
    let (profile, _t3) = h
        .pool
        .create("a", spec(PersistenceMode::Profile))
        .await
        .unwrap();
    let lossy = SessionSpec {
        recovery: RecoveryPolicy::None,
        ..SessionSpec::default()
    };
    let (none, _t4) = h.pool.create("a", lossy).await.unwrap();
    let expiring = SessionSpec {
        ttl_secs: Some(10),
        ..SessionSpec::default()
    };
    let (expired, _t5) = h.pool.create("a", expiring).await.unwrap();
    for b in h.rt.browsers() {
        if b.request.user_data_dir.is_some() {
            b.set_cookie(None, "sid", "p");
        }
    }
    h.rt.browsers()[1].set_cookie(None, "sid", "s");
    h.pool
        .snapshot_now("a", snapshot.session_id, &t2)
        .await
        .unwrap();
    // Simulate a worker crash: the process (and every browser) disappears.
    drop(h.pool);
    let rt2 = FakeRuntime::new();
    h.clock.advance(time::Duration::seconds(11));
    let pool2 = build_pool(
        test_cfg(),
        &rt2,
        &h.leases,
        &h.snaps,
        &h.sealer,
        &h.clock,
        &h.dir,
    );
    pool2.start().await.unwrap();
    eventually("orphans recovered", || async {
        let all = pool2.list("a", None).await.unwrap();
        all.iter()
            .filter(|l| l.status == SessionStatus::Idle)
            .count()
            == 3
    })
    .await;
    let get = |id: SessionId| {
        let pool2 = pool2.clone();
        async move { pool2.get("a", id).await.unwrap() }
    };
    let e = get(ephemeral.session_id).await;
    assert_eq!(
        (e.status, e.last_recovery),
        (SessionStatus::Idle, Some(RecoveryOutcome::FreshProcess))
    );
    assert_eq!(e.generation, Generation(2));
    let s = get(snapshot.session_id).await;
    assert_eq!(s.last_recovery, Some(RecoveryOutcome::RestoredFromSnapshot));
    let p = get(profile.session_id).await;
    assert_eq!(p.last_recovery, Some(RecoveryOutcome::RestoredFromProfile));
    assert_eq!(get(none.session_id).await.status, SessionStatus::Lost);
    assert_eq!(get(expired.session_id).await.status, SessionStatus::Closed);
    assert_eq!(rt2.launch_count(), 3);
    pool2.shutdown().await;
}

#[tokio::test]
async fn shared_sessions_fill_contexts_then_open_a_new_browser() {
    let mut cfg = test_cfg();
    cfg.max_contexts_per_browser = 2;
    let h = harness(cfg);
    let (a, ta) = h.pool.create(OWNER, shared()).await.unwrap();
    let (b, tb) = h.pool.create("o2", shared()).await.unwrap();
    assert_eq!(h.rt.launch_count(), 1);
    assert_eq!(a.browser_id, b.browser_id);
    assert_ne!(a.context_id, b.context_id);
    assert!(a.context_id.is_some());
    let (c, tc) = h.pool.create("o3", shared()).await.unwrap();
    assert_eq!(h.rt.launch_count(), 2);
    assert_ne!(c.browser_id, a.browser_id);
    assert_eq!(h.pool.metrics().await.browsers["shared_browser"], 2);

    // Releasing one context keeps a still-used browser; releasing both retires it.
    let first = h.rt.browsers()[0].clone();
    h.pool
        .release(OWNER, a.session_id, Some(&ta), None)
        .await
        .unwrap();
    assert!(first.is_alive());
    assert_eq!(first.context_count(), 1);
    h.pool
        .release("o2", b.session_id, Some(&tb), None)
        .await
        .unwrap();
    assert!(
        !first.is_alive(),
        "empty shared browser retires when no warm pool is configured"
    );
    h.pool
        .release("o3", c.session_id, Some(&tc), None)
        .await
        .unwrap();
    assert_eq!(h.pool.metrics().await.browsers["shared_browser"], 0);
}

#[tokio::test]
async fn shared_browser_retires_after_serving_its_quota() {
    let mut cfg = test_cfg();
    cfg.max_contexts_per_browser = 4;
    cfg.browser_max_contexts_served = 2;
    cfg.warm_shared_browsers = 1;
    let h = harness(cfg);
    let (a, ta) = h.pool.create(OWNER, shared()).await.unwrap();
    let (b, tb) = h.pool.create("o2", shared()).await.unwrap();
    // The first browser has served its two contexts; a third goes to a new browser.
    let (c, tc) = h.pool.create("o3", shared()).await.unwrap();
    assert_eq!(h.rt.launch_count(), 2);
    let first = h.rt.browsers()[0].clone();
    h.pool
        .release(OWNER, a.session_id, Some(&ta), None)
        .await
        .unwrap();
    h.pool
        .release("o2", b.session_id, Some(&tb), None)
        .await
        .unwrap();
    assert!(
        !first.is_alive(),
        "exhausted browser retires even when warm slots are free"
    );
    h.pool
        .release("o3", c.session_id, Some(&tc), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn warm_pool_prestarts_and_serves_shared_sessions() {
    let mut cfg = test_cfg();
    cfg.warm_shared_browsers = 1;
    let h = harness(cfg);
    h.pool.run_maintenance().await;
    assert_eq!(h.rt.launch_count(), 1);
    h.pool.run_maintenance().await;
    assert_eq!(h.rt.launch_count(), 1, "warm target is already met");
    let (lease, token) = h.pool.create(OWNER, shared()).await.unwrap();
    assert_eq!(
        h.rt.launch_count(),
        1,
        "session was served by the warm browser"
    );
    h.pool
        .release(OWNER, lease.session_id, Some(&token), None)
        .await
        .unwrap();
    assert!(h.rt.browsers()[0].is_alive(), "warm browser stays");
    h.pool.shutdown().await;
    assert!(!h.rt.browsers()[0].is_alive());
}

#[tokio::test]
async fn shared_capacity_is_released_for_dedicated_demand() {
    let mut cfg = test_cfg();
    cfg.max_browsers = 1;
    cfg.warm_shared_browsers = 1;
    let h = harness(cfg);
    h.pool.run_maintenance().await;
    // The only slot is held by an idle warm browser; dedicated demand evicts it.
    let (lease, token) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    assert_eq!(h.rt.launch_count(), 2);
    h.pool
        .release(OWNER, lease.session_id, Some(&token), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn release_takes_a_final_snapshot() {
    let h = harness(test_cfg());
    let (lease, token) = h
        .pool
        .create(OWNER, spec(PersistenceMode::Snapshot))
        .await
        .unwrap();
    h.rt.last().unwrap().set_cookie(None, "sid", "final");
    h.pool
        .release(OWNER, lease.session_id, Some(&token), Some(Generation(1)))
        .await
        .unwrap();
    let listed = h.snaps.list(lease.profile_id.unwrap()).await.unwrap();
    assert_eq!(listed.len(), 1);
    // A new session for the same profile restores it.
    let again = SessionSpec {
        profile_id: lease.profile_id,
        ..spec(PersistenceMode::Snapshot)
    };
    let (second, _t) = h.pool.create(OWNER, again).await.unwrap();
    assert_eq!(
        second.last_recovery,
        Some(RecoveryOutcome::RestoredFromSnapshot)
    );
    assert_eq!(
        h.rt.last().unwrap().cookie_names(None),
        vec!["sid".to_owned()]
    );
}

#[tokio::test]
async fn periodic_snapshots_follow_the_interval() {
    let mut cfg = test_cfg();
    cfg.snapshot_interval = Duration::from_secs(60);
    let h = harness(cfg);
    let (lease, _token) = h
        .pool
        .create(OWNER, spec(PersistenceMode::Snapshot))
        .await
        .unwrap();
    h.pool.run_maintenance().await;
    assert!(
        h.snaps
            .list(lease.profile_id.unwrap())
            .await
            .unwrap()
            .is_empty()
    );
    h.clock.advance(time::Duration::seconds(61));
    h.pool.run_maintenance().await;
    assert_eq!(
        h.snaps.list(lease.profile_id.unwrap()).await.unwrap().len(),
        1
    );
    h.pool.run_maintenance().await;
    assert_eq!(
        h.snaps.list(lease.profile_id.unwrap()).await.unwrap().len(),
        1
    );
    assert_eq!(h.pool.metrics().await.snapshots["ok"], 1);
}

#[tokio::test]
async fn shutdown_snapshots_stops_browsers_and_refuses_new_work() {
    let h = harness(test_cfg());
    let (lease, _token) = h
        .pool
        .create(OWNER, spec(PersistenceMode::Snapshot))
        .await
        .unwrap();
    let (plain, _t2) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    h.pool.shutdown().await;
    assert!(h.rt.alive().is_empty());
    assert_eq!(
        h.snaps.list(lease.profile_id.unwrap()).await.unwrap().len(),
        1
    );
    // Leases stay non-terminal so a restarted worker recovers them.
    assert_eq!(
        h.pool.get(OWNER, plain.session_id).await.unwrap().status,
        SessionStatus::Idle
    );
    assert!(matches!(
        h.pool.create(OWNER, SessionSpec::default()).await,
        Err(Error::ShuttingDown)
    ));
    assert!(h.pool.is_draining());
}

#[tokio::test]
async fn delete_profile_erases_snapshots_and_checks_ownership() {
    let h = harness(test_cfg());
    let (lease, token) = h
        .pool
        .create(OWNER, spec(PersistenceMode::Snapshot))
        .await
        .unwrap();
    let profile = lease.profile_id.unwrap();
    h.pool
        .snapshot_now(OWNER, lease.session_id, &token)
        .await
        .unwrap();
    assert!(matches!(
        h.pool.delete_profile(OWNER, profile).await,
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        h.pool.delete_profile("mallory", profile).await,
        Err(Error::NotFound(_))
    ));
    h.pool
        .release(OWNER, lease.session_id, Some(&token), None)
        .await
        .unwrap();
    assert_eq!(h.pool.delete_profile(OWNER, profile).await.unwrap(), 2);
    assert!(h.snaps.list(profile).await.unwrap().is_empty());
    assert!(matches!(
        h.pool.delete_profile(OWNER, profile).await,
        Err(Error::NotFound(_))
    ));
}

#[tokio::test]
async fn failed_launch_does_not_leak_capacity_or_quota() {
    let mut cfg = test_cfg();
    cfg.max_browsers = 1;
    cfg.default_owner_quota = 1;
    let h = harness(cfg);
    h.rt.fail_next_launches(1);
    assert!(matches!(
        h.pool.create(OWNER, SessionSpec::default()).await,
        Err(Error::Browser(_))
    ));
    let (lease, token) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    assert_eq!(h.pool.metrics().await.admissions["failed"], 1);
    h.pool
        .release(OWNER, lease.session_id, Some(&token), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn metrics_snapshot_counts_sessions_and_launches() {
    let h = harness(test_cfg());
    let (lease, token) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    let m = h.pool.metrics().await;
    assert_eq!(m.sessions["idle"], 1);
    assert_eq!(m.browsers["dedicated_browser"], 1);
    assert_eq!(m.admissions["accepted"], 1);
    assert_eq!(m.launch_seconds.count, 1);
    h.pool
        .release(OWNER, lease.session_id, Some(&token), None)
        .await
        .unwrap();
    assert_eq!(h.pool.metrics().await.sessions["closed"], 1);
}

#[tokio::test]
async fn persona_seed_follows_the_profile_and_survives_recovery() {
    let h = harness(test_cfg());
    let (lease, token) = h
        .pool
        .create(OWNER, spec(PersistenceMode::Snapshot))
        .await
        .unwrap();
    let profile = lease.profile_id.unwrap();
    let first = h.rt.last().unwrap().request.persona_seed.clone();
    assert_eq!(first, browserx_core::persona_seed(&profile.0));
    h.rt.last().unwrap().kill();
    h.pool
        .attach(OWNER, lease.session_id, &token)
        .await
        .unwrap();
    assert_eq!(h.rt.last().unwrap().request.persona_seed, first);
    let (plain, _t) = h.pool.create(OWNER, SessionSpec::default()).await.unwrap();
    assert_eq!(
        h.rt.last().unwrap().request.persona_seed,
        browserx_core::persona_seed(&plain.session_id.0)
    );
}
