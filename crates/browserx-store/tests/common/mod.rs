//! Conformance suites shared by every store implementation.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod services;

use std::sync::Arc;

use browserx_core::Clock;
use browserx_core::clock::ManualClock;
use browserx_core::snapshot::{CookieRecord, OriginStorage, STATE_FORMAT_VERSION};
use browserx_core::{
    BrowserId, Error, Generation, LeaseStore, ProfileId, ProxyRoute, RecoveryOutcome, Secret,
    SessionId, SessionLease, SessionSpec, SessionStatus, Snapshot, SnapshotMeta, SnapshotStore,
    StateSnapshot, WorkerId,
};
use browserx_store::{Sealer, Zeroizing};
use time::{Duration, OffsetDateTime};

pub fn epoch() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::days(20_000)
}

pub fn lease(owner: &str, status: SessionStatus, created_at: OffsetDateTime) -> SessionLease {
    SessionLease {
        session_id: SessionId::new(),
        owner: owner.to_owned(),
        spec: SessionSpec::default(),
        status,
        generation: Generation(1),
        worker_id: None,
        browser_id: None,
        context_id: None,
        profile_id: None,
        snapshot_version: None,
        token_digest: None,
        last_recovery: None,
        recoveries: 0,
        created_at,
        expires_at: created_at + Duration::minutes(10),
        max_expires_at: created_at + Duration::hours(1),
        last_heartbeat_at: None,
        last_attach_at: None,
        reason: None,
    }
}

/// Runs the lease-registry contract. `clock` must be the clock the store was built with.
pub async fn lease_store_conformance(store: Arc<dyn LeaseStore>, clock: Arc<ManualClock>) {
    let t0 = clock.now();

    // insert / get / duplicate
    let mut a = lease("alice", SessionStatus::Idle, t0);
    assert!(store.get(a.session_id).await.unwrap().is_none());
    store.insert(&a).await.unwrap();
    assert_eq!(store.get(a.session_id).await.unwrap().as_ref(), Some(&a));
    assert!(matches!(store.insert(&a).await, Err(Error::Conflict(_))));

    // a lease with every optional field survives a round trip
    let mut full = lease("alice", SessionStatus::Active, t0 + Duration::seconds(1));
    full.spec.proxy = Some(ProxyRoute {
        url: "socks5://proxy.invalid:1080".into(),
        username: Some("user-{session}".into()),
        password: Some(Secret::new("synthetic-password")),
    });
    full.worker_id = Some(WorkerId::new());
    full.browser_id = Some(BrowserId::new());
    full.profile_id = Some(ProfileId::new());
    full.snapshot_version = Some(4);
    full.token_digest = Some("ab".repeat(32));
    full.last_recovery = Some(RecoveryOutcome::RestoredFromSnapshot);
    full.recoveries = 2;
    full.last_heartbeat_at = Some(t0 + Duration::seconds(5));
    full.last_attach_at = Some(t0 + Duration::seconds(6));
    full.reason = Some("because".into());
    store.insert(&full).await.unwrap();
    assert_eq!(
        store.get(full.session_id).await.unwrap().as_ref(),
        Some(&full)
    );

    // CAS: same generation succeeds, advancing succeeds, stale fails, jumps fail
    a.status = SessionStatus::Active;
    store.compare_and_swap(Generation(1), &a).await.unwrap();
    a.generation = Generation(2);
    a.recoveries = 1;
    store.compare_and_swap(Generation(1), &a).await.unwrap();
    assert_eq!(
        store.get(a.session_id).await.unwrap().unwrap().generation,
        Generation(2)
    );

    let mut stale = a.clone();
    stale.generation = Generation(2);
    stale.reason = Some("stale writer".into());
    match store.compare_and_swap(Generation(1), &stale).await {
        Err(Error::StaleGeneration { expected, found }) => {
            assert_eq!(expected, Generation(1));
            assert_eq!(found, Generation(2));
        }
        other => panic!("expected StaleGeneration, got {other:?}"),
    }
    assert_eq!(store.get(a.session_id).await.unwrap().unwrap().reason, None);

    let mut jump = a.clone();
    jump.generation = Generation(4);
    assert!(matches!(
        store.compare_and_swap(Generation(2), &jump).await,
        Err(Error::InvalidRequest(_))
    ));
    let ghost = lease("alice", SessionStatus::Idle, t0);
    assert!(matches!(
        store.compare_and_swap(Generation(1), &ghost).await,
        Err(Error::NotFound(_))
    ));

    // racing writers: exactly one wins
    let race = lease("racer", SessionStatus::Idle, t0 + Duration::seconds(2));
    store.insert(&race).await.unwrap();
    let mut tasks = Vec::new();
    for i in 0..16u32 {
        let store = Arc::clone(&store);
        let mut next = race.clone();
        next.generation = Generation(2);
        next.recoveries = i;
        tasks.push(tokio::spawn(async move {
            store.compare_and_swap(Generation(1), &next).await
        }));
    }
    let mut wins = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(()) => wins += 1,
            Err(Error::StaleGeneration { .. }) => {}
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }
    assert_eq!(wins, 1);

    // list filters
    let b = lease("bob", SessionStatus::Idle, t0 + Duration::seconds(3));
    let c = lease("bob", SessionStatus::Draining, t0 + Duration::seconds(4));
    store.insert(&b).await.unwrap();
    store.insert(&c).await.unwrap();
    let all = store.list(None, None).await.unwrap();
    assert_eq!(all.len(), 5);
    assert!(all.windows(2).all(|w| w[0].created_at <= w[1].created_at));
    let bobs = store.list(Some("bob"), None).await.unwrap();
    assert_eq!(
        bobs.iter().map(|l| l.session_id).collect::<Vec<_>>(),
        vec![b.session_id, c.session_id]
    );
    let idle = store
        .list(None, Some(&[SessionStatus::Idle]))
        .await
        .unwrap();
    assert!(idle.iter().all(|l| l.status == SessionStatus::Idle));
    assert!(idle.iter().any(|l| l.session_id == b.session_id));
    let bob_draining = store
        .list(
            Some("bob"),
            Some(&[SessionStatus::Draining, SessionStatus::Lost]),
        )
        .await
        .unwrap();
    assert_eq!(bob_draining.len(), 1);
    assert_eq!(bob_draining[0].session_id, c.session_id);
    assert!(store.list(None, Some(&[])).await.unwrap().is_empty());
    assert!(store.list(Some("nobody"), None).await.unwrap().is_empty());

    // purge: only terminal leases last written before the cutoff
    let mut old = lease("purge", SessionStatus::Draining, t0);
    store.insert(&old).await.unwrap();
    old.generation = Generation(2);
    old.status = SessionStatus::Closed;
    store.compare_and_swap(Generation(1), &old).await.unwrap();
    let old_live = lease("purge", SessionStatus::Idle, t0);
    store.insert(&old_live).await.unwrap();

    clock.advance(Duration::hours(2));
    let mut recent = lease("purge", SessionStatus::Idle, clock.now());
    store.insert(&recent).await.unwrap();
    recent.generation = Generation(2);
    recent.status = SessionStatus::Lost;
    store
        .compare_and_swap(Generation(1), &recent)
        .await
        .unwrap();

    let cutoff = t0 + Duration::hours(1);
    assert_eq!(store.purge_terminal(cutoff).await.unwrap(), 1);
    assert!(store.get(old.session_id).await.unwrap().is_none());
    assert!(store.get(old_live.session_id).await.unwrap().is_some());
    assert!(store.get(recent.session_id).await.unwrap().is_some());
    assert_eq!(store.purge_terminal(cutoff).await.unwrap(), 0);
    assert_eq!(
        store
            .purge_terminal(clock.now() + Duration::hours(1))
            .await
            .unwrap(),
        1
    );
    assert!(store.get(recent.session_id).await.unwrap().is_none());

    // the upstream proxy password lives only as long as the lease can recover
    let now = clock.now();
    let mut proxied = lease("scrub", SessionStatus::Idle, now);
    proxied.spec.proxy = Some(ProxyRoute {
        url: "http://proxy.invalid:3128".into(),
        username: Some("user".into()),
        password: Some(Secret::new("synthetic-scrub-password")),
    });
    store.insert(&proxied).await.unwrap();
    let mut draining = proxied.clone();
    draining.status = SessionStatus::Draining;
    store
        .compare_and_swap(Generation(1), &draining)
        .await
        .unwrap();
    let kept = store.get(proxied.session_id).await.unwrap().unwrap();
    assert_eq!(
        kept.spec.proxy.as_ref().unwrap().password,
        Some(Secret::new("synthetic-scrub-password")),
        "a lease that can still recover keeps its password"
    );
    let mut closed = draining.clone();
    closed.status = SessionStatus::Closed;
    store
        .compare_and_swap(Generation(1), &closed)
        .await
        .unwrap();
    let terminal = store.get(proxied.session_id).await.unwrap().unwrap();
    let proxy = terminal.spec.proxy.as_ref().unwrap();
    assert_eq!(proxy.password, None, "terminal leases drop the password");
    assert_eq!(proxy.username.as_deref(), Some("user"));
    assert_eq!(proxy.url, "http://proxy.invalid:3128");

    // a lease inserted already terminal is scrubbed too
    let mut born_terminal = lease("scrub", SessionStatus::Closed, now);
    born_terminal.spec.proxy.clone_from(&proxied.spec.proxy);
    store.insert(&born_terminal).await.unwrap();
    let stored = store.get(born_terminal.session_id).await.unwrap().unwrap();
    assert_eq!(stored.spec.proxy.unwrap().password, None);
}

pub fn test_sealer() -> Sealer {
    Sealer::new("0badc0de".into(), &Zeroizing::new([42u8; 32]))
}

pub fn sample_state(tag: &str) -> StateSnapshot {
    StateSnapshot {
        format_version: STATE_FORMAT_VERSION,
        browser_version: "Chromium/0.0".into(),
        cookies: vec![CookieRecord {
            name: "sid".into(),
            value: format!("synthetic-{tag}"),
            domain: "example.test".into(),
            path: "/".into(),
            expires: Some(2_000_000_000.0),
            http_only: true,
            secure: true,
            same_site: Some("Lax".into()),
        }],
        origins: vec![OriginStorage {
            origin: "https://example.test".into(),
            local_storage: vec![("k".into(), tag.into())],
        }],
        open_urls: vec!["https://example.test/".into()],
    }
}

pub fn sealed_snapshot(sealer: &Sealer, profile: ProfileId, version: u64) -> Snapshot {
    let meta = SnapshotMeta {
        profile_id: profile,
        version,
        session_id: SessionId::new(),
        generation: Generation(1),
        created_at: epoch() + Duration::seconds(i64::try_from(version).unwrap()),
        size: 0,
        key_id: String::new(),
    };
    sealer
        .seal(meta, &sample_state(&format!("v{version}")))
        .unwrap()
}

/// Runs the snapshot-store contract.
pub async fn snapshot_store_conformance(store: Arc<dyn SnapshotStore>) {
    let sealer = test_sealer();
    let p1 = ProfileId::new();
    let p2 = ProfileId::new();

    assert!(store.latest(p1).await.unwrap().is_none());
    assert!(store.list(p1).await.unwrap().is_empty());
    assert_eq!(store.prune(p1, 3).await.unwrap(), 0);
    assert_eq!(store.delete_profile(p1).await.unwrap(), 0);

    // monotonic versions
    for v in 1..=3 {
        store.put(&sealed_snapshot(&sealer, p1, v)).await.unwrap();
    }
    assert!(matches!(
        store.put(&sealed_snapshot(&sealer, p1, 3)).await,
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        store.put(&sealed_snapshot(&sealer, p1, 2)).await,
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        store.put(&sealed_snapshot(&sealer, p1, 0)).await,
        Err(Error::InvalidRequest(_))
    ));
    let mut bad_size = sealed_snapshot(&sealer, p1, 4);
    bad_size.meta.size += 1;
    assert!(matches!(
        store.put(&bad_size).await,
        Err(Error::InvalidRequest(_))
    ));
    // gaps are allowed: only monotonic order is enforced
    store.put(&sealed_snapshot(&sealer, p1, 5)).await.unwrap();

    // latest returns exactly what was stored, and it still opens
    let latest = store.latest(p1).await.unwrap().unwrap();
    assert_eq!(latest.meta.version, 5);
    assert_eq!(sealer.open(&latest).unwrap(), sample_state("v5"));

    // list: newest first
    let versions: Vec<u64> = store
        .list(p1)
        .await
        .unwrap()
        .iter()
        .map(|m| m.version)
        .collect();
    assert_eq!(versions, vec![5, 3, 2, 1]);

    // profiles are independent
    assert!(store.latest(p2).await.unwrap().is_none());
    store.put(&sealed_snapshot(&sealer, p2, 1)).await.unwrap();

    // prune
    assert_eq!(store.prune(p1, 2).await.unwrap(), 2);
    let versions: Vec<u64> = store
        .list(p1)
        .await
        .unwrap()
        .iter()
        .map(|m| m.version)
        .collect();
    assert_eq!(versions, vec![5, 3]);
    assert_eq!(store.prune(p1, 2).await.unwrap(), 0);
    assert_eq!(store.prune(p1, 10).await.unwrap(), 0);
    assert_eq!(store.list(p2).await.unwrap().len(), 1);

    // delete
    assert_eq!(store.delete_profile(p1).await.unwrap(), 2);
    assert!(store.latest(p1).await.unwrap().is_none());
    assert!(store.list(p1).await.unwrap().is_empty());
    assert_eq!(store.list(p2).await.unwrap().len(), 1);
    assert_eq!(store.prune(p2, 0).await.unwrap(), 1);
    assert!(store.latest(p2).await.unwrap().is_none());
}
