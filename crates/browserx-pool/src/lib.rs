//! The BrowserX scheduler.
//!
//! [`Pool`] owns the browsers of one worker and the leases that govern them:
//!
//! * **Admission**: a bounded FIFO queue with a deadline and per-owner quotas.
//! * **Allocation**: a dedicated browser per session, or an isolated context in
//!   a shared, warm browser; persistence is restored as requested
//!   (`profile` reuses a locked directory, `snapshot` replays the latest sealed
//!   snapshot).
//! * **Leases**: every mutation is load, modify, compare-and-swap on the
//!   generation; renew, handoff and release are fenced by it.
//! * **Recovery**: a health monitor replaces lost browsers per the session's
//!   recovery policy and reports what survived through
//!   [`browserx_core::RecoveryOutcome`].
//! * **Background duties**: reaper (expiry, idle timeout, retention),
//!   snapshotter, warm pool, startup reconciliation, graceful shutdown.
//!
//! Browsers are started through [`browserx_core::BrowserRuntime`], so the
//! scheduler is independent of how browsers are launched.

mod alloc;
mod config;
mod event;
mod lifecycle;
mod metrics;
mod ops;
mod profiles;
mod recovery;
mod state;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use browserx_core::{
    BrowserRuntime, Clock, Generation, Isolation, LeaseStore, LeaseToken, ProfileId, Result,
    SessionId, SessionLease, SessionSpec, SessionStatus, SnapshotMeta, SnapshotStore, WorkerId,
};
use browserx_egress::EgressPolicy;
use browserx_store::Sealer;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub use config::PoolConfig;
pub use event::{PoolEvent, PoolEventKind};
pub use metrics::{HistogramSnapshot, LAUNCH_BUCKETS, MetricsSnapshot};
pub use ops::{AttachInfo, RelayAccess, RelayGuard, ct_eq};

use metrics::Metrics;
use ops::{AttachMode, OwnedCaller};
use state::{Inner, State};

const EVENT_BUFFER: usize = 1024;
/// Terminal-lease purging runs every this many maintenance ticks.
const PURGE_EVERY_TICKS: u64 = 30;

/// Handle to the scheduler. Cheap to clone.
#[derive(Clone)]
pub struct Pool {
    inner: Arc<Inner>,
}

impl Pool {
    /// Builds a pool. Nothing runs until [`Pool::start`] (operations work
    /// without it; background duties do not).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: PoolConfig,
        runtime: Arc<dyn BrowserRuntime>,
        leases: Arc<dyn LeaseStore>,
        snapshots: Arc<dyn SnapshotStore>,
        sealer: Arc<Sealer>,
        clock: Arc<dyn Clock>,
        egress_policy: EgressPolicy,
        profiles_root: PathBuf,
    ) -> Result<Self> {
        cfg.validate()?;
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        Ok(Self {
            inner: Arc::new(Inner {
                cfg,
                worker_id: WorkerId::new(),
                runtime,
                leases,
                snapshots,
                sealer,
                clock,
                egress_policy,
                profiles_root,
                state: std::sync::Mutex::new(State::default()),
                capacity: tokio::sync::Notify::new(),
                events,
                drain: CancellationToken::new(),
                shutdown: CancellationToken::new(),
                tracker: TaskTracker::new(),
                metrics: Arc::new(Metrics::default()),
            }),
        })
    }

    /// Recovers sessions orphaned by a previous process, then starts the health
    /// monitor, reaper, snapshotter and warm pool.
    pub async fn start(&self) -> Result<()> {
        self.inner.reconcile().await?;
        let inner = self.inner.clone();
        self.inner.tracker.spawn(async move {
            let mut tick = 0u64;
            loop {
                tokio::select! {
                    () = inner.shutdown.cancelled() => break,
                    () = tokio::time::sleep(inner.cfg.maintenance_interval) => {}
                }
                tick += 1;
                inner
                    .reap_tick(tick.is_multiple_of(PURGE_EVERY_TICKS))
                    .await;
                inner.snapshot_tick().await;
                inner.warm_tick().await;
            }
        });
        let inner = self.inner.clone();
        self.inner.tracker.spawn(async move {
            loop {
                tokio::select! {
                    () = inner.shutdown.cancelled() => break,
                    () = tokio::time::sleep(inner.cfg.probe_interval) => {}
                }
                inner.health_tick().await;
            }
        });
        Ok(())
    }

    /// Runs one pass of every background duty once. [`Pool::start`] does this on
    /// a timer; embedders and tests with a manual clock call it directly.
    pub async fn run_maintenance(&self) {
        self.inner.health_tick().await;
        self.inner.reap_tick(true).await;
        self.inner.snapshot_tick().await;
        self.inner.warm_tick().await;
    }

    /// Drains the pool: stops admission, takes final snapshots, stops every
    /// browser (confirmed) and returns. Leases stay non-terminal so a restarted
    /// worker recovers them.
    pub async fn shutdown(&self) {
        self.inner.shutdown_impl().await;
    }

    /// Stops admitting new sessions immediately (readiness turns false) without
    /// touching running ones. [`Pool::shutdown`] implies it.
    pub fn stop_admission(&self) {
        self.inner.drain.cancel();
    }

    /// Whether admission has stopped (shutdown has begun).
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.inner.drain.is_cancelled()
    }

    /// This process's worker identity.
    #[must_use]
    pub fn worker_id(&self) -> WorkerId {
        self.inner.worker_id
    }

    /// Names of the launch profiles the runtime offers.
    #[must_use]
    pub fn launch_profiles(&self) -> Vec<String> {
        self.inner.runtime.launch_profiles()
    }

    /// Subscribes to lifecycle events. Slow receivers lose the oldest events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<PoolEvent> {
        self.inner.events.subscribe()
    }

    /// Whether the lease store answers.
    pub async fn ping_store(&self) -> Result<()> {
        self.inner.leases.get(SessionId::new()).await.map(|_| ())
    }

    // ----- sessions ------------------------------------------------------

    /// Admits and allocates a session. Returns the lease (generation 1, status
    /// `idle`) and the controller token, which is shown only here.
    pub async fn create(
        &self,
        owner: &str,
        spec: SessionSpec,
    ) -> Result<(SessionLease, LeaseToken)> {
        self.inner.clone().create_impl(owner.to_owned(), spec).await
    }

    /// The owner's view of one session.
    pub async fn get(&self, owner: &str, id: SessionId) -> Result<SessionLease> {
        let lease = self.inner.load_lease(id).await?;
        if lease.owner == owner {
            Ok(lease)
        } else {
            Err(browserx_core::Error::NotFound(format!("session {id}")))
        }
    }

    /// The owner's sessions, optionally filtered by status.
    pub async fn list(
        &self,
        owner: &str,
        statuses: Option<&[SessionStatus]>,
    ) -> Result<Vec<SessionLease>> {
        self.inner.leases.list(Some(owner), statuses).await
    }

    /// Attaches a controller; recovers the browser first if it is gone.
    pub async fn attach(
        &self,
        owner: &str,
        id: SessionId,
        token: &LeaseToken,
    ) -> Result<AttachInfo> {
        self.inner
            .attach_core(Some(owner), id, token, AttachMode::Api)
            .await
            .map(|(info, _)| info)
    }

    /// Opens a relay connection authenticated by the session token alone (the
    /// token is the credential in the relay URL).
    pub async fn open_relay(
        &self,
        id: SessionId,
        token: &LeaseToken,
    ) -> Result<(AttachInfo, RelayAccess)> {
        let (info, access) = self
            .inner
            .attach_core(None, id, token, AttachMode::Relay)
            .await?;
        let access = access.ok_or_else(|| {
            browserx_core::Error::Internal("relay attach returned no access".into())
        })?;
        Ok((info, access))
    }

    /// Whether a relay bound to `generation` may keep running.
    pub async fn relay_valid(&self, id: SessionId, generation: Generation) -> bool {
        matches!(
            self.inner.leases.get(id).await,
            Ok(Some(l)) if l.generation == generation && l.status.is_attachable()
        )
    }

    /// Extends the lease; `ttl = None` repeats the session's TTL.
    pub async fn renew(
        &self,
        owner: &str,
        id: SessionId,
        token: &LeaseToken,
        expected: Generation,
        ttl: Option<Duration>,
    ) -> Result<SessionLease> {
        self.inner
            .clone()
            .renew_impl(owner.to_owned(), id, token.clone(), expected, ttl)
            .await
    }

    /// Moves control to a new token and generation; the old token stops working.
    pub async fn handoff(
        &self,
        owner: &str,
        id: SessionId,
        token: &LeaseToken,
        expected: Generation,
    ) -> Result<(SessionLease, LeaseToken)> {
        self.inner
            .clone()
            .handoff_impl(owner.to_owned(), id, token.clone(), expected)
            .await
    }

    /// Takes a snapshot now (`snapshot` persistence only).
    pub async fn snapshot_now(
        &self,
        owner: &str,
        id: SessionId,
        token: &LeaseToken,
    ) -> Result<SnapshotMeta> {
        self.inner
            .clone()
            .snapshot_impl(owner.to_owned(), id, token.clone())
            .await
    }

    /// Releases a session. The owner may omit the token; a given generation is
    /// fenced. Idempotent for sessions that already ended.
    pub async fn release(
        &self,
        owner: &str,
        id: SessionId,
        token: Option<&LeaseToken>,
        expected: Option<Generation>,
    ) -> Result<SessionLease> {
        self.inner
            .clone()
            .release_impl(
                OwnedCaller::Owner(owner.to_owned()),
                id,
                token.cloned(),
                expected,
                "released by owner",
            )
            .await
    }

    // ----- profiles ------------------------------------------------------

    /// Snapshot metadata of a profile the owner created.
    pub async fn list_profile_snapshots(
        &self,
        owner: &str,
        profile: ProfileId,
    ) -> Result<Vec<SnapshotMeta>> {
        self.inner.list_profile_snapshots_impl(owner, profile).await
    }

    /// Erases a profile's snapshots and directory. Refused while a session uses it.
    pub async fn delete_profile(&self, owner: &str, profile: ProfileId) -> Result<u64> {
        self.inner.delete_profile_impl(owner, profile).await
    }

    // ----- observability ---------------------------------------------------

    /// OS process id of the browser backing a session. Diagnostic hook for
    /// tests and operators; not exposed through the public API.
    #[must_use]
    pub fn browser_pid(&self, id: SessionId) -> Option<u32> {
        self.inner
            .live_binding(id)
            .and_then(|(b, _)| b)
            .and_then(|b| b.handle.pid())
    }

    /// A consistent copy of every scheduler metric.
    pub async fn metrics(&self) -> MetricsSnapshot {
        let inner = &self.inner;
        let mut out = MetricsSnapshot::default();
        for status in [
            SessionStatus::Queued,
            SessionStatus::Allocating,
            SessionStatus::Active,
            SessionStatus::Idle,
            SessionStatus::Recovering,
            SessionStatus::Draining,
            SessionStatus::Lost,
            SessionStatus::Closed,
        ] {
            out.sessions.insert(ops::status_label(status), 0);
        }
        if let Ok(leases) = inner.leases.list(None, None).await {
            for lease in leases {
                *out.sessions
                    .entry(ops::status_label(lease.status))
                    .or_insert(0) += 1;
            }
        }
        out.browsers
            .insert(isolation_label(Isolation::DedicatedBrowser), 0);
        out.browsers
            .insert(isolation_label(Isolation::SharedBrowser), 0);
        let mut refused = inner.metrics.egress_refused_closed.get();
        {
            let st = inner.st();
            for slot in st.browsers.values() {
                let iso = if slot.shared {
                    Isolation::SharedBrowser
                } else {
                    Isolation::DedicatedBrowser
                };
                *out.browsers.entry(isolation_label(iso)).or_insert(0) += 1;
                refused += slot.entry.egress_refused();
            }
            out.queue_depth = st.queue.len() as u64;
        }
        let m = &inner.metrics;
        out.admissions = BTreeMap::from([
            ("accepted", m.adm_accepted.get()),
            ("queue_full", m.adm_queue_full.get()),
            ("timeout", m.adm_timeout.get()),
            ("quota", m.adm_quota.get()),
            ("failed", m.adm_failed.get()),
        ]);
        out.recoveries = BTreeMap::from([
            ("restored_from_profile", m.rec_profile.get()),
            ("restored_from_snapshot", m.rec_snapshot.get()),
            ("fresh_process", m.rec_fresh.get()),
            ("lost", m.rec_lost.get()),
        ]);
        out.launch_seconds = m.launch_histogram();
        out.relay_connections =
            u64::try_from(m.relay_connections.load(Ordering::Relaxed)).unwrap_or(0);
        out.snapshots = BTreeMap::from([
            ("ok", m.snap_ok.get()),
            ("failed", m.snap_failed.get()),
            ("stale", m.snap_stale.get()),
        ]);
        out.egress_refused = refused;
        out
    }
}

fn isolation_label(isolation: Isolation) -> &'static str {
    match isolation {
        Isolation::SharedBrowser => "shared_browser",
        Isolation::DedicatedBrowser => "dedicated_browser",
    }
}
