//! In-memory scheduler state: browser slots, live sessions, and the FIFO
//! admission queue. Everything here is guarded by one `std::sync::Mutex` that is
//! never held across an `.await`.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, PoisonError};
use std::time::Duration;

use browserx_core::{
    BrowserHandle, BrowserId, BrowserRuntime, Clock, ContextId, Error, LeaseStore, ProfileId,
    RecoveryOutcome, Result, SessionId, SnapshotStore, WorkerId,
};
use browserx_egress::{EgressPolicy, Forwarder};
use browserx_runtime::ProfileLock;
use browserx_store::Sealer;
use time::OffsetDateTime;
use tokio::sync::{Mutex, Notify, broadcast};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::PoolConfig;
use crate::event::PoolEvent;
use crate::metrics::Metrics;

/// One running browser process plus the resources whose lifetime is tied to it.
pub(crate) struct BrowserEntry {
    pub id: BrowserId,
    pub handle: Arc<dyn BrowserHandle>,
    pub launched_at: OffsetDateTime,
    forwarder: StdMutex<Option<Forwarder>>,
    profile_lock: StdMutex<Option<ProfileLock>>,
    metrics: Arc<Metrics>,
}

impl BrowserEntry {
    pub(crate) fn new(
        handle: Arc<dyn BrowserHandle>,
        launched_at: OffsetDateTime,
        forwarder: Forwarder,
        profile_lock: Option<ProfileLock>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            id: handle.id(),
            handle,
            launched_at,
            forwarder: StdMutex::new(Some(forwarder)),
            profile_lock: StdMutex::new(profile_lock),
            metrics,
        }
    }

    /// Confirmed shutdown, then egress forwarder, then profile lock. The lock is
    /// kept when death could not be confirmed so a second browser can never open
    /// the same profile directory. Safe to call again after an error.
    pub(crate) async fn teardown(&self) -> Result<()> {
        let result = self.handle.shutdown_confirmed().await;
        let forwarder = self
            .forwarder
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(f) = forwarder {
            self.metrics.egress_refused_closed.add(f.stats().refused);
            f.shutdown().await;
        }
        if result.is_ok() {
            drop(
                self.profile_lock
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take(),
            );
        }
        result
    }

    pub(crate) fn egress_refused(&self) -> u64 {
        self.forwarder
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map_or(0, |f| f.stats().refused)
    }
}

pub(crate) struct BrowserSlot {
    pub entry: Arc<BrowserEntry>,
    pub shared: bool,
    /// Live plus reserved contexts (shared) or 1 (dedicated).
    pub contexts: usize,
    /// Contexts ever granted from this browser.
    pub served: u64,
    pub launch_profile: Option<String>,
    pub strikes: u32,
}

/// A non-terminal session known to this process.
pub(crate) struct Live {
    /// Serializes every mutation of the session's lease and resources.
    pub ctl: Arc<Mutex<()>>,
    pub browser: Option<Arc<BrowserEntry>>,
    pub context: Option<ContextId>,
    pub relay_conns: usize,
    /// Recovery outcome nobody has been told about yet; reported by the next attach.
    pub pending_outcome: Option<RecoveryOutcome>,
    pub last_snapshot_at: OffsetDateTime,
}

#[derive(Default)]
pub(crate) struct State {
    pub sessions: HashMap<SessionId, Live>,
    pub browsers: HashMap<BrowserId, BrowserSlot>,
    pub launching: usize,
    /// Shared browsers being launched, by launch profile. They are candidates
    /// for shared admissions: those wait for the launch instead of starting
    /// another browser each.
    pub launching_shared: HashMap<Option<String>, usize>,
    pub warming: usize,
    pub tearing_down: usize,
    pub queue: VecDeque<u64>,
    pub next_ticket: u64,
    pub owner_counts: HashMap<String, usize>,
    pub profiles: HashMap<ProfileId, SessionId>,
    pub zombies: Vec<Arc<BrowserEntry>>,
}

impl State {
    pub(crate) fn slots_used(&self) -> usize {
        self.browsers.len() + self.launching + self.tearing_down
    }
}

pub(crate) struct Inner {
    pub cfg: PoolConfig,
    pub worker_id: WorkerId,
    pub runtime: Arc<dyn BrowserRuntime>,
    pub leases: Arc<dyn LeaseStore>,
    pub snapshots: Arc<dyn SnapshotStore>,
    pub sealer: Arc<Sealer>,
    pub clock: Arc<dyn Clock>,
    pub egress_policy: EgressPolicy,
    pub profiles_root: PathBuf,
    pub state: StdMutex<State>,
    pub capacity: Notify,
    pub events: broadcast::Sender<PoolEvent>,
    /// Cancelled when the pool stops admitting work (drain started).
    pub drain: CancellationToken,
    /// Cancelled when background tasks must stop.
    pub shutdown: CancellationToken,
    pub tracker: TaskTracker,
    pub metrics: Arc<Metrics>,
}

/// What an admission asks for.
pub(crate) enum Want {
    Dedicated,
    Shared(Option<String>),
}

/// What an admission was granted.
pub(crate) enum Grant {
    Dedicated,
    /// A new shared browser for this launch profile.
    SharedNew(Option<String>),
    SharedExisting(Arc<BrowserEntry>),
}

/// What one grant attempt came to.
enum Attempt {
    Granted(Grant),
    /// No slot, but a shared browser that could serve the request is starting.
    LaunchInFlight,
    /// No slot and nothing is starting that could help.
    Full,
}

fn end_shared_launch(st: &mut State, profile: &Option<String>) {
    if let Some(n) = st.launching_shared.get_mut(profile) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            st.launching_shared.remove(profile);
        }
    }
}

/// A granted slot. Dropping it without committing gives the slot back.
pub(crate) struct Reservation {
    inner: Arc<Inner>,
    grant: Option<Grant>,
}

impl Reservation {
    pub(crate) fn grant(&self) -> Option<&Grant> {
        self.grant.as_ref()
    }

    /// Registers a freshly launched browser holding `contexts` contexts.
    pub(crate) fn commit_launched(
        mut self,
        entry: Arc<BrowserEntry>,
        shared: bool,
        launch_profile: Option<String>,
        contexts: usize,
    ) {
        let Some(grant) = self.grant.take() else {
            return;
        };
        {
            let mut st = self.inner.st();
            st.launching = st.launching.saturating_sub(1);
            if let Grant::SharedNew(profile) = &grant {
                end_shared_launch(&mut st, profile);
            }
            st.browsers.insert(
                entry.id,
                BrowserSlot {
                    entry,
                    shared,
                    contexts,
                    served: contexts as u64,
                    launch_profile,
                    strikes: 0,
                },
            );
        }
        self.inner.capacity.notify_waiters();
    }

    /// Confirms the context slot reserved on an existing shared browser.
    pub(crate) fn commit_existing(mut self) {
        if let Some(Grant::SharedExisting(entry)) = self.grant.take() {
            let mut st = self.inner.st();
            if let Some(slot) = st.browsers.get_mut(&entry.id) {
                slot.served += 1;
            }
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(grant) = self.grant.take() {
            self.inner.rollback(grant);
        }
    }
}

struct QueueTicket<'a> {
    inner: &'a Inner,
    id: u64,
}

impl Drop for QueueTicket<'_> {
    fn drop(&mut self) {
        self.inner.st().queue.retain(|t| *t != self.id);
        self.inner.capacity.notify_waiters();
    }
}

impl Inner {
    pub(crate) fn st(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn emit(&self, event: PoolEvent) {
        // No subscribers is normal; ignore the send error.
        let _ = self.events.send(event);
    }

    fn rollback(self: &Arc<Self>, grant: Grant) {
        let evicted = {
            let mut st = self.st();
            match grant {
                Grant::Dedicated => {
                    st.launching = st.launching.saturating_sub(1);
                    Vec::new()
                }
                Grant::SharedNew(profile) => {
                    st.launching = st.launching.saturating_sub(1);
                    end_shared_launch(&mut st, &profile);
                    Vec::new()
                }
                Grant::SharedExisting(entry) => {
                    if let Some(slot) = st.browsers.get_mut(&entry.id) {
                        slot.contexts = slot.contexts.saturating_sub(1);
                    }
                    self.sweep_idle_shared(&mut st)
                }
            }
        };
        self.spawn_teardowns(evicted);
        self.capacity.notify_waiters();
    }

    fn is_exhausted(&self, slot: &BrowserSlot) -> bool {
        slot.served >= self.cfg.browser_max_contexts_served
            || self.clock.now() - slot.entry.launched_at
                >= time::Duration::try_from(self.cfg.browser_max_age).unwrap_or(time::Duration::MAX)
    }

    /// Tries to satisfy `want` now. Side effects on success: reserves the slot.
    /// May evict an idle shared browser to make room; the caller spawns the
    /// returned teardowns after releasing the lock.
    fn try_grant(&self, st: &mut State, want: &Want) -> (Attempt, Vec<Arc<BrowserEntry>>) {
        if let Want::Shared(profile) = want {
            let candidate = st
                .browsers
                .values()
                .filter(|s| {
                    s.shared
                        && s.launch_profile == *profile
                        && s.contexts < self.cfg.max_contexts_per_browser
                        && !self.is_exhausted(s)
                })
                .max_by_key(|s| s.contexts)
                .map(|s| s.entry.clone());
            if let Some(entry) = candidate {
                if let Some(slot) = st.browsers.get_mut(&entry.id) {
                    slot.contexts += 1;
                }
                return (Attempt::Granted(Grant::SharedExisting(entry)), Vec::new());
            }
            // A browser that is still starting counts as a candidate: wait for
            // it rather than launching one more per concurrent request.
            if self.cfg.max_contexts_per_browser > 1
                && st.launching_shared.get(profile).is_some_and(|n| *n > 0)
            {
                return (Attempt::LaunchInFlight, Vec::new());
            }
        }
        if st.slots_used() < self.cfg.max_browsers {
            st.launching += 1;
            let grant = match want {
                Want::Dedicated => Grant::Dedicated,
                Want::Shared(profile) => {
                    *st.launching_shared.entry(profile.clone()).or_insert(0) += 1;
                    Grant::SharedNew(profile.clone())
                }
            };
            return (Attempt::Granted(grant), Vec::new());
        }
        // Full: an idle shared browser is the cheapest thing to give up.
        let victim = st
            .browsers
            .values()
            .filter(|s| s.shared && s.contexts == 0)
            .min_by_key(|s| s.entry.launched_at)
            .map(|s| s.entry.id);
        let mut evicted = Vec::new();
        if let Some(id) = victim
            && let Some(slot) = st.browsers.remove(&id)
        {
            st.tearing_down += 1;
            evicted.push(slot.entry);
        }
        (Attempt::Full, evicted)
    }

    /// Removes idle shared browsers that are exhausted or exceed the warm count.
    /// Returns entries to tear down; slot accounting is already adjusted.
    pub(crate) fn sweep_idle_shared(&self, st: &mut State) -> Vec<Arc<BrowserEntry>> {
        let mut idle: Vec<(BrowserId, bool, bool, OffsetDateTime)> = st
            .browsers
            .values()
            .filter(|s| s.shared && s.contexts == 0)
            .map(|s| {
                (
                    s.entry.id,
                    s.launch_profile.is_none(),
                    self.is_exhausted(s),
                    s.entry.launched_at,
                )
            })
            .collect();
        idle.sort_by_key(|(_, _, _, at)| std::cmp::Reverse(*at));
        let mut kept_warm = 0usize;
        let mut out = Vec::new();
        for (id, is_default, exhausted, _) in idle {
            let keep = is_default && !exhausted && kept_warm < self.cfg.warm_shared_browsers;
            if keep {
                kept_warm += 1;
                continue;
            }
            if let Some(slot) = st.browsers.remove(&id) {
                st.tearing_down += 1;
                out.push(slot.entry);
            }
        }
        out
    }

    pub(crate) fn spawn_teardowns(self: &Arc<Self>, entries: Vec<Arc<BrowserEntry>>) {
        for entry in entries {
            let inner = self.clone();
            self.tracker.spawn(async move {
                inner.finish_teardown(entry).await;
            });
        }
    }

    /// Tears `entry` down and settles its `tearing_down` slot. A browser whose
    /// death cannot be confirmed stays counted and is retried by maintenance.
    pub(crate) async fn finish_teardown(self: &Arc<Self>, entry: Arc<BrowserEntry>) -> bool {
        match entry.teardown().await {
            Ok(()) => {
                {
                    let mut st = self.st();
                    st.tearing_down = st.tearing_down.saturating_sub(1);
                }
                self.capacity.notify_waiters();
                true
            }
            Err(e) => {
                tracing::error!(browser = %entry.id, error = %e, "browser shutdown unconfirmed; will retry");
                self.st().zombies.push(entry);
                false
            }
        }
    }

    pub(crate) async fn retry_zombies(self: &Arc<Self>) {
        let zombies = std::mem::take(&mut self.st().zombies);
        for entry in zombies {
            self.finish_teardown(entry).await;
        }
    }

    /// Detaches a session from its browser slot. Returns browsers to tear down:
    /// the dedicated browser itself, or a shared browser that became surplus.
    /// A slot already removed (browser lost) yields nothing.
    pub(crate) fn unbind(&self, browser: &BrowserEntry) -> Vec<Arc<BrowserEntry>> {
        let mut st = self.st();
        let dedicated = match st.browsers.get(&browser.id) {
            None => return Vec::new(),
            Some(slot) => !slot.shared,
        };
        if dedicated {
            return match st.browsers.remove(&browser.id) {
                Some(slot) => {
                    st.tearing_down += 1;
                    vec![slot.entry]
                }
                None => Vec::new(),
            };
        }
        if let Some(slot) = st.browsers.get_mut(&browser.id) {
            slot.contexts = slot.contexts.saturating_sub(1);
        }
        self.sweep_idle_shared(&mut st)
    }

    /// Waits (FIFO) for capacity. `wait` bounds the wait; `enforce_cap` applies
    /// the queue length limit (recoveries bypass it).
    pub(crate) async fn admit(
        self: &Arc<Self>,
        want: Want,
        wait: Duration,
        enforce_cap: bool,
    ) -> Result<Reservation> {
        if self.drain.is_cancelled() {
            return Err(Error::ShuttingDown);
        }
        let (immediate, evicted, ticket) = {
            let mut st = self.st();
            if st.queue.is_empty() {
                let (attempt, evicted) = self.try_grant(&mut st, &want);
                if let Attempt::Granted(grant) = attempt {
                    (Some(grant), evicted, None)
                } else if matches!(attempt, Attempt::LaunchInFlight) {
                    // Waits for a launch, not for capacity: the queue cap does not apply.
                    let id = st.next_ticket;
                    st.next_ticket += 1;
                    st.queue.push_back(id);
                    (None, evicted, Some(id))
                } else if enforce_cap && self.cfg.queue_capacity == 0 {
                    drop(st);
                    self.spawn_teardowns(evicted);
                    self.metrics.adm_queue_full.inc();
                    return Err(Error::Capacity(
                        "no browser capacity and queueing is disabled".into(),
                    ));
                } else {
                    let id = st.next_ticket;
                    st.next_ticket += 1;
                    st.queue.push_back(id);
                    (None, evicted, Some(id))
                }
            } else if enforce_cap && st.queue.len() >= self.cfg.queue_capacity {
                self.metrics.adm_queue_full.inc();
                return Err(Error::Capacity("admission queue is full".into()));
            } else {
                let id = st.next_ticket;
                st.next_ticket += 1;
                st.queue.push_back(id);
                (None, Vec::new(), Some(id))
            }
        };
        self.spawn_teardowns(evicted);
        if let Some(grant) = immediate {
            self.metrics.adm_accepted.inc();
            return Ok(Reservation {
                inner: self.clone(),
                grant: Some(grant),
            });
        }
        let Some(id) = ticket else {
            return Err(Error::Internal("admission ticket missing".into()));
        };
        let ticket = QueueTicket { inner: self, id };
        let sleep = tokio::time::sleep(wait);
        tokio::pin!(sleep);
        loop {
            let notified = self.capacity.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let attempt = {
                let mut st = self.st();
                if st.queue.front() == Some(&ticket.id) {
                    let (attempt, evicted) = self.try_grant(&mut st, &want);
                    let grant = match attempt {
                        Attempt::Granted(grant) => {
                            st.queue.pop_front();
                            Some(grant)
                        }
                        Attempt::LaunchInFlight | Attempt::Full => None,
                    };
                    Some((grant, evicted))
                } else {
                    None
                }
            };
            if let Some((grant, evicted)) = attempt {
                self.spawn_teardowns(evicted);
                if let Some(grant) = grant {
                    self.capacity.notify_waiters();
                    self.metrics.adm_accepted.inc();
                    return Ok(Reservation {
                        inner: self.clone(),
                        grant: Some(grant),
                    });
                }
            }
            tokio::select! {
                () = &mut notified => {}
                () = &mut sleep => {
                    self.metrics.adm_timeout.inc();
                    return Err(Error::Capacity(format!(
                        "no browser capacity within {}s", wait.as_secs()
                    )));
                }
                () = self.drain.cancelled() => return Err(Error::ShuttingDown),
            }
        }
    }
}

impl Inner {
    /// Reserves a browser slot for a warm shared browser without queueing or
    /// evicting anything. `None` when enough warm browsers exist or are being
    /// started, the pool is full, or demand is waiting. Pair with `finish_warm`.
    pub(crate) fn try_reserve_warm(self: &Arc<Self>) -> Option<Reservation> {
        let mut st = self.st();
        let warm = st
            .browsers
            .values()
            .filter(|s| {
                s.shared && s.contexts == 0 && s.launch_profile.is_none() && !self.is_exhausted(s)
            })
            .count();
        if warm + st.warming >= self.cfg.warm_shared_browsers
            || !st.queue.is_empty()
            || st.slots_used() >= self.cfg.max_browsers
        {
            return None;
        }
        st.launching += 1;
        st.warming += 1;
        *st.launching_shared.entry(None).or_insert(0) += 1;
        Some(Reservation {
            inner: self.clone(),
            grant: Some(Grant::SharedNew(None)),
        })
    }

    pub(crate) fn finish_warm(&self) {
        let mut st = self.st();
        st.warming = st.warming.saturating_sub(1);
    }
}
