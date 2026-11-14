//! Recovery: replacing a lost browser, snapshots, and the health monitor.

use std::sync::Arc;

use browserx_core::{
    Error, Generation, PersistenceMode, RecoveryOutcome, RecoveryPolicy, Result, RuntimeHealth,
    SessionId, SessionLease, SessionStatus, SnapshotMeta,
};
use futures_util::future::join_all;

use crate::alloc::AllocParams;
use crate::event::{PoolEvent, PoolEventKind};
use crate::state::{BrowserEntry, Inner};

impl Inner {
    /// Ends a session whose browser is gone and cannot be replaced.
    pub(crate) async fn lose_session(&self, mut lease: SessionLease, reason: &str) -> Error {
        let prior = lease.generation;
        if lease
            .transition(SessionStatus::Lost, Some(reason.to_owned()))
            .is_ok()
            && let Err(e) = self.leases.compare_and_swap(prior, &lease).await
        {
            tracing::warn!(session = %lease.session_id, error = %e, "could not persist lost state");
        }
        self.forget_session(&lease);
        self.metrics.rec_lost.inc();
        self.emit(PoolEvent {
            session_id: lease.session_id,
            kind: PoolEventKind::Lost,
            generation: lease.generation,
            outcome: None,
        });
        self.capacity.notify_waiters();
        tracing::warn!(session = %lease.session_id, reason, "session lost");
        Error::Conflict(format!("session {} is lost: {reason}", lease.session_id))
    }

    /// Replaces the browser of `lease` according to its recovery policy. The
    /// caller holds the session's control mutex and has already torn down the
    /// previous browser (or there was none). Returns the updated lease, or an
    /// error after marking the session lost.
    pub(crate) async fn recover_locked(
        self: &Arc<Self>,
        mut lease: SessionLease,
        reason: &str,
    ) -> Result<SessionLease> {
        let id = lease.session_id;
        if lease.spec.recovery == RecoveryPolicy::None {
            return Err(self
                .lose_session(lease, "browser lost and recovery is disabled")
                .await);
        }
        if lease.status != SessionStatus::Recovering {
            let prior = lease.generation;
            lease.transition(SessionStatus::Recovering, Some(reason.to_owned()))?;
            self.leases.compare_and_swap(prior, &lease).await?;
        }
        self.emit(PoolEvent {
            session_id: id,
            kind: PoolEventKind::Recovering,
            generation: lease.generation,
            outcome: None,
        });
        let mut last_error = String::from("no attempt made");
        for attempt in 1..=self.cfg.recovery_attempts {
            if self.drain.is_cancelled() {
                return Err(Error::ShuttingDown);
            }
            let next = lease.generation.next();
            let allocated = self
                .allocate(&AllocParams {
                    session_id: id,
                    spec: &lease.spec,
                    profile_id: lease.profile_id,
                    generation: next,
                    enforce_queue_cap: false,
                })
                .await;
            match allocated {
                Ok(alloc) => {
                    let mut updated = lease.clone();
                    updated.transition(SessionStatus::Idle, Some(reason.to_owned()))?;
                    updated.generation = next;
                    updated.browser_id = Some(alloc.browser.id);
                    updated.context_id = alloc.context.clone();
                    updated.worker_id = Some(self.worker_id);
                    updated.recoveries = updated.recoveries.saturating_add(1);
                    updated.last_recovery = Some(alloc.outcome);
                    updated.last_heartbeat_at = Some(self.clock.now());
                    if let Err(e) = self
                        .leases
                        .compare_and_swap(lease.generation, &updated)
                        .await
                    {
                        self.release_binding(&alloc.browser, alloc.context.as_ref())
                            .await;
                        return Err(e);
                    }
                    {
                        let mut st = self.st();
                        if let Some(live) = st.sessions.get_mut(&id) {
                            live.browser = Some(alloc.browser.clone());
                            live.context = alloc.context.clone();
                            live.pending_outcome = Some(alloc.outcome);
                            live.last_snapshot_at = self.clock.now();
                        }
                    }
                    match alloc.outcome {
                        RecoveryOutcome::RestoredFromProfile => self.metrics.rec_profile.inc(),
                        RecoveryOutcome::RestoredFromSnapshot => self.metrics.rec_snapshot.inc(),
                        _ => self.metrics.rec_fresh.inc(),
                    }
                    self.emit(PoolEvent {
                        session_id: id,
                        kind: PoolEventKind::Recovered,
                        generation: updated.generation,
                        outcome: Some(alloc.outcome),
                    });
                    tracing::info!(session = %id, outcome = ?alloc.outcome, generation = %updated.generation, "session recovered");
                    return Ok(updated);
                }
                Err(Error::ShuttingDown) => return Err(Error::ShuttingDown),
                Err(e) => {
                    tracing::warn!(session = %id, attempt, error = %e, "recovery attempt failed");
                    last_error = e.to_string();
                    if attempt < self.cfg.recovery_attempts {
                        tokio::time::sleep(self.cfg.recovery_backoff).await;
                    }
                }
            }
        }
        Err(self
            .lose_session(
                lease,
                &format!(
                    "recovery failed after {} attempts: {last_error}",
                    self.cfg.recovery_attempts
                ),
            )
            .await)
    }

    /// Removes a lost or unresponsive browser from the pool and confirms its
    /// death. Returns every session that was bound to it.
    pub(crate) async fn retire_dead_browser(
        self: &Arc<Self>,
        entry: &Arc<BrowserEntry>,
    ) -> Vec<SessionId> {
        let (removed, affected) = {
            let mut st = self.st();
            let removed = st.browsers.remove(&entry.id).is_some();
            if removed {
                st.tearing_down += 1;
            }
            let affected: Vec<SessionId> = st
                .sessions
                .iter()
                .filter(|(_, live)| live.browser.as_ref().is_some_and(|b| b.id == entry.id))
                .map(|(id, _)| *id)
                .collect();
            (removed, affected)
        };
        if removed {
            self.finish_teardown(entry.clone()).await;
        }
        affected
    }

    /// Recovers `sessions` that were bound to the retired browser `dead`.
    pub(crate) async fn recover_many(
        self: &Arc<Self>,
        sessions: Vec<SessionId>,
        dead: browserx_core::BrowserId,
        except: Option<SessionId>,
    ) {
        let tasks = sessions
            .into_iter()
            .filter(|id| Some(*id) != except)
            .map(|id| self.recover_session(id, dead));
        join_all(tasks).await;
    }

    pub(crate) fn spawn_recoveries(
        self: &Arc<Self>,
        sessions: Vec<SessionId>,
        dead: browserx_core::BrowserId,
        except: Option<SessionId>,
    ) {
        if sessions.iter().all(|id| Some(*id) == except) {
            return;
        }
        let inner = self.clone();
        self.tracker
            .spawn(async move { inner.recover_many(sessions, dead, except).await });
    }

    async fn recover_session(self: &Arc<Self>, id: SessionId, dead: browserx_core::BrowserId) {
        let Ok(_guard) = self.lock_session(id).await else {
            return;
        };
        let still_bound = self
            .live_binding(id)
            .and_then(|(b, _)| b)
            .is_some_and(|b| b.id == dead);
        if !still_bound {
            return;
        }
        let Ok(lease) = self.load_lease(id).await else {
            return;
        };
        if !(lease.status.is_attachable() || lease.status == SessionStatus::Recovering) {
            return;
        }
        if let Err(e) = self.recover_locked(lease, "browser lost").await {
            tracing::debug!(session = %id, error = %e, "recovery ended without a replacement browser");
        }
    }

    /// One pass of the health monitor.
    pub(crate) async fn health_tick(self: &Arc<Self>) {
        let entries: Vec<Arc<BrowserEntry>> = self
            .st()
            .browsers
            .values()
            .map(|s| s.entry.clone())
            .collect();
        let probes = entries.into_iter().map(|entry| async move {
            let result = tokio::time::timeout(self.cfg.probe_timeout, entry.handle.health()).await;
            (entry, result)
        });
        for (entry, result) in join_all(probes).await {
            let verdict = match result {
                Ok(RuntimeHealth::Healthy) => {
                    self.set_strikes(&entry, 0);
                    None
                }
                Ok(RuntimeHealth::Exited { detail }) => Some(format!("exited: {detail}")),
                Ok(RuntimeHealth::Unresponsive { detail }) => self
                    .strike(&entry)
                    .map(|n| format!("unresponsive x{n}: {detail}")),
                Err(_) => self
                    .strike(&entry)
                    .map(|n| format!("health probe timed out x{n}")),
            };
            if let Some(why) = verdict {
                tracing::warn!(browser = %entry.id, why, "browser lost");
                let affected = self.retire_dead_browser(&entry).await;
                self.recover_many(affected, entry.id, None).await;
            }
        }
    }

    fn set_strikes(&self, entry: &BrowserEntry, value: u32) {
        if let Some(slot) = self.st().browsers.get_mut(&entry.id) {
            slot.strikes = value;
        }
    }

    /// Records one failed probe; returns the strike count once it reaches the limit.
    fn strike(&self, entry: &BrowserEntry) -> Option<u32> {
        let mut st = self.st();
        let slot = st.browsers.get_mut(&entry.id)?;
        slot.strikes += 1;
        (slot.strikes >= self.cfg.unresponsive_strikes).then_some(slot.strikes)
    }

    // ----- snapshots -----------------------------------------------------

    /// Captures, seals and stores a snapshot. The caller holds the session's
    /// control mutex. A snapshot whose generation is no longer current is discarded.
    pub(crate) async fn snapshot_locked(&self, lease: &mut SessionLease) -> Result<SnapshotMeta> {
        let result = self.snapshot_inner(lease).await;
        match &result {
            Ok(_) => self.metrics.snap_ok.inc(),
            Err(Error::StaleGeneration { .. }) => self.metrics.snap_stale.inc(),
            Err(_) => self.metrics.snap_failed.inc(),
        }
        result
    }

    async fn snapshot_inner(&self, lease: &mut SessionLease) -> Result<SnapshotMeta> {
        let id = lease.session_id;
        let profile = lease
            .profile_id
            .ok_or_else(|| Error::Internal("snapshot session without profile id".into()))?;
        let (browser, context) = match self.live_binding(id) {
            Some((Some(browser), context)) => (browser, context),
            _ => return Err(Error::Browser("session has no running browser".into())),
        };
        let state = self
            .bounded(
                "state capture",
                browser.handle.capture_state(context.as_ref()),
            )
            .await?;
        let current = self.load_lease(id).await?;
        if current.generation != lease.generation {
            return Err(Error::StaleGeneration {
                expected: lease.generation,
                found: current.generation,
            });
        }
        let version = self
            .snapshots
            .list(profile)
            .await?
            .first()
            .map_or(0, |m| m.version)
            + 1;
        let now = self.clock.now();
        let meta = SnapshotMeta {
            profile_id: profile,
            version,
            session_id: id,
            generation: lease.generation,
            created_at: now,
            size: 0,
            key_id: String::new(),
        };
        let sealed = self.sealer.seal(meta, &state)?;
        self.snapshots.put(&sealed).await?;
        if let Err(e) = self.snapshots.prune(profile, self.cfg.snapshot_keep).await {
            tracing::warn!(profile = %profile, error = %e, "snapshot prune failed");
        }
        let prior: Generation = lease.generation;
        lease.snapshot_version = Some(version);
        lease.last_heartbeat_at = Some(now);
        self.leases.compare_and_swap(prior, lease).await?;
        if let Some(live) = self.st().sessions.get_mut(&id) {
            live.last_snapshot_at = now;
        }
        self.emit(PoolEvent {
            session_id: id,
            kind: PoolEventKind::Snapshotted,
            generation: lease.generation,
            outcome: None,
        });
        Ok(sealed.meta)
    }

    /// One pass of the snapshotter: snapshot every due `snapshot`-persistence session.
    pub(crate) async fn snapshot_tick(self: &Arc<Self>) {
        let Ok(leases) = self
            .leases
            .list(None, Some(&[SessionStatus::Active, SessionStatus::Idle]))
            .await
        else {
            return;
        };
        let now = self.clock.now();
        let interval =
            time::Duration::try_from(self.cfg.snapshot_interval).unwrap_or(time::Duration::MAX);
        let due: Vec<SessionId> = {
            let mut st = self.st();
            leases
                .iter()
                .filter(|l| l.spec.persistence == PersistenceMode::Snapshot)
                .filter_map(|l| {
                    let live = st.sessions.get_mut(&l.session_id)?;
                    if live.browser.is_some() && now - live.last_snapshot_at >= interval {
                        live.last_snapshot_at = now;
                        Some(l.session_id)
                    } else {
                        None
                    }
                })
                .collect()
        };
        join_all(due.into_iter().map(|id| self.periodic_snapshot(id))).await;
    }

    async fn periodic_snapshot(self: &Arc<Self>, id: SessionId) {
        let Ok(_guard) = self.lock_session(id).await else {
            return;
        };
        let Ok(mut lease) = self.load_lease(id).await else {
            return;
        };
        if !lease.status.is_attachable() {
            return;
        }
        if let Err(e) = self.snapshot_locked(&mut lease).await {
            tracing::warn!(session = %id, error = %e, "periodic snapshot failed");
        }
    }
}
