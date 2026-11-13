//! Background duties (reaper, warm pool), startup reconciliation and shutdown.

use std::sync::Arc;

use browserx_core::{PersistenceMode, Result, SessionId, SessionLease, SessionStatus};
use futures_util::future::join_all;
use tokio::sync::Mutex;

use crate::ops::{OwnedCaller, add_duration};
use crate::state::{Inner, Live};

impl Inner {
    /// One pass of the reaper: expired leases and idle sessions are released,
    /// old terminal leases are purged, surplus idle shared browsers retire.
    pub(crate) async fn reap_tick(self: &Arc<Self>, purge: bool) {
        let now = self.clock.now();
        if let Ok(leases) = self
            .leases
            .list(None, Some(&[SessionStatus::Active, SessionStatus::Idle]))
            .await
        {
            let live: Vec<(SessionLease, usize)> = {
                let st = self.st();
                leases
                    .into_iter()
                    .filter_map(|l| st.sessions.get(&l.session_id).map(|s| (l, s.relay_conns)))
                    .collect()
            };
            let victims: Vec<(SessionId, &'static str)> = live
                .iter()
                .filter_map(|(l, relays)| {
                    if l.is_expired(now) {
                        return Some((l.session_id, "lease expired"));
                    }
                    let idle = l.spec.idle_timeout_secs.map_or(
                        self.cfg.default_idle_timeout,
                        std::time::Duration::from_secs,
                    );
                    let since = l.last_attach_at.unwrap_or(l.created_at);
                    (*relays == 0 && now >= add_duration(since, idle))
                        .then_some((l.session_id, "idle timeout"))
                })
                .collect();
            join_all(victims.into_iter().map(|(id, why)| async move {
                if let Err(e) = self
                    .clone()
                    .release_impl(OwnedCaller::System, id, None, None, why)
                    .await
                {
                    tracing::warn!(session = %id, error = %e, why, "reaper release failed");
                }
            }))
            .await;
        }
        if purge {
            let cutoff = time::Duration::try_from(self.cfg.terminal_retention)
                .ok()
                .and_then(|d| now.checked_sub(d));
            if let Some(cutoff) = cutoff
                && let Err(e) = self.leases.purge_terminal(cutoff).await
            {
                tracing::warn!(error = %e, "purging terminal leases failed");
            }
        }
        self.sweep_and_retry().await;
    }

    async fn sweep_and_retry(self: &Arc<Self>) {
        let evicted = {
            let mut st = self.st();
            self.sweep_idle_shared(&mut st)
        };
        for entry in evicted {
            self.finish_teardown(entry).await;
        }
        self.retry_zombies().await;
    }

    /// One pass of the warm pool: start shared browsers until the target is met.
    pub(crate) async fn warm_tick(self: &Arc<Self>) {
        while let Some(reservation) = self.try_reserve_warm() {
            let launched = self
                .launch_browser(
                    None,
                    None,
                    None,
                    None,
                    "shared".into(),
                    0,
                    browserx_core::persona_seed(&browserx_core::BrowserId::new().0),
                )
                .await;
            self.finish_warm();
            match launched {
                Ok(entry) => reservation.commit_launched(entry, true, None, 0),
                Err(e) => {
                    tracing::warn!(error = %e, "warm shared browser failed to start");
                    drop(reservation);
                    break;
                }
            }
        }
    }

    // ----- startup -------------------------------------------------------

    async fn close_orphan(&self, mut lease: SessionLease, reason: &str) -> Result<()> {
        let prior = lease.generation;
        if lease.status != SessionStatus::Draining && lease.status != SessionStatus::Queued {
            let to = if lease.status == SessionStatus::Allocating {
                SessionStatus::Lost
            } else {
                SessionStatus::Draining
            };
            lease.transition(to, Some(reason.to_owned()))?;
            self.leases.compare_and_swap(prior, &lease).await?;
            if to == SessionStatus::Lost {
                return Ok(());
            }
        }
        lease.transition(SessionStatus::Closed, Some(reason.to_owned()))?;
        self.leases.compare_and_swap(prior, &lease).await
    }

    /// Every non-terminal lease found at startup belongs to a previous process
    /// whose browsers died with it. Finished sessions are closed; the rest are
    /// registered and recovered according to their policy.
    pub(crate) async fn reconcile(self: &Arc<Self>) -> Result<()> {
        let leases = self
            .leases
            .list(
                None,
                Some(&[
                    SessionStatus::Queued,
                    SessionStatus::Allocating,
                    SessionStatus::Active,
                    SessionStatus::Idle,
                    SessionStatus::Recovering,
                    SessionStatus::Draining,
                ]),
            )
            .await?;
        let now = self.clock.now();
        let mut recover = Vec::new();
        for lease in leases {
            let id = lease.session_id;
            let finished = matches!(
                lease.status,
                SessionStatus::Queued | SessionStatus::Allocating | SessionStatus::Draining
            ) || lease.is_expired(now);
            if finished {
                if let Err(e) = self
                    .close_orphan(lease, "worker restarted before the session finished")
                    .await
                {
                    tracing::warn!(session = %id, error = %e, "could not close orphaned lease");
                }
                continue;
            }
            {
                let mut st = self.st();
                st.sessions.insert(
                    id,
                    Live {
                        ctl: Arc::new(Mutex::new(())),
                        browser: None,
                        context: None,
                        relay_conns: 0,
                        pending_outcome: None,
                        last_snapshot_at: now,
                    },
                );
                *st.owner_counts.entry(lease.owner.clone()).or_insert(0) += 1;
                if let Some(profile) = lease.profile_id {
                    st.profiles.entry(profile).or_insert(id);
                }
            }
            recover.push(id);
        }
        if !recover.is_empty() {
            tracing::info!(
                sessions = recover.len(),
                "recovering sessions orphaned by a previous worker"
            );
            let inner = self.clone();
            self.tracker.spawn(async move {
                for id in recover {
                    inner.recover_orphan(id).await;
                }
            });
        }
        Ok(())
    }

    async fn recover_orphan(self: &Arc<Self>, id: SessionId) {
        let Ok(_guard) = self.lock_session(id).await else {
            return;
        };
        if self.live_binding(id).is_none_or(|(b, _)| b.is_some()) {
            return;
        }
        let Ok(lease) = self.load_lease(id).await else {
            return;
        };
        if lease.status.is_terminal() || lease.status == SessionStatus::Draining {
            return;
        }
        if let Err(e) = self
            .recover_locked(lease, "recovered at worker startup")
            .await
        {
            tracing::warn!(session = %id, error = %e, "startup recovery did not produce a browser");
        }
    }

    // ----- shutdown ------------------------------------------------------

    /// Stops admission, takes a final snapshot of every snapshot-persistence
    /// session, stops every browser with confirmation and leaves leases
    /// non-terminal so a restarted worker recovers them.
    pub(crate) async fn shutdown_impl(self: &Arc<Self>) {
        self.drain.cancel();
        self.shutdown.cancel();
        self.tracker.close();
        if tokio::time::timeout(self.cfg.operation_timeout, self.tracker.wait())
            .await
            .is_err()
        {
            tracing::warn!("background tasks did not stop within the shutdown deadline");
        }
        let ids: Vec<SessionId> = self.st().sessions.keys().copied().collect();
        join_all(ids.into_iter().map(|id| self.park_session(id))).await;
        let rest: Vec<_> = {
            let mut st = self.st();
            let entries: Vec<_> = st.browsers.drain().map(|(_, slot)| slot.entry).collect();
            st.tearing_down += entries.len();
            entries
        };
        for entry in rest {
            self.finish_teardown(entry).await;
        }
        self.retry_zombies().await;
    }

    async fn park_session(self: &Arc<Self>, id: SessionId) {
        let Ok(_guard) = self.lock_session(id).await else {
            return;
        };
        let Some((Some(browser), context)) = self.live_binding(id) else {
            return;
        };
        if let Ok(mut lease) = self.load_lease(id).await
            && lease.spec.persistence == PersistenceMode::Snapshot
            && lease.profile_id.is_some()
            && lease.status.is_attachable()
            && !self.browser_exited(&browser).await
            && let Err(e) = self.snapshot_locked(&mut lease).await
        {
            tracing::warn!(session = %id, error = %e, "shutdown snapshot failed");
        }
        self.release_binding(&browser, context.as_ref()).await;
        if let Some(live) = self.st().sessions.get_mut(&id) {
            live.browser = None;
            live.context = None;
        }
    }
}
