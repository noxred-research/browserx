//! Session operations: create, attach, renew, handoff, snapshot, release.
//!
//! Every mutation of a lease happens with the session's control mutex held and
//! follows load -> modify -> compare-and-swap on the generation.

use std::sync::Arc;
use std::time::Duration;

use browserx_core::{
    ContextId, Error, Generation, Isolation, LeaseToken, PersistenceMode, ProfileId,
    RecoveryOutcome, Result, RuntimeHealth, SessionId, SessionLease, SessionSpec, SessionStatus,
    SnapshotMeta,
};
use time::OffsetDateTime;
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::alloc::AllocParams;
use crate::event::{PoolEvent, PoolEventKind};
use crate::state::{BrowserEntry, Inner, Live};

/// Compares two equal-purpose secrets without early exit.
#[must_use]
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(crate) fn add_duration(t: OffsetDateTime, d: Duration) -> OffsetDateTime {
    time::Duration::try_from(d)
        .ok()
        .and_then(|d| t.checked_add(d))
        .unwrap_or(t)
}

/// Where a relay should connect, plus the guard that tracks the connection.
pub struct RelayAccess {
    /// Session being relayed.
    pub session_id: SessionId,
    /// Lease generation the relay is bound to; a different generation means close.
    pub generation: Generation,
    /// Isolation, which decides raw versus scoped relaying.
    pub isolation: Isolation,
    /// Browser-level DevTools URL (loopback). Never shown to clients.
    pub ws_url: String,
    /// The session's browser context (shared isolation).
    pub context: Option<ContextId>,
    /// Keeps the session `active` while alive; dropping it marks the session idle
    /// once the last relay closes.
    pub guard: RelayGuard,
}

/// Tracks one open relay connection.
pub struct RelayGuard {
    inner: Arc<Inner>,
    session_id: SessionId,
}

impl Drop for RelayGuard {
    fn drop(&mut self) {
        self.inner.metrics.relay_delta(-1);
        let remaining = {
            let mut st = self.inner.st();
            st.sessions.get_mut(&self.session_id).map(|live| {
                live.relay_conns = live.relay_conns.saturating_sub(1);
                live.relay_conns
            })
        };
        if remaining == Some(0) {
            let inner = self.inner.clone();
            let id = self.session_id;
            self.inner
                .tracker
                .spawn(async move { inner.detach_impl(id).await });
        }
    }
}

/// Result of attaching a controller.
#[derive(Clone, Debug)]
pub struct AttachInfo {
    /// The lease after attaching (status `active`).
    pub lease: SessionLease,
    /// How the controller reaches its browser state.
    pub outcome: RecoveryOutcome,
}

pub(crate) enum AttachMode {
    Api,
    Relay,
}

impl Inner {
    pub(crate) fn live_ctl(&self, id: SessionId) -> Option<Arc<Mutex<()>>> {
        self.st().sessions.get(&id).map(|l| l.ctl.clone())
    }

    pub(crate) fn live_binding(
        &self,
        id: SessionId,
    ) -> Option<(Option<Arc<BrowserEntry>>, Option<ContextId>)> {
        self.st()
            .sessions
            .get(&id)
            .map(|l| (l.browser.clone(), l.context.clone()))
    }

    pub(crate) async fn load_lease(&self, id: SessionId) -> Result<SessionLease> {
        self.leases
            .get(id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("session {id}")))
    }

    /// Locks a session's control mutex, failing with `NotFound`/`Conflict` for
    /// sessions that are gone or finished.
    pub(crate) async fn lock_session(&self, id: SessionId) -> Result<OwnedMutexGuard<()>> {
        let Some(ctl) = self.live_ctl(id) else {
            return match self.leases.get(id).await? {
                Some(lease) if lease.status.is_terminal() => Err(Error::Conflict(
                    format!("session {id} is {:?}", lease.status).to_lowercase(),
                )),
                _ => Err(Error::NotFound(format!("session {id}"))),
            };
        };
        let patience = self
            .cfg
            .operation_timeout
            .saturating_mul(self.cfg.recovery_attempts + 1);
        tokio::time::timeout(patience, ctl.lock_owned())
            .await
            .map_err(|_| Error::Timeout(format!("session {id} is busy")))
    }

    fn check_owner(lease: &SessionLease, owner: &str) -> Result<()> {
        if lease.owner == owner {
            Ok(())
        } else {
            // Same answer as a missing session: do not reveal other owners' ids.
            Err(Error::NotFound(format!("session {}", lease.session_id)))
        }
    }

    fn check_token(lease: &SessionLease, token: &LeaseToken) -> Result<()> {
        match &lease.token_digest {
            Some(stored) if ct_eq(stored, &token.digest()) => Ok(()),
            _ => Err(Error::Forbidden("invalid session token".into())),
        }
    }

    fn check_generation(lease: &SessionLease, expected: Generation) -> Result<()> {
        if lease.generation == expected {
            Ok(())
        } else {
            Err(Error::StaleGeneration {
                expected,
                found: lease.generation,
            })
        }
    }

    pub(crate) fn forget_session(&self, lease: &SessionLease) {
        let mut st = self.st();
        st.sessions.remove(&lease.session_id);
        if let Some(n) = st.owner_counts.get_mut(&lease.owner) {
            *n = n.saturating_sub(1);
        }
        if let Some(profile) = lease.profile_id
            && st.profiles.get(&profile) == Some(&lease.session_id)
        {
            st.profiles.remove(&profile);
        }
    }

    fn emit_lease(
        &self,
        lease: &SessionLease,
        kind: PoolEventKind,
        outcome: Option<RecoveryOutcome>,
    ) {
        self.emit(PoolEvent {
            session_id: lease.session_id,
            kind,
            generation: lease.generation,
            outcome,
        });
    }

    // ----- create -----------------------------------------------------

    pub(crate) async fn create_impl(
        self: Arc<Self>,
        owner: String,
        spec: SessionSpec,
    ) -> Result<(SessionLease, LeaseToken)> {
        if self.drain.is_cancelled() {
            return Err(Error::ShuttingDown);
        }
        spec.validate()?;
        if let Some(name) = &spec.launch_profile
            && !self.runtime.launch_profiles().contains(name)
        {
            return Err(Error::InvalidRequest(format!(
                "unknown launch profile {name}"
            )));
        }
        let ttl = Duration::from_secs(spec.ttl_secs.unwrap_or(self.cfg.default_ttl.as_secs()));
        if ttl > self.cfg.max_ttl {
            return Err(Error::InvalidRequest(format!(
                "ttl_secs exceeds the server maximum of {}",
                self.cfg.max_ttl.as_secs()
            )));
        }
        let lifetime = Duration::from_secs(
            spec.max_lifetime_secs
                .unwrap_or(self.cfg.max_lifetime.as_secs()),
        );
        if lifetime > self.cfg.max_lifetime {
            return Err(Error::InvalidRequest(format!(
                "max_lifetime_secs exceeds the server maximum of {}",
                self.cfg.max_lifetime.as_secs()
            )));
        }
        if spec.profile_id.is_some() && spec.persistence == PersistenceMode::Ephemeral {
            return Err(Error::InvalidRequest(
                "profile_id needs persistence=snapshot or persistence=profile".into(),
            ));
        }

        let session_id = SessionId::new();
        let mut admitted = self.admit_owner(&owner)?;
        let mut minted_profile: Option<ProfileId> = None;
        let profile_id = match (spec.persistence, spec.profile_id) {
            (PersistenceMode::Ephemeral, _) => None,
            (_, Some(id)) => {
                self.check_profile_owner(&owner, id).await?;
                Some(id)
            }
            (_, None) => {
                let id = ProfileId::new();
                self.register_profile_owner(&owner, id).await?;
                minted_profile = Some(id);
                Some(id)
            }
        };
        let result = self
            .create_admitted(
                &owner,
                spec,
                session_id,
                profile_id,
                ttl,
                lifetime,
                &mut admitted,
            )
            .await;
        match result {
            Ok(created) => {
                admitted.commit();
                Ok(created)
            }
            Err(e) => {
                if let Some(id) = minted_profile {
                    self.forget_profile_owner(id).await;
                }
                if !matches!(e, Error::Capacity(_) | Error::ShuttingDown) {
                    self.metrics.adm_failed.inc();
                }
                Err(e)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_admitted(
        self: &Arc<Self>,
        owner: &str,
        mut spec: SessionSpec,
        session_id: SessionId,
        profile_id: Option<ProfileId>,
        ttl: Duration,
        lifetime: Duration,
        admitted: &mut crate::profiles::Admitted,
    ) -> Result<(SessionLease, LeaseToken)> {
        if let Some(id) = profile_id {
            admitted.claim_profile(id, session_id)?;
        }
        spec.profile_id = profile_id;
        let generation = Generation(1);
        let alloc = self
            .allocate(&AllocParams {
                session_id,
                spec: &spec,
                profile_id,
                generation,
                enforce_queue_cap: true,
            })
            .await?;

        let now = self.clock.now();
        let max_expires_at = add_duration(now, lifetime);
        let expires_at = add_duration(now, ttl).min(max_expires_at);
        let snapshot_version = match profile_id {
            Some(id) if spec.persistence == PersistenceMode::Snapshot => self
                .snapshots
                .list(id)
                .await
                .ok()
                .and_then(|m| m.first().map(|m| m.version)),
            _ => None,
        };
        let token = LeaseToken::generate();
        let lease = SessionLease {
            session_id,
            owner: owner.to_owned(),
            spec,
            status: SessionStatus::Idle,
            generation,
            worker_id: Some(self.worker_id),
            browser_id: Some(alloc.browser.id),
            context_id: alloc.context.clone(),
            profile_id,
            snapshot_version,
            token_digest: Some(token.digest()),
            last_recovery: Some(alloc.outcome),
            recoveries: 0,
            created_at: now,
            expires_at,
            max_expires_at,
            last_heartbeat_at: Some(now),
            last_attach_at: None,
            reason: None,
        };
        self.st().sessions.insert(
            session_id,
            Live {
                ctl: Arc::new(Mutex::new(())),
                browser: Some(alloc.browser.clone()),
                context: alloc.context.clone(),
                relay_conns: 0,
                pending_outcome: None,
                last_snapshot_at: now,
            },
        );
        if let Err(e) = self.leases.insert(&lease).await {
            self.st().sessions.remove(&session_id);
            self.release_binding(&alloc.browser, alloc.context.as_ref())
                .await;
            return Err(e);
        }
        self.emit_lease(&lease, PoolEventKind::Created, Some(alloc.outcome));
        tracing::info!(session = %session_id, owner, outcome = ?alloc.outcome, "session created");
        Ok((lease, token))
    }

    /// Disposes a context (shared) and tears the browser down when it is no
    /// longer needed. Returns whether every browser it had to stop is confirmed dead.
    pub(crate) async fn release_binding(
        self: &Arc<Self>,
        browser: &Arc<BrowserEntry>,
        context: Option<&ContextId>,
    ) -> bool {
        if let Some(context) = context
            && let Err(e) = browser.handle.dispose_context(context).await
        {
            tracing::warn!(browser = %browser.id, error = %e, "could not dispose browser context");
        }
        let mut confirmed = true;
        for entry in self.unbind(browser) {
            confirmed &= self.finish_teardown(entry).await;
        }
        self.capacity.notify_waiters();
        confirmed
    }

    // ----- attach / detach ----------------------------------------------

    pub(crate) async fn attach_core(
        self: &Arc<Self>,
        owner: Option<&str>,
        id: SessionId,
        token: &LeaseToken,
        mode: AttachMode,
    ) -> Result<(AttachInfo, Option<RelayAccess>)> {
        let _guard = self.lock_session(id).await?;
        let mut lease = self.load_lease(id).await?;
        if let Some(owner) = owner {
            Self::check_owner(&lease, owner)?;
        }
        Self::check_token(&lease, token)?;
        if lease.status.is_terminal() {
            return Err(Error::Conflict(format!(
                "session {id} is {}",
                status_label(lease.status)
            )));
        }
        if lease.status == SessionStatus::Draining {
            return Err(Error::Conflict(format!("session {id} is being released")));
        }
        let browser = self.live_binding(id).and_then(|(b, _)| b);
        let gone = match &browser {
            Some(b) => self.browser_gone(b).await,
            None => true,
        };
        if gone {
            if let Some(dead) = &browser {
                let others = self.retire_dead_browser(dead).await;
                self.spawn_recoveries(others, dead.id, Some(id));
            }
            lease = self
                .recover_locked(lease, "browser not running at attach")
                .await?;
        }
        let outcome = {
            let mut st = self.st();
            match st.sessions.get_mut(&id) {
                Some(live) => live
                    .pending_outcome
                    .take()
                    .unwrap_or(RecoveryOutcome::ResumedSameProcess),
                None => return Err(Error::NotFound(format!("session {id}"))),
            }
        };
        let now = self.clock.now();
        let prior = lease.generation;
        lease.transition(SessionStatus::Active, None)?;
        lease.last_attach_at = Some(now);
        self.leases.compare_and_swap(prior, &lease).await?;
        self.emit_lease(&lease, PoolEventKind::Attached, Some(outcome));
        let relay = match mode {
            AttachMode::Api => None,
            AttachMode::Relay => {
                let (browser, context) = {
                    let mut st = self.st();
                    let Some(live) = st.sessions.get_mut(&id) else {
                        return Err(Error::NotFound(format!("session {id}")));
                    };
                    live.relay_conns += 1;
                    (live.browser.clone(), live.context.clone())
                };
                self.metrics.relay_delta(1);
                let guard = RelayGuard {
                    inner: self.clone(),
                    session_id: id,
                };
                let browser = browser
                    .ok_or_else(|| Error::Browser("session has no running browser".into()))?;
                Some(RelayAccess {
                    session_id: id,
                    generation: lease.generation,
                    isolation: lease.spec.isolation,
                    ws_url: browser.handle.browser_ws_url().to_owned(),
                    context,
                    guard,
                })
            }
        };
        Ok((AttachInfo { lease, outcome }, relay))
    }

    /// Whether the browser is dead, tolerating the short window between a
    /// process dying and the runtime noticing it: an immediate "unresponsive"
    /// (a closed DevTools connection, say) is re-probed a few times. A browser
    /// that merely times out is considered alive; the health monitor owns that case.
    pub(crate) async fn browser_gone(&self, browser: &BrowserEntry) -> bool {
        const REPROBES: u32 = 5;
        for attempt in 0..REPROBES {
            match tokio::time::timeout(self.cfg.probe_timeout, browser.handle.health()).await {
                Ok(RuntimeHealth::Healthy) | Err(_) => return false,
                Ok(RuntimeHealth::Exited { .. }) => return true,
                Ok(RuntimeHealth::Unresponsive { .. }) => {
                    if attempt + 1 < REPROBES {
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                }
            }
        }
        false
    }

    pub(crate) async fn browser_exited(&self, browser: &BrowserEntry) -> bool {
        matches!(
            tokio::time::timeout(self.cfg.probe_timeout, browser.handle.health()).await,
            Ok(RuntimeHealth::Exited { .. })
        )
    }

    pub(crate) async fn detach_impl(self: Arc<Self>, id: SessionId) {
        let Ok(guard) = self.lock_session(id).await else {
            return;
        };
        let still_unattached = self
            .st()
            .sessions
            .get(&id)
            .is_some_and(|live| live.relay_conns == 0);
        if !still_unattached {
            return;
        }
        let Ok(mut lease) = self.load_lease(id).await else {
            return;
        };
        if lease.status != SessionStatus::Active {
            return;
        }
        let prior = lease.generation;
        if lease.transition(SessionStatus::Idle, None).is_err() {
            return;
        }
        lease.last_attach_at = Some(self.clock.now());
        if let Err(e) = self.leases.compare_and_swap(prior, &lease).await {
            tracing::warn!(session = %id, error = %e, "could not mark session idle");
            return;
        }
        self.emit_lease(&lease, PoolEventKind::Detached, None);
        drop(guard);
    }

    // ----- renew / handoff / snapshot -----------------------------------

    pub(crate) async fn renew_impl(
        self: Arc<Self>,
        owner: String,
        id: SessionId,
        token: LeaseToken,
        expected: Generation,
        ttl: Option<Duration>,
    ) -> Result<SessionLease> {
        let _guard = self.lock_session(id).await?;
        let mut lease = self.load_lease(id).await?;
        Self::check_owner(&lease, &owner)?;
        Self::check_token(&lease, &token)?;
        Self::check_generation(&lease, expected)?;
        if lease.status.is_terminal() || lease.status == SessionStatus::Draining {
            return Err(Error::Conflict(format!(
                "session {id} is {}",
                status_label(lease.status)
            )));
        }
        let ttl = ttl
            .or_else(|| lease.spec.ttl_secs.map(Duration::from_secs))
            .unwrap_or(self.cfg.default_ttl);
        if ttl.is_zero() || ttl > self.cfg.max_ttl {
            return Err(Error::InvalidRequest(format!(
                "ttl must be between 1 and {} seconds",
                self.cfg.max_ttl.as_secs()
            )));
        }
        lease.expires_at = add_duration(self.clock.now(), ttl).min(lease.max_expires_at);
        self.leases.compare_and_swap(expected, &lease).await?;
        self.emit_lease(&lease, PoolEventKind::Renewed, None);
        Ok(lease)
    }

    pub(crate) async fn handoff_impl(
        self: Arc<Self>,
        owner: String,
        id: SessionId,
        token: LeaseToken,
        expected: Generation,
    ) -> Result<(SessionLease, LeaseToken)> {
        let _guard = self.lock_session(id).await?;
        let mut lease = self.load_lease(id).await?;
        Self::check_owner(&lease, &owner)?;
        Self::check_token(&lease, &token)?;
        Self::check_generation(&lease, expected)?;
        if !lease.status.is_attachable() {
            return Err(Error::Conflict(format!(
                "session {id} is {} and cannot be handed off",
                status_label(lease.status)
            )));
        }
        let fresh = LeaseToken::generate();
        lease.generation = expected.next();
        lease.token_digest = Some(fresh.digest());
        self.leases.compare_and_swap(expected, &lease).await?;
        self.emit_lease(&lease, PoolEventKind::HandedOff, None);
        tracing::info!(session = %id, generation = %lease.generation, "session handed off");
        Ok((lease, fresh))
    }

    pub(crate) async fn snapshot_impl(
        self: Arc<Self>,
        owner: String,
        id: SessionId,
        token: LeaseToken,
    ) -> Result<SnapshotMeta> {
        let _guard = self.lock_session(id).await?;
        let mut lease = self.load_lease(id).await?;
        Self::check_owner(&lease, &owner)?;
        Self::check_token(&lease, &token)?;
        if lease.spec.persistence != PersistenceMode::Snapshot {
            return Err(Error::Conflict(
                "session persistence is not snapshot".into(),
            ));
        }
        if !lease.status.is_attachable() {
            return Err(Error::Conflict(format!(
                "session {id} is {} and cannot be snapshotted",
                status_label(lease.status)
            )));
        }
        self.snapshot_locked(&mut lease).await
    }

    // ----- release -------------------------------------------------------

    pub(crate) async fn release_impl(
        self: Arc<Self>,
        caller: OwnedCaller,
        id: SessionId,
        token: Option<LeaseToken>,
        expected: Option<Generation>,
        reason: &'static str,
    ) -> Result<SessionLease> {
        let lease = self.load_lease(id).await?;
        if let OwnedCaller::Owner(owner) = &caller {
            Self::check_owner(&lease, owner)?;
        }
        if lease.status.is_terminal() {
            return Ok(lease);
        }
        let _guard = self.lock_session(id).await?;
        let mut lease = self.load_lease(id).await?;
        if lease.status.is_terminal() {
            return Ok(lease);
        }
        if let Some(token) = &token {
            Self::check_token(&lease, token)?;
        }
        if let Some(expected) = expected {
            Self::check_generation(&lease, expected)?;
        }
        if lease.status != SessionStatus::Draining {
            let prior = lease.generation;
            lease.transition(SessionStatus::Draining, Some(reason.to_owned()))?;
            self.leases.compare_and_swap(prior, &lease).await?;
            self.emit_lease(&lease, PoolEventKind::Draining, None);
        }
        let binding = self.live_binding(id);
        if let Some((Some(browser), context)) = binding {
            if lease.spec.persistence == PersistenceMode::Snapshot
                && lease.profile_id.is_some()
                && !self.browser_exited(&browser).await
                && let Err(e) = self.snapshot_locked(&mut lease).await
            {
                tracing::warn!(session = %id, error = %e, "final snapshot failed");
            }
            if !self.release_binding(&browser, context.as_ref()).await {
                lease.reason = Some(format!(
                    "{reason}; browser exit unconfirmed, retrying in background"
                ));
            }
        }
        let prior = lease.generation;
        lease.transition(
            SessionStatus::Closed,
            Some(lease.reason.clone().unwrap_or_else(|| reason.to_owned())),
        )?;
        self.leases.compare_and_swap(prior, &lease).await?;
        self.forget_session(&lease);
        self.emit_lease(&lease, PoolEventKind::Closed, None);
        self.capacity.notify_waiters();
        tracing::info!(session = %id, reason, "session closed");
        Ok(lease)
    }
}

/// Owned form of [`Caller`] that can move into a spawned task.
pub(crate) enum OwnedCaller {
    Owner(String),
    System,
}

pub(crate) fn status_label(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Queued => "queued",
        SessionStatus::Allocating => "allocating",
        SessionStatus::Active => "active",
        SessionStatus::Idle => "idle",
        SessionStatus::Recovering => "recovering",
        SessionStatus::Draining => "draining",
        SessionStatus::Lost => "lost",
        SessionStatus::Closed => "closed",
    }
}
