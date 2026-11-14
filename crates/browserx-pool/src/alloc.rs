//! Allocation: turn an admission into a running browser (and context) with the
//! requested persistence restored.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use browserx_core::{
    BrowserId, ContextId, Error, Generation, Isolation, LaunchRequest, PersistenceMode, ProfileId,
    ProxyRoute, RecoveryOutcome, Result, SessionId, SessionSpec, StateSnapshot, persona_seed,
};
use browserx_egress::Forwarder;
use browserx_runtime::ProfileLock;
use sha2::{Digest, Sha256};

use crate::profiles::dir_has_content;
use crate::state::{BrowserEntry, Grant, Inner, Reservation, Want};

/// Opaque per-session egress key: stable across recoveries, reveals no session id.
pub(crate) fn sticky_key(session: SessionId) -> String {
    let digest = Sha256::digest(format!("browserx-sticky:{}", session.0).as_bytes());
    hex::encode(digest)[..24].to_owned()
}

pub(crate) struct AllocParams<'a> {
    pub session_id: SessionId,
    pub spec: &'a SessionSpec,
    pub profile_id: Option<ProfileId>,
    pub generation: Generation,
    pub enforce_queue_cap: bool,
}

impl AllocParams<'_> {
    /// Stable per-identity seed: the profile when there is one, else the session.
    fn persona_seed(&self) -> String {
        match self.profile_id {
            Some(profile) => persona_seed(&profile.0),
            None => persona_seed(&self.session_id.0),
        }
    }
}

pub(crate) struct Allocation {
    pub browser: Arc<BrowserEntry>,
    pub context: Option<ContextId>,
    pub outcome: RecoveryOutcome,
}

impl Inner {
    /// Runs a browser operation under the configured deadline.
    pub(crate) async fn bounded<T>(
        &self,
        what: &str,
        fut: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        match tokio::time::timeout(self.cfg.operation_timeout, fut).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout(format!(
                "{what} exceeded {}s",
                self.cfg.operation_timeout.as_secs()
            ))),
        }
    }

    pub(crate) async fn allocate(self: &Arc<Self>, p: &AllocParams<'_>) -> Result<Allocation> {
        let shared = p.spec.isolation == Isolation::SharedBrowser;
        let want = if shared {
            Want::Shared(p.spec.launch_profile.clone())
        } else {
            Want::Dedicated
        };
        let reservation = self
            .admit(want, self.cfg.queue_timeout, p.enforce_queue_cap)
            .await?;
        if shared {
            self.allocate_shared(reservation, p).await
        } else {
            self.allocate_dedicated(reservation, p).await
        }
    }

    async fn load_restore_state(&self, p: &AllocParams<'_>) -> Result<Option<StateSnapshot>> {
        if p.spec.persistence != PersistenceMode::Snapshot {
            return Ok(None);
        }
        let Some(profile) = p.profile_id else {
            return Ok(None);
        };
        match self.snapshots.latest(profile).await? {
            Some(snapshot) => self.sealer.open(&snapshot).map(Some),
            None => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn launch_browser(
        &self,
        launch_profile: Option<String>,
        user_data_dir: Option<PathBuf>,
        lock: Option<ProfileLock>,
        upstream: Option<ProxyRoute>,
        sticky_key: String,
        generation: u64,
        persona_seed: String,
    ) -> Result<Arc<BrowserEntry>> {
        let forwarder =
            Forwarder::start(upstream, sticky_key, generation, self.egress_policy.clone()).await?;
        let request = LaunchRequest {
            browser_id: BrowserId::new(),
            launch_profile,
            user_data_dir,
            proxy_server: Some(forwarder.proxy_server()),
            persona_seed,
        };
        let started = Instant::now();
        let launched =
            tokio::time::timeout(self.cfg.operation_timeout, self.runtime.launch(request)).await;
        self.metrics.observe_launch(started.elapsed().as_secs_f64());
        let handle = match launched {
            Ok(Ok(handle)) => handle,
            Ok(Err(e)) => {
                forwarder.shutdown().await;
                return Err(e);
            }
            Err(_) => {
                forwarder.shutdown().await;
                return Err(Error::Timeout(format!(
                    "browser launch exceeded {}s",
                    self.cfg.operation_timeout.as_secs()
                )));
            }
        };
        Ok(Arc::new(BrowserEntry::new(
            Arc::from(handle),
            self.clock.now(),
            forwarder,
            lock,
            self.metrics.clone(),
        )))
    }

    /// Shuts down a browser that never became part of the registry. If its
    /// death cannot be confirmed it is parked for retry and keeps its slot.
    pub(crate) async fn discard_entry(&self, entry: Arc<BrowserEntry>) {
        if let Err(e) = entry.teardown().await {
            tracing::error!(browser = %entry.id, error = %e, "discarded browser not confirmed dead");
            let mut st = self.st();
            st.tearing_down += 1;
            st.zombies.push(entry);
        }
    }

    async fn allocate_dedicated(
        self: &Arc<Self>,
        reservation: Reservation,
        p: &AllocParams<'_>,
    ) -> Result<Allocation> {
        let restore = self.load_restore_state(p).await?;
        let mut had_profile_data = false;
        let (dir, lock) = if p.spec.persistence == PersistenceMode::Profile {
            let profile = p
                .profile_id
                .ok_or_else(|| Error::Internal("profile persistence without profile id".into()))?;
            let dir = self.profile_dir(profile);
            had_profile_data = dir_has_content(&dir).await;
            let lock = ProfileLock::acquire(&dir)?;
            (Some(dir), Some(lock))
        } else {
            (None, None)
        };
        let entry = self
            .launch_browser(
                p.spec.launch_profile.clone(),
                dir,
                lock,
                p.spec.proxy.clone(),
                sticky_key(p.session_id),
                p.generation.0,
                p.persona_seed(),
            )
            .await?;
        if let Some(state) = &restore
            && let Err(e) = self
                .bounded("snapshot restore", entry.handle.restore_state(None, state))
                .await
        {
            self.discard_entry(entry).await;
            return Err(e);
        }
        reservation.commit_launched(entry.clone(), false, p.spec.launch_profile.clone(), 1);
        let outcome = if restore.is_some() {
            RecoveryOutcome::RestoredFromSnapshot
        } else if had_profile_data {
            RecoveryOutcome::RestoredFromProfile
        } else {
            RecoveryOutcome::FreshProcess
        };
        Ok(Allocation {
            browser: entry,
            context: None,
            outcome,
        })
    }

    async fn allocate_shared(
        self: &Arc<Self>,
        reservation: Reservation,
        p: &AllocParams<'_>,
    ) -> Result<Allocation> {
        let restore = self.load_restore_state(p).await?;
        let existing = match reservation.grant() {
            Some(Grant::SharedExisting(entry)) => Some(entry.clone()),
            Some(Grant::SharedNew(_)) => None,
            _ => {
                return Err(Error::Internal(
                    "shared allocation without a shared grant".into(),
                ));
            }
        };
        let entry = match existing {
            Some(entry) => {
                reservation.commit_existing();
                entry
            }
            None => {
                let entry = self
                    .launch_browser(
                        p.spec.launch_profile.clone(),
                        None,
                        None,
                        None,
                        "shared".into(),
                        0,
                        p.persona_seed(),
                    )
                    .await?;
                reservation.commit_launched(entry.clone(), true, p.spec.launch_profile.clone(), 1);
                entry
            }
        };
        let context = match self
            .bounded("create context", entry.handle.create_context())
            .await
        {
            Ok(context) => context,
            Err(e) => {
                let evicted = self.unbind(&entry);
                self.spawn_teardowns(evicted);
                self.capacity.notify_waiters();
                return Err(e);
            }
        };
        if let Some(state) = &restore
            && let Err(e) = self
                .bounded(
                    "snapshot restore",
                    entry.handle.restore_state(Some(&context), state),
                )
                .await
        {
            if let Err(dispose) = entry.handle.dispose_context(&context).await {
                tracing::warn!(error = %dispose, "could not dispose context after failed restore");
            }
            let evicted = self.unbind(&entry);
            self.spawn_teardowns(evicted);
            self.capacity.notify_waiters();
            return Err(e);
        }
        let outcome = if restore.is_some() {
            RecoveryOutcome::RestoredFromSnapshot
        } else {
            RecoveryOutcome::FreshProcess
        };
        Ok(Allocation {
            browser: entry,
            context: Some(context),
            outcome,
        })
    }
}
