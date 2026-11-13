//! The Chromium runtime and its browser handles.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use browserx_cdp::{CdpClient, CdpLimits};
use browserx_core::{
    BrowserHandle, BrowserId, BrowserRuntime, ContextId, Error, LaunchRequest, Result,
    RuntimeHealth, StateSnapshot,
};
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::config::{LaunchProfile, RuntimeConfig};
use crate::control::Control;
use crate::discover::discover_chromium;
use crate::orphans::{self, RecordGuard, SweepReport, TEMP_DIR_PREFIX};
use crate::process::{self, Proc};
use crate::state;

/// Deadline for a health probe's protocol round trip.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
/// How long `Browser.close` may take to be acknowledged.
const BROWSER_CLOSE_ACK: Duration = Duration::from_secs(2);
/// How long the process may take to exit after `Browser.close`.
const BROWSER_CLOSE_EXIT: Duration = Duration::from_secs(5);
/// Flags every launch gets, regardless of profile.
const BASE_FLAGS: &[&str] = &[
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-default-apps",
    "--password-store=basic",
    "--use-mock-keychain",
];
/// Added when the browser's traffic goes through the egress forwarder: WebRTC
/// may then only use UDP that is itself proxied, so it can neither reveal the
/// host's real address nor reach destinations the forwarder's policy refuses.
const WEBRTC_FLAG: &str = "--force-webrtc-ip-handling-policy=disable_non_proxied_udp";

/// Launches and supervises local Chromium processes.
#[derive(Debug)]
pub struct ChromiumRuntime {
    cfg: RuntimeConfig,
}

impl ChromiumRuntime {
    /// Builds the runtime, rejecting launch profiles that set managed flags.
    pub fn new(cfg: RuntimeConfig) -> Result<Self> {
        Ok(Self {
            cfg: cfg.validated()?,
        })
    }

    /// Kills browsers left behind by a worker that crashed, and removes the
    /// temporary directories they used.
    ///
    /// Call once at startup, before launching anything. Each launched browser
    /// leaves a record under the configured `temp_root`; a record whose owning
    /// worker is gone is acted on only if the recorded process is verifiably the
    /// browser (same process group, exact `--user-data-dir=` argument, same start
    /// time). Records of workers that are still running are left alone. Requires
    /// `/proc`; elsewhere it logs a warning and does nothing.
    pub async fn sweep_orphans(&self) -> Result<SweepReport> {
        let root = self.cfg.temp_root.clone();
        let report = tokio::task::spawn_blocking(move || orphans::sweep(&root))
            .await
            .map_err(|e| Error::Internal(format!("orphan sweep failed: {e}")))?;
        if report != SweepReport::default() {
            tracing::warn!(
                killed = report.killed,
                removed_dirs = report.removed_dirs,
                "cleaned up after a previous worker"
            );
        }
        Ok(report)
    }

    fn cdp_limits(&self) -> CdpLimits {
        CdpLimits {
            max_message_bytes: self.cfg.cdp_max_message_bytes,
            ..CdpLimits::default()
        }
    }

    fn profile(&self, name: Option<&str>) -> Result<&LaunchProfile> {
        let name = name.unwrap_or(&self.cfg.default_launch_profile);
        self.cfg
            .launch_profiles
            .get(name)
            .ok_or_else(|| Error::InvalidRequest(format!("unknown launch profile `{name}`")))
    }
}

fn resolve_executable(profile: &LaunchProfile) -> Result<PathBuf> {
    match &profile.executable {
        Some(path) => Ok(path.clone()),
        None => discover_chromium().ok_or_else(|| {
            Error::Browser(
                "no Chromium executable found: set BROWSERX_CHROMIUM_PATH, put one on PATH, \
                 or set `executable` in the launch profile"
                    .into(),
            )
        }),
    }
}

/// The full argument vector: managed flags first, then the profile's own, with
/// `{persona_seed}` replaced by the request's seed.
fn build_args(
    profile: &LaunchProfile,
    user_data_dir: &Path,
    proxy: Option<&str>,
    persona_seed: &str,
) -> Vec<String> {
    let mut args = vec![
        "--remote-debugging-port=0".to_owned(),
        format!("--user-data-dir={}", user_data_dir.display()),
    ];
    if profile.headless {
        args.push("--headless=new".to_owned());
    }
    args.extend(BASE_FLAGS.iter().map(|f| (*f).to_owned()));
    if let Some(proxy) = proxy {
        args.push(format!("--proxy-server={proxy}"));
        args.push("--proxy-bypass-list=<-loopback>".to_owned());
        args.push(WEBRTC_FLAG.to_owned());
    }
    args.extend(
        profile
            .args
            .iter()
            .map(|a| a.replace("{persona_seed}", persona_seed)),
    );
    args
}

#[async_trait]
impl BrowserRuntime for ChromiumRuntime {
    async fn launch(&self, request: LaunchRequest) -> Result<Box<dyn BrowserHandle>> {
        let profile = self.profile(request.launch_profile.as_deref())?;
        let executable = resolve_executable(profile)?;

        if request.persona_seed.is_empty()
            || !request
                .persona_seed
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(Error::InvalidRequest(
                "persona seed must be [A-Za-z0-9_]+".into(),
            ));
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(self.cfg.startup_timeout)
            .ok_or_else(|| Error::InvalidRequest("startup timeout is too large".into()))?;

        let (user_data_dir, temp) = match &request.user_data_dir {
            Some(dir) => {
                tokio::fs::create_dir_all(dir)
                    .await
                    .map_err(|e| Error::Storage(format!("cannot create user-data dir: {e}")))?;
                (dir.clone(), None)
            }
            None => {
                orphans::ensure_private_dir(&self.cfg.temp_root)?;
                let temp = tempfile::Builder::new()
                    .prefix(TEMP_DIR_PREFIX)
                    .tempdir_in(&self.cfg.temp_root)
                    .map_err(|e| Error::Storage(format!("cannot create temp dir: {e}")))?;
                (temp.path().to_path_buf(), Some(temp))
            }
        };
        // The record exists before the browser does, so a crash at any later
        // point leaves something the next worker's sweep can act on.
        let mut record = RecordGuard::create(
            &self.cfg.temp_root,
            request.browser_id,
            &user_data_dir,
            temp.as_ref().map(TempDir::path),
        )?;

        let args = build_args(
            profile,
            &user_data_dir,
            request.proxy_server.as_deref(),
            &request.persona_seed,
        );
        let (proc, ws_url) = process::spawn(
            &executable,
            &args,
            &profile.env,
            self.cfg.startup_timeout,
            |pid| record.set_browser(pid),
        )
        .await?;

        let limits = self.cdp_limits();
        let connected = async {
            let cdp = CdpClient::connect(&ws_url, limits.clone()).await?;
            let version = match cdp.call("Browser.getVersion", json!({}), None).await {
                Ok(reply) => reply
                    .get("product")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| Error::Browser("Browser.getVersion returned no product".into())),
                Err(err) => Err(err.into()),
            };
            match version {
                Ok(version) => Ok((cdp, version)),
                Err(err) => {
                    cdp.close().await;
                    Err(err)
                }
            }
        };
        let (cdp, version) = match tokio::time::timeout_at(deadline, connected).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(err)) => return Err(abort_launch(&proc, temp, err).await),
            Err(_) => {
                let err = Error::Timeout("browser DevTools endpoint did not answer in time".into());
                return Err(abort_launch(&proc, temp, err).await);
            }
        };

        tracing::info!(browser = %request.browser_id, pid = proc.pid(), %version, "browser launched");
        Ok(Box::new(ChromiumHandle {
            id: request.browser_id,
            ws_url: ws_url.clone(),
            version,
            proc,
            control: Control::new(ws_url, limits, cdp),
            record,
            temp: Mutex::new(temp),
            shutdown_done: tokio::sync::Mutex::new(false),
        }))
    }

    fn launch_profiles(&self) -> Vec<String> {
        self.cfg.launch_profiles.keys().cloned().collect()
    }
}

/// Kills a half-started browser and removes its temp directory, then returns `err`.
async fn abort_launch(proc: &Proc, temp: Option<TempDir>, err: Error) -> Error {
    if let Err(kill_err) = proc.terminate().await {
        tracing::warn!(error = %kill_err, "could not terminate a browser that failed to start");
    }
    drop(temp);
    err
}

struct ChromiumHandle {
    id: BrowserId,
    ws_url: String,
    version: String,
    proc: Proc,
    control: Control,
    /// Removed once the browser is gone (or the handle is dropped).
    record: RecordGuard,
    temp: Mutex<Option<TempDir>>,
    shutdown_done: tokio::sync::Mutex<bool>,
}

impl ChromiumHandle {
    async fn remove_temp_dir(&self) {
        let temp = self
            .temp
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(temp) = temp else { return };
        let path = temp.keep();
        let mut last = None;
        for _ in 0..5 {
            match tokio::fs::remove_dir_all(&path).await {
                Ok(()) => return,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
                Err(err) => last = Some(err),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if let Some(err) = last {
            tracing::warn!(error = %err, "could not remove the browser's temporary directory");
        }
    }
}

#[async_trait]
impl BrowserHandle for ChromiumHandle {
    fn id(&self) -> BrowserId {
        self.id
    }

    fn browser_ws_url(&self) -> &str {
        &self.ws_url
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn pid(&self) -> Option<u32> {
        Some(self.proc.pid())
    }

    async fn health(&self) -> RuntimeHealth {
        if let Some(exit) = self.proc.exited() {
            return RuntimeHealth::Exited { detail: exit.0 };
        }
        // A closed control connection (an oversized reply, a transport error) is
        // repaired here rather than counted against a browser that still runs.
        let probe = async {
            let cdp = self.control.client().await?;
            cdp.call("Browser.getVersion", json!({}), None)
                .await
                .map_err(Error::from)
        };
        match tokio::time::timeout(HEALTH_TIMEOUT, probe).await {
            Ok(Ok(_)) => RuntimeHealth::Healthy,
            Ok(Err(err)) => RuntimeHealth::Unresponsive {
                detail: err.to_string(),
            },
            Err(_) => RuntimeHealth::Unresponsive {
                detail: format!("no reply to Browser.getVersion within {HEALTH_TIMEOUT:?}"),
            },
        }
    }

    async fn create_context(&self) -> Result<ContextId> {
        let reply = self
            .control
            .client()
            .await?
            .call(
                "Target.createBrowserContext",
                json!({ "disposeOnDetach": false }),
                None,
            )
            .await?;
        reply
            .get("browserContextId")
            .and_then(Value::as_str)
            .map(|id| ContextId(id.to_owned()))
            .ok_or_else(|| Error::Browser("createBrowserContext returned no id".into()))
    }

    async fn dispose_context(&self, context: &ContextId) -> Result<()> {
        self.control
            .client()
            .await?
            .call(
                "Target.disposeBrowserContext",
                json!({ "browserContextId": context.0 }),
                None,
            )
            .await?;
        Ok(())
    }

    async fn capture_state(&self, context: Option<&ContextId>) -> Result<StateSnapshot> {
        state::capture(&self.control, &self.version, context).await
    }

    async fn restore_state(
        &self,
        context: Option<&ContextId>,
        snapshot: &StateSnapshot,
    ) -> Result<()> {
        state::restore(&self.control, context, snapshot).await
    }

    async fn shutdown_confirmed(&self) -> Result<()> {
        let mut done = self.shutdown_done.lock().await;
        if *done {
            return Ok(());
        }
        if self.proc.exited().is_none() {
            // Polite first: the browser flushes profile data on `Browser.close`.
            // Its error is irrelevant; the exit wait below is the confirmation.
            let close = async {
                self.control
                    .client()
                    .await?
                    .call("Browser.close", json!({}), None)
                    .await
                    .map_err(Error::from)
            };
            let _ = tokio::time::timeout(BROWSER_CLOSE_ACK, close).await;
            if !self.proc.wait_exit(BROWSER_CLOSE_EXIT).await {
                self.proc.terminate().await?;
            }
        }
        self.control.close().await;
        self.remove_temp_dir().await;
        self.record.remove();
        *done = true;
        tracing::info!(browser = %self.id, "browser shut down");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{WEBRTC_FLAG, build_args};
    use crate::config::LaunchProfile;

    #[test]
    fn persona_seed_placeholder_is_substituted_in_profile_args() {
        let profile = LaunchProfile {
            args: vec!["--fingerprint={persona_seed}".to_owned()],
            ..LaunchProfile::default()
        };
        let args = build_args(&profile, Path::new("dir"), None, "42");
        assert!(args.iter().any(|a| a == "--fingerprint=42"));
        assert!(!args.iter().any(|a| a.contains("{persona_seed}")));
    }

    #[test]
    fn proxied_launch_forces_webrtc_through_the_proxy() {
        let profile = LaunchProfile::default();
        let proxied = build_args(&profile, Path::new("dir"), Some("http://127.0.0.1:1"), "1");
        assert!(proxied.iter().any(|a| a == WEBRTC_FLAG), "{proxied:?}");
        assert!(
            proxied
                .iter()
                .any(|a| a == "--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
        );
        let direct = build_args(&profile, Path::new("dir"), None, "1");
        assert!(!direct.iter().any(|a| a.contains("webrtc")));
    }
}
