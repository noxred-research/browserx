//! Spawning and supervising one browser process group.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use browserx_core::{Error, Result};
use nix::sys::signal::{Signal, killpg};
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::Pid;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

/// Longest stderr line read at once; longer lines are split.
const MAX_STDERR_LINE: u64 = 16 * 1024;
/// Stderr lines kept for launch-failure diagnostics.
const STDERR_TAIL_LINES: usize = 20;
/// Characters of stderr tail included in an error message.
const STDERR_TAIL_CHARS: usize = 1000;
/// Grace between escalating signals.
pub(crate) const SIGNAL_GRACE: Duration = Duration::from_secs(5);
const ENDPOINT_MARKER: &str = "DevTools listening on ";
/// Fallback poll interval of the exit watcher; SIGCHLD normally wakes it sooner.
const EXIT_POLL: Duration = Duration::from_millis(200);

/// Environment variables the browser inherits from the worker; everything else
/// (database and object-store credentials, tokens, proxy settings, ...) is
/// dropped. The launch profile's own `env` is added on top.
const INHERITED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LANGUAGE",
    "TZ",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_DIRS",
    "FONTCONFIG_PATH",
    "FONTCONFIG_FILE",
    // Headed browsers need to find their display.
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
];
/// Variable-name prefix inherited as well (`LC_ALL`, `LC_CTYPE`, ...).
const INHERITED_ENV_PREFIX: &str = "LC_";

/// The browser's environment: the allow-listed part of `parent`, then the
/// launch profile's `env` (which wins).
fn browser_env(
    parent: impl IntoIterator<Item = (OsString, OsString)>,
    profile: &BTreeMap<String, String>,
) -> BTreeMap<OsString, OsString> {
    let allowed = |name: &OsStr| {
        name.to_str().is_some_and(|n| {
            INHERITED_ENV.contains(&n)
                || n.strip_prefix(INHERITED_ENV_PREFIX)
                    .is_some_and(|rest| !rest.is_empty())
        })
    };
    let mut env: BTreeMap<OsString, OsString> =
        parent.into_iter().filter(|(k, _)| allowed(k)).collect();
    for (key, value) in profile {
        env.insert(key.into(), value.into());
    }
    env
}

/// How the process ended.
#[derive(Clone, Debug)]
pub(crate) struct ExitInfo(pub String);

/// Whether the leader of a process group has been reaped.
///
/// Once a leader is reaped and its group is empty, the kernel may hand the same
/// number to an unrelated process. Every signal to the group therefore takes
/// this lock and checks the flag, and the reaper sets the flag under the same
/// lock, so no signal can ever reach a recycled group id.
struct GroupState {
    pgid: i32,
    reaped: Mutex<bool>,
}

impl GroupState {
    /// Signals the group unless its leader was already reaped. ESRCH (group
    /// already gone) is not an error.
    fn signal(&self, signal: Signal) {
        let reaped = self.reaped.lock().unwrap_or_else(PoisonError::into_inner);
        if !*reaped {
            let _ = killpg(Pid::from_raw(self.pgid), Some(signal));
        }
    }
}

/// A supervised browser process group.
///
/// A background task owns the child. When the leader exits it is first observed
/// *without* being reaped (`waitid` with `WNOWAIT`), so the group id is still
/// ours: the task SIGKILLs any stragglers in the group (renderers, zygotes),
/// then reaps the leader. Dropping a `Proc` whose leader is still alive kills
/// the whole group.
pub(crate) struct Proc {
    pid: u32,
    group: Arc<GroupState>,
    exit: watch::Receiver<Option<ExitInfo>>,
    drain: JoinHandle<()>,
}

impl Proc {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// The exit description once the leader has been reaped.
    pub(crate) fn exited(&self) -> Option<ExitInfo> {
        self.exit.borrow().clone()
    }

    /// Waits up to `limit` for the leader to be reaped.
    pub(crate) async fn wait_exit(&self, limit: Duration) -> bool {
        let mut rx = self.exit.clone();
        matches!(
            tokio::time::timeout(limit, rx.wait_for(Option::is_some)).await,
            Ok(Ok(_))
        )
    }

    /// SIGTERM the group, then SIGKILL it, waiting for the leader to be reaped.
    pub(crate) async fn terminate(&self) -> Result<()> {
        if self.exited().is_some() {
            return Ok(());
        }
        self.group.signal(Signal::SIGTERM);
        if self.wait_exit(SIGNAL_GRACE).await {
            return Ok(());
        }
        self.group.signal(Signal::SIGKILL);
        if self.wait_exit(SIGNAL_GRACE).await {
            return Ok(());
        }
        Err(Error::Browser(format!(
            "browser process {} did not exit after SIGKILL",
            self.pid
        )))
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.group.signal(Signal::SIGKILL);
        self.drain.abort();
    }
}

/// Resolves once the child has exited, without reaping it: the zombie keeps the
/// process group id reserved until the caller reaps it.
async fn wait_until_exited(pid: i32) {
    // Subscribed before the first check so an exit in between is not missed.
    let mut sigchld = signal(SignalKind::child()).ok();
    loop {
        match waitid(
            Id::Pid(Pid::from_raw(pid)),
            WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
        ) {
            Ok(WaitStatus::StillAlive) => {}
            // Exited, or not our child any more (ECHILD): nothing left to watch.
            Ok(_) | Err(_) => return,
        }
        match sigchld.as_mut() {
            Some(stream) => {
                tokio::select! {
                    _ = stream.recv() => {}
                    () = tokio::time::sleep(EXIT_POLL) => {}
                }
            }
            None => tokio::time::sleep(EXIT_POLL).await,
        }
    }
}

/// Kills the group's stragglers and reaps the leader, as one step with respect
/// to [`GroupState::signal`]. Returns the exit description.
async fn reap_and_sweep(mut child: Child, group: &GroupState) -> String {
    {
        let mut reaped = group.reaped.lock().unwrap_or_else(PoisonError::into_inner);
        // The leader is a zombie, so the group id is still ours.
        let _ = killpg(Pid::from_raw(group.pgid), Some(Signal::SIGKILL));
        if let Ok(Some(status)) = child.try_wait() {
            *reaped = true;
            return status.to_string();
        }
    }
    // Not reapable without blocking (cannot happen after a positive `waitid`, but
    // never assume); wait normally, then mark the group as gone.
    let outcome = match child.wait().await {
        Ok(status) => status.to_string(),
        Err(err) => format!("wait failed: {err}"),
    };
    *group.reaped.lock().unwrap_or_else(PoisonError::into_inner) = true;
    outcome
}

/// Starts the browser and waits for its DevTools endpoint on stderr.
///
/// `on_spawned` runs with the process id as soon as the process exists, before
/// the endpoint wait, so a record of it can be written while the browser is
/// still starting. If it fails the process group is terminated.
///
/// On failure the process group is terminated before the error is returned.
pub(crate) async fn spawn(
    executable: &Path,
    args: &[String],
    env: &BTreeMap<String, String>,
    startup: Duration,
    on_spawned: impl FnOnce(u32) -> Result<()>,
) -> Result<(Proc, String)> {
    let mut child = Command::new(executable)
        .args(args)
        .env_clear()
        .envs(browser_env(std::env::vars_os(), env))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0)
        .spawn()
        .map_err(|e| Error::Browser(format!("cannot start {}: {e}", executable.display())))?;
    let pid = child
        .id()
        .ok_or_else(|| Error::Browser("browser exited before it could be supervised".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::Internal("browser stderr was not captured".into()))?;

    let raw_pid = i32::try_from(pid)
        .map_err(|_| Error::Internal("browser process id out of range".into()))?;
    let group = Arc::new(GroupState {
        pgid: raw_pid,
        reaped: Mutex::new(false),
    });
    let (exit_tx, exit_rx) = watch::channel(None);
    tokio::spawn({
        let group = Arc::clone(&group);
        async move {
            wait_until_exited(raw_pid).await;
            let outcome = reap_and_sweep(child, &group).await;
            // The receiver side may be gone already.
            let _ = exit_tx.send(Some(ExitInfo(outcome)));
        }
    });

    let (url_tx, url_rx) = oneshot::channel();
    let tail = Arc::new(Mutex::new(VecDeque::new()));
    let drain = tokio::spawn(drain_stderr(stderr, url_tx, tail.clone()));
    let proc = Proc {
        pid,
        group,
        exit: exit_rx,
        drain,
    };
    if let Err(err) = on_spawned(pid) {
        if let Err(kill_err) = proc.terminate().await {
            tracing::warn!(error = %kill_err, "could not terminate a browser whose launch was abandoned");
        }
        return Err(err);
    }

    let outcome = tokio::time::timeout(startup, url_rx).await;
    match outcome {
        Ok(Ok(url)) => Ok((proc, url)),
        Ok(Err(_)) => {
            // stderr closed without an endpoint line: the process is dying or dead.
            proc.wait_exit(Duration::from_secs(2)).await;
            let status = proc
                .exited()
                .map_or_else(|| "still running".to_owned(), |e| e.0);
            let detail = tail_text(&tail);
            if let Err(err) = proc.terminate().await {
                tracing::warn!(error = %err, "could not terminate a browser that failed to start");
            }
            Err(Error::Browser(format!(
                "browser exited before opening a DevTools endpoint ({status}); stderr: {detail}"
            )))
        }
        Err(_) => {
            let detail = tail_text(&tail);
            if let Err(err) = proc.terminate().await {
                tracing::warn!(error = %err, "could not terminate a browser that failed to start");
            }
            Err(Error::Timeout(format!(
                "browser did not open a DevTools endpoint within {startup:?}; stderr: {detail}"
            )))
        }
    }
}

fn tail_text(tail: &Mutex<VecDeque<String>>) -> String {
    let lines = tail.lock().unwrap_or_else(PoisonError::into_inner);
    let joined = lines
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" | ");
    joined.chars().take(STDERR_TAIL_CHARS).collect()
}

/// Reads stderr until EOF: hands over the DevTools URL once, keeps a short tail
/// until then, and discards everything afterwards so the pipe never fills.
async fn drain_stderr(
    stderr: tokio::process::ChildStderr,
    url_tx: oneshot::Sender<String>,
    tail: Arc<Mutex<VecDeque<String>>>,
) {
    let mut reader = BufReader::new(stderr);
    let mut url_tx = Some(url_tx);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let read = (&mut reader)
            .take(MAX_STDERR_LINE)
            .read_until(b'\n', &mut buf)
            .await;
        if !matches!(read, Ok(n) if n > 0) {
            break;
        }
        if url_tx.is_none() {
            continue;
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_end();
        if let Some(url) = parse_endpoint(line) {
            if let Some(tx) = url_tx.take() {
                // The launcher may have timed out already.
                let _ = tx.send(url);
            }
            continue;
        }
        let mut lines = tail.lock().unwrap_or_else(PoisonError::into_inner);
        if lines.len() == STDERR_TAIL_LINES {
            lines.pop_front();
        }
        lines.push_back(line.chars().take(200).collect());
    }
}

/// Extracts a loopback `ws://` URL from a `DevTools listening on …` line.
pub(crate) fn parse_endpoint(line: &str) -> Option<String> {
    let rest = line.split_once(ENDPOINT_MARKER)?.1.trim();
    let url = url::Url::parse(rest).ok()?;
    if url.scheme() != "ws" {
        return None;
    }
    let loopback = match url.host()? {
        url::Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    };
    loopback.then(|| rest.to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    use super::*;

    #[test]
    fn endpoint_line_is_parsed() {
        let line = "DevTools listening on ws://127.0.0.1:40123/devtools/browser/abc-def";
        assert_eq!(
            parse_endpoint(line).as_deref(),
            Some("ws://127.0.0.1:40123/devtools/browser/abc-def")
        );
        assert!(parse_endpoint("[1:2:ERROR] something else").is_none());
    }

    #[test]
    fn non_loopback_or_non_ws_endpoints_are_refused() {
        assert!(
            parse_endpoint("DevTools listening on ws://10.0.0.5:9222/devtools/browser/x").is_none()
        );
        assert!(parse_endpoint("DevTools listening on http://127.0.0.1:9222/").is_none());
        assert!(
            parse_endpoint("DevTools listening on ws://[::1]:9222/devtools/browser/x").is_some()
        );
    }

    #[tokio::test]
    async fn nothing_is_signalled_once_the_leader_is_reaped() {
        // A bystander in its own group stands in for an unrelated process that
        // was handed the recycled group id.
        let mut bystander = std::process::Command::new("sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let pgid = i32::try_from(bystander.id()).unwrap();
        let group = GroupState {
            pgid,
            reaped: Mutex::new(true),
        };
        group.signal(Signal::SIGKILL);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            bystander.try_wait().unwrap().is_none(),
            "a reaped group must never be signalled"
        );
        // Control: the same call on a live group does signal.
        let live = GroupState {
            pgid,
            reaped: Mutex::new(false),
        };
        live.signal(Signal::SIGKILL);
        assert!(bystander.wait().is_ok());
    }

    #[tokio::test]
    async fn stragglers_of_the_group_die_with_the_leader() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("straggler.pid");
        let script = dir.path().join("leader.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nsleep 300 &\necho $! > {}\necho 'DevTools listening on ws://127.0.0.1:1/devtools/browser/x' >&2\nsleep 1\nexit 0\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (proc, _url) = spawn(
            &script,
            &[],
            &BTreeMap::new(),
            Duration::from_secs(10),
            |_| Ok(()),
        )
        .await
        .unwrap();
        assert!(
            proc.wait_exit(Duration::from_secs(10)).await,
            "leader exit not noticed"
        );
        let straggler: u32 = std::fs::read_to_string(&marker)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        for _ in 0..50 {
            if !Path::new(&format!("/proc/{straggler}")).exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the straggler outlived the group leader");
    }

    #[tokio::test]
    async fn a_failing_spawn_hook_aborts_the_launch_and_kills_the_process() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("hook.sh");
        std::fs::write(&script, "#!/bin/sh\nsleep 300\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let seen = std::cell::Cell::new(0u32);
        let err = spawn(
            &script,
            &[],
            &BTreeMap::new(),
            Duration::from_secs(10),
            |pid| {
                seen.set(pid);
                Err(Error::Storage("cannot record".into()))
            },
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(err, Error::Storage(_)), "{err:?}");
        assert_ne!(seen.get(), 0);
        assert!(!Path::new(&format!("/proc/{}", seen.get())).exists());
    }
    fn os(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    #[test]
    fn browser_env_keeps_the_allow_list_and_drops_secrets() {
        let parent = os(&[
            ("PATH", "/usr/bin"),
            ("HOME", "/var/lib/worker"),
            ("TMPDIR", "/tmp"),
            ("LANG", "C.UTF-8"),
            ("LC_ALL", "C"),
            ("TZ", "UTC"),
            ("XDG_CONFIG_HOME", "/cfg"),
            ("FONTCONFIG_PATH", "/etc/fonts"),
            ("BROWSERX_DATABASE_PASSWORD", "db-secret"),
            ("BROWSERX_OBJECT_STORE_SECRET_ACCESS_KEY", "s3-secret"),
            ("BROWSERX_OBJECT_STORE_SESSION_TOKEN", "s3-token"),
            ("BROWSERX_EVENTS_PASSWORD", "kafka-secret"),
            ("GITHUB_TOKEN", "ghp_x"),
            ("AWS_SECRET_ACCESS_KEY", "aws"),
            ("HTTPS_PROXY", "http://proxy.invalid:3128"),
            ("LC_", "not a locale category"),
            ("LCX", "x"),
        ]);
        let profile = BTreeMap::from([
            ("TZ".to_owned(), "Europe/Berlin".to_owned()),
            ("CHROME_FLAG".to_owned(), "1".to_owned()),
        ]);
        let env = browser_env(parent, &profile);
        let names: Vec<&str> = env.keys().filter_map(|k| k.to_str()).collect();
        assert_eq!(
            names,
            [
                "CHROME_FLAG",
                "FONTCONFIG_PATH",
                "HOME",
                "LANG",
                "LC_ALL",
                "PATH",
                "TMPDIR",
                "TZ",
                "XDG_CONFIG_HOME"
            ]
        );
        assert_eq!(env[OsStr::new("TZ")], "Europe/Berlin", "profile env wins");
    }

    #[tokio::test]
    async fn the_spawned_browser_does_not_inherit_the_workers_environment() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("environ");
        // `sh -c` instead of a script file: writing and executing files from
        // concurrently running tests can race on `ETXTBSY`.
        let script = format!(
            "tr '\\0' '\\n' < /proc/$$/environ > '{}'; echo 'DevTools listening on ws://127.0.0.1:1/devtools/browser/x' >&2; exec sleep 300",
            out.display()
        );
        let args = ["-c".to_owned(), script];
        // cargo sets these for every test process; a browser must not see them.
        let leaked: Vec<String> = std::env::vars_os()
            .filter_map(|(k, _)| k.into_string().ok())
            .filter(|k| !INHERITED_ENV.contains(&k.as_str()) && !k.starts_with("LC_"))
            .collect();
        assert!(
            leaked.iter().any(|k| k == "CARGO_MANIFEST_DIR"),
            "the test needs a non-allow-listed variable in its own environment"
        );
        let profile = BTreeMap::from([("BX_PROFILE_VAR".to_owned(), "kept".to_owned())]);
        let (proc, _) = spawn(
            Path::new("/bin/sh"),
            &args,
            &profile,
            Duration::from_secs(10),
            |_| Ok(()),
        )
        .await
        .unwrap();
        let dumped = tokio::fs::read_to_string(&out).await.unwrap();
        let names: Vec<&str> = dumped
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, _)| k))
            .collect();
        for k in &leaked {
            assert!(!names.contains(&k.as_str()), "{k} leaked into the browser");
        }
        assert!(names.contains(&"BX_PROFILE_VAR"), "{names:?}");
        assert!(names.contains(&"PATH") || std::env::var_os("PATH").is_none());
        proc.terminate().await.unwrap();
    }
}
