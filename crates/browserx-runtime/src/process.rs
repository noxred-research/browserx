//! Spawning and supervising one browser process group.

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use browserx_core::{Error, Result};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
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

/// How the process ended.
#[derive(Clone, Debug)]
pub(crate) struct ExitInfo(pub String);

/// A supervised browser process group.
///
/// A background task owns the child, reaps it, and then SIGKILLs any stragglers
/// in its process group (renderers, zygotes). Dropping a `Proc` whose leader is
/// still alive kills the whole group.
pub(crate) struct Proc {
    pid: u32,
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

    fn signal_group(&self, signal: Signal) {
        let Ok(raw) = i32::try_from(self.pid) else {
            return;
        };
        // ESRCH means the group is already gone.
        let _ = killpg(Pid::from_raw(raw), Some(signal));
    }

    /// SIGTERM the group, then SIGKILL it, waiting for the leader to be reaped.
    pub(crate) async fn terminate(&self) -> Result<()> {
        if self.exited().is_some() {
            return Ok(());
        }
        self.signal_group(Signal::SIGTERM);
        if self.wait_exit(SIGNAL_GRACE).await {
            return Ok(());
        }
        self.signal_group(Signal::SIGKILL);
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
        // Only while the leader is unreaped is the process group id guaranteed
        // to still be ours.
        if self.exited().is_none() {
            self.signal_group(Signal::SIGKILL);
        }
        self.drain.abort();
    }
}

/// Starts the browser and waits for its DevTools endpoint on stderr.
///
/// On failure the process group is terminated before the error is returned.
pub(crate) async fn spawn(
    executable: &Path,
    args: &[String],
    env: &BTreeMap<String, String>,
    startup: Duration,
) -> Result<(Proc, String)> {
    let mut child = Command::new(executable)
        .args(args)
        .envs(env)
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

    let (exit_tx, exit_rx) = watch::channel(None);
    tokio::spawn(async move {
        let outcome = match child.wait().await {
            Ok(status) => format!("{status}"),
            Err(err) => format!("wait failed: {err}"),
        };
        if let Ok(raw) = i32::try_from(pid) {
            // Sweep stragglers of the group; ESRCH when there are none.
            let _ = killpg(Pid::from_raw(raw), Some(Signal::SIGKILL));
        }
        // The receiver side may be gone already.
        let _ = exit_tx.send(Some(ExitInfo(outcome)));
    });

    let (url_tx, url_rx) = oneshot::channel();
    let tail = Arc::new(Mutex::new(VecDeque::new()));
    let drain = tokio::spawn(drain_stderr(stderr, url_tx, tail.clone()));
    let proc = Proc {
        pid,
        exit: exit_rx,
        drain,
    };

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
}
