//! Bidirectional byte relay with shared idle timeout and live byte counters.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, sleep, timeout};

const CHUNK: usize = 16 * 1024;

/// Last-activity clock shared by both directions of one tunnel.
struct Activity {
    base: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn touch(&self) {
        self.last_ms.store(self.elapsed_ms(), Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        Duration::from_millis(
            self.elapsed_ms()
                .saturating_sub(self.last_ms.load(Ordering::Relaxed)),
        )
    }
}

/// Why a relay ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RelayEnd {
    /// Both directions reached end-of-stream.
    Closed,
    /// No bytes moved in either direction for the idle limit.
    Idle,
    /// A read or write failed.
    Error,
}

/// Copies both ways until both sides finish, one side fails, or the tunnel is idle.
///
/// `up` counts bytes from the client to the upstream, `down` the reverse. One
/// side closing its write half is propagated as a half-close, so protocols that
/// send a request then wait for a reply keep working.
pub(crate) async fn relay<C, U>(
    client: C,
    upstream: U,
    up: &AtomicU64,
    down: &AtomicU64,
    idle: Duration,
) -> RelayEnd
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Activity::new();
    let (client_r, client_w) = tokio::io::split(client);
    let (upstream_r, upstream_w) = tokio::io::split(upstream);
    let upward = pump(client_r, upstream_w, up, &activity, idle);
    let downward = pump(upstream_r, client_w, down, &activity, idle);
    tokio::pin!(upward, downward);
    let (mut up_done, mut down_done) = (false, false);
    loop {
        tokio::select! {
            res = &mut upward, if !up_done => match res {
                Ok(()) => up_done = true,
                Err(end) => return end,
            },
            res = &mut downward, if !down_done => match res {
                Ok(()) => down_done = true,
                Err(end) => return end,
            },
        }
        if up_done && down_done {
            return RelayEnd::Closed;
        }
    }
}

async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    counter: &AtomicU64,
    activity: &Activity,
    idle: Duration,
) -> Result<(), RelayEnd>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; CHUNK];
    loop {
        let wait = idle.saturating_sub(activity.idle_for());
        tokio::select! {
            read = reader.read(&mut buf) => {
                let n = read.map_err(|_| RelayEnd::Error)?;
                if n == 0 {
                    // Half-close: the peer finished sending. Ignore shutdown errors;
                    // the other direction decides how the tunnel ends.
                    let _ = writer.shutdown().await;
                    return Ok(());
                }
                activity.touch();
                match timeout(idle, writer.write_all(&buf[..n])).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => return Err(RelayEnd::Error),
                    Err(_) => return Err(RelayEnd::Idle),
                }
                counter.fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
                activity.touch();
            }
            () = sleep(wait) => {
                if activity.idle_for() >= idle {
                    return Err(RelayEnd::Idle);
                }
            }
        }
    }
}
