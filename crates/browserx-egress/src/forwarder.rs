//! The loopback forwarder: accept loop, request handling, statistics.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use browserx_core::{Error, ProxyRoute, Result};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::http::{
    AbsoluteTarget, HeadError, RawHead, parse_absolute_http, parse_connect_authority, parse_head,
    read_head,
};
use crate::policy::{CompiledPolicy, EgressPolicy};
use crate::relay::relay;
use crate::upstream::{DialError, Route, Tunnel};

/// Counters since the forwarder started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ForwarderStats {
    /// Tunnels established to a destination (CONNECT tunnels and forwarded plain-HTTP requests).
    pub connections: u64,
    /// Bytes sent from the browser towards the destination.
    pub bytes_up: u64,
    /// Bytes sent from the destination towards the browser.
    pub bytes_down: u64,
    /// Requests refused by the destination policy or the connection limit.
    pub refused: u64,
}

/// Bounds and timeouts. The defaults suit browser traffic.
#[derive(Clone, Debug)]
pub struct ForwarderOptions {
    /// Concurrent client connections served; more receive `503`. Default 512.
    pub max_connections: usize,
    /// Time allowed to establish a tunnel including upstream handshakes. Default 15 s.
    pub connect_timeout: Duration,
    /// Time a client has to send its request head. Default 30 s.
    pub header_timeout: Duration,
    /// A tunnel with no traffic in either direction for this long is closed. Default 300 s.
    pub idle_timeout: Duration,
    /// Largest accepted request or upstream reply head in bytes. Default 16 KiB.
    pub max_header_bytes: usize,
    /// Additional trusted root certificates (PEM) for an `https://` upstream proxy,
    /// for example a private CA. Built-in public roots always apply.
    pub extra_root_pem: Option<String>,
}

impl Default for ForwarderOptions {
    fn default() -> Self {
        Self {
            max_connections: 512,
            connect_timeout: Duration::from_secs(15),
            header_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            max_header_bytes: 16 * 1024,
            extra_root_pem: None,
        }
    }
}

#[derive(Default)]
struct Counters {
    connections: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    refused: AtomicU64,
}

struct Shared {
    route: Route,
    policy: CompiledPolicy,
    options: ForwarderOptions,
    counters: Counters,
}

/// A running loopback forwarder for one session. Stops when shut down or dropped.
pub struct Forwarder {
    addr: SocketAddr,
    shared: Arc<Shared>,
    cancel: CancellationToken,
    tracker: TaskTracker,
}

impl fmt::Debug for Forwarder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Forwarder")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Forwarder {
    /// Starts a forwarder on `127.0.0.1` with an ephemeral port and default bounds.
    ///
    /// `upstream = None` dials destinations directly. `sticky_key` and
    /// `generation` fill the `{session}` and `{generation}` placeholders of the
    /// route's username template.
    pub async fn start(
        upstream: Option<ProxyRoute>,
        sticky_key: String,
        generation: u64,
        policy: EgressPolicy,
    ) -> Result<Self> {
        Self::start_with(
            upstream,
            sticky_key,
            generation,
            policy,
            ForwarderOptions::default(),
        )
        .await
    }

    /// Like [`Self::start`] with explicit bounds.
    pub async fn start_with(
        upstream: Option<ProxyRoute>,
        sticky_key: String,
        generation: u64,
        policy: EgressPolicy,
        options: ForwarderOptions,
    ) -> Result<Self> {
        if options.max_connections == 0
            || options.max_header_bytes < 512
            || options.connect_timeout.is_zero()
            || options.header_timeout.is_zero()
            || options.idle_timeout.is_zero()
        {
            return Err(Error::InvalidRequest(
                "forwarder limits must be positive".into(),
            ));
        }
        let policy = policy.compile()?;
        let route = match &upstream {
            None => Route::direct(options.max_header_bytes),
            Some(r) => Route::from_proxy(
                r,
                &sticky_key,
                generation,
                options.extra_root_pem.as_deref(),
                options.max_header_bytes,
            )?,
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| Error::Egress(format!("cannot bind the loopback forwarder: {e}")))?;
        let addr = listener
            .local_addr()
            .map_err(|e| Error::Egress(format!("cannot read the forwarder address: {e}")))?;
        let semaphore = Arc::new(Semaphore::new(options.max_connections));
        let shared = Arc::new(Shared {
            route,
            policy,
            options,
            counters: Counters::default(),
        });
        let cancel = CancellationToken::new();
        let tracker = TaskTracker::new();
        tracker.spawn(accept_loop(
            listener,
            Arc::clone(&shared),
            cancel.clone(),
            tracker.clone(),
            semaphore,
        ));
        tracing::debug!(%addr, "egress forwarder listening");
        Ok(Self {
            addr,
            shared,
            cancel,
            tracker,
        })
    }

    /// The value for the browser's `--proxy-server` flag: `http://127.0.0.1:<port>`.
    #[must_use]
    pub fn proxy_server(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The bound loopback address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// A snapshot of the counters.
    #[must_use]
    pub fn stats(&self) -> ForwarderStats {
        let c = &self.shared.counters;
        ForwarderStats {
            connections: c.connections.load(Ordering::Relaxed),
            bytes_up: c.bytes_up.load(Ordering::Relaxed),
            bytes_down: c.bytes_down.load(Ordering::Relaxed),
            refused: c.refused.load(Ordering::Relaxed),
        }
    }

    /// Stops accepting, drops every open tunnel and waits for the tasks to end.
    pub async fn shutdown(self) {
        self.cancel.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn accept_loop(
    listener: TcpListener,
    shared: Arc<Shared>,
    cancel: CancellationToken,
    tracker: TaskTracker,
    semaphore: Arc<Semaphore>,
) {
    loop {
        let accepted = tokio::select! {
            () = cancel.cancelled() => break,
            res = listener.accept() => res,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(kind = ?e.kind(), "egress accept failed");
                sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
            shared.counters.refused.fetch_add(1, Ordering::Relaxed);
            // Best effort and non-blocking: the socket buffer of a new connection is empty.
            let _ = stream.try_write(&response_bytes(
                503,
                "Service Unavailable",
                "too many connections",
            ));
            continue;
        };
        let shared = Arc::clone(&shared);
        let cancel = cancel.clone();
        tracker.spawn(async move {
            let _permit = permit;
            tokio::select! {
                () = cancel.cancelled() => {}
                () = serve(&shared, stream) => {}
            }
        });
    }
}

fn response_bytes(status: u16, reason: &str, body: &str) -> Vec<u8> {
    let body = format!("{body}\n");
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

async fn respond(client: &mut TcpStream, wait: Duration, status: u16, reason: &str, body: &str) {
    let bytes = response_bytes(status, reason, body);
    let _ = timeout(wait, async {
        client.write_all(&bytes).await?;
        client.shutdown().await
    })
    .await;
}

async fn serve(shared: &Shared, mut client: TcpStream) {
    let opts = &shared.options;
    let mut buf = Vec::with_capacity(2048);
    let head_len = match timeout(
        opts.header_timeout,
        read_head(&mut client, &mut buf, opts.max_header_bytes),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(HeadError::TooLarge)) => {
            respond(
                &mut client,
                opts.header_timeout,
                431,
                "Request Header Fields Too Large",
                "request head too large",
            )
            .await;
            return;
        }
        Ok(Err(HeadError::Bad(why))) => {
            respond(&mut client, opts.header_timeout, 400, "Bad Request", why).await;
            return;
        }
        Ok(Err(HeadError::Closed | HeadError::Io)) => return,
        Err(_) => {
            respond(
                &mut client,
                opts.header_timeout,
                408,
                "Request Timeout",
                "request head not received in time",
            )
            .await;
            return;
        }
    };
    let head = match parse_head(&buf[..head_len]) {
        Ok(h) => h,
        Err(HeadError::Bad(why)) => {
            respond(&mut client, opts.header_timeout, 400, "Bad Request", why).await;
            return;
        }
        Err(_) => return,
    };
    let client_bytes = buf.split_off(head_len);

    if head.method == "CONNECT" {
        let (host, port) = match parse_connect_authority(&head.target) {
            Ok(t) => t,
            Err(why) => {
                respond(&mut client, opts.header_timeout, 400, "Bad Request", why).await;
                return;
            }
        };
        let Some(tunnel) = open_tunnel(shared, &mut client, &host, port).await else {
            return;
        };
        let Tunnel { mut io, leftover } = tunnel;
        let preface = timeout(opts.header_timeout, async {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            if !leftover.is_empty() {
                client.write_all(&leftover).await?;
            }
            if !client_bytes.is_empty() {
                io.write_all(&client_bytes).await?;
            }
            Ok::<(), std::io::Error>(())
        })
        .await;
        if !matches!(preface, Ok(Ok(()))) {
            return;
        }
        add(&shared.counters.bytes_down, leftover.len());
        add(&shared.counters.bytes_up, client_bytes.len());
        let end = relay(
            client,
            io,
            &shared.counters.bytes_up,
            &shared.counters.bytes_down,
            opts.idle_timeout,
        )
        .await;
        tracing::trace!(?end, "tunnel closed");
        return;
    }

    let target = match parse_absolute_http(&head.target) {
        Ok(t) => t,
        Err(why) => {
            respond(&mut client, opts.header_timeout, 400, "Bad Request", why).await;
            return;
        }
    };
    let Some(tunnel) = open_tunnel(shared, &mut client, &target.host, target.port).await else {
        return;
    };
    let Tunnel { mut io, leftover } = tunnel;
    let request = plain_request(&head, &target);
    let preface = timeout(opts.header_timeout, async {
        io.write_all(&request).await?;
        if !client_bytes.is_empty() {
            io.write_all(&client_bytes).await?;
        }
        if !leftover.is_empty() {
            client.write_all(&leftover).await?;
        }
        Ok::<(), std::io::Error>(())
    })
    .await;
    if !matches!(preface, Ok(Ok(()))) {
        return;
    }
    add(
        &shared.counters.bytes_up,
        request.len() + client_bytes.len(),
    );
    add(&shared.counters.bytes_down, leftover.len());
    let end = relay(
        client,
        io,
        &shared.counters.bytes_up,
        &shared.counters.bytes_down,
        opts.idle_timeout,
    )
    .await;
    tracing::trace!(?end, "plain request finished");
}

fn add(counter: &AtomicU64, n: usize) {
    counter.fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
}

/// Dials the destination; on failure answers the client and returns `None`.
async fn open_tunnel(
    shared: &Shared,
    client: &mut TcpStream,
    host: &crate::http::Host,
    port: u16,
) -> Option<Tunnel> {
    let opts = &shared.options;
    let outcome = timeout(
        opts.connect_timeout,
        shared.route.dial(host, port, &shared.policy),
    )
    .await;
    let error = match outcome {
        Ok(Ok(tunnel)) => {
            shared.counters.connections.fetch_add(1, Ordering::Relaxed);
            return Some(tunnel);
        }
        Ok(Err(e)) => e,
        Err(_) => DialError::Timeout,
    };
    match error {
        DialError::Refused(why) => {
            shared.counters.refused.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(reason = %why, "egress destination refused");
            respond(
                client,
                opts.header_timeout,
                403,
                "Forbidden",
                &format!("blocked by egress policy: {why}"),
            )
            .await;
        }
        DialError::Unreachable(why) | DialError::Upstream(why) => {
            tracing::debug!(reason = %why, "egress dial failed");
            respond(client, opts.header_timeout, 502, "Bad Gateway", &why).await;
        }
        DialError::Timeout => {
            tracing::debug!("egress dial timed out");
            respond(
                client,
                opts.header_timeout,
                504,
                "Gateway Timeout",
                "timed out connecting to the destination",
            )
            .await;
        }
    }
    None
}

/// Rewrites an absolute-form request to origin-form for the destination.
///
/// The `Host` header is replaced by the target authority so it cannot disagree
/// with where the request goes. Hop-by-hop and proxy headers are dropped and the
/// connection is closed after the response (one request per proxy connection),
/// except for protocol upgrades, which keep their `Connection`/`Upgrade` pair.
fn plain_request(head: &RawHead, target: &AbsoluteTarget) -> Vec<u8> {
    let named_in_connection: Vec<String> = head
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| {
            String::from_utf8_lossy(v)
                .split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .filter(|t| !t.is_empty())
        .collect();
    let has_upgrade_header = head
        .headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("upgrade"));
    let upgrade = has_upgrade_header && named_in_connection.iter().any(|t| t == "upgrade");

    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\n",
            head.method, target.path, target.host_header
        )
        .as_bytes(),
    );
    for (name, value) in &head.headers {
        let lname = name.to_ascii_lowercase();
        let hop = matches!(
            lname.as_str(),
            "host" | "proxy-connection" | "proxy-authorization" | "keep-alive"
        );
        let named =
            lname != "upgrade" && lname != "connection" && named_in_connection.contains(&lname);
        let pair = lname == "connection" || lname == "upgrade";
        if hop || named || (pair && !upgrade) {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    if !upgrade {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::http::{parse_absolute_http, parse_head};

    fn rewrite(raw: &str) -> String {
        let head = parse_head(raw.as_bytes()).unwrap();
        let target = parse_absolute_http(&head.target).unwrap();
        String::from_utf8(plain_request(&head, &target)).unwrap()
    }

    #[test]
    fn rewrites_to_origin_form() {
        let out = rewrite(
            "GET http://Origin.test:8080/a?b=1 HTTP/1.1\r\nHost: evil.test\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic eA==\r\nAccept: */*\r\nX-Trace: 1\r\n\r\n",
        );
        assert_eq!(
            out,
            "GET /a?b=1 HTTP/1.1\r\nHost: origin.test:8080\r\nAccept: */*\r\nX-Trace: 1\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn connection_named_headers_are_dropped() {
        let out = rewrite(
            "GET http://o.test/ HTTP/1.1\r\nConnection: keep-alive, X-Hop\r\nX-Hop: 1\r\nX-Keep: 2\r\n\r\n",
        );
        assert!(!out.contains("X-Hop"));
        assert!(out.contains("X-Keep: 2"));
        assert!(out.ends_with("Connection: close\r\n\r\n"));
        assert_eq!(out.matches("Connection:").count(), 1);
    }

    #[test]
    fn upgrades_keep_their_headers() {
        let out = rewrite(
            "GET http://o.test/ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        );
        assert!(out.contains("Connection: Upgrade\r\n"));
        assert!(out.contains("Upgrade: websocket\r\n"));
        assert!(!out.contains("close"));
    }
}
