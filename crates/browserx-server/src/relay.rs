//! The authenticated CDP WebSocket relay.
//!
//! `GET /cdp/{session_id}/{token}` upgrades to a WebSocket that is connected to
//! the browser-level DevTools endpoint of the session's browser. Both kinds of
//! session get the host-protection policy ([`crate::host_policy`]); shared
//! sessions additionally get the scoped filter ([`crate::scope`]). The route
//! carries the credential in its path, so request paths are never logged.
//! A bad token and an unknown session are indistinguishable: both answer `401`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message as ClientMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::Response;
use browserx_core::{Error, Generation, Isolation, LeaseToken, SessionId};
use browserx_pool::{PoolEventKind, RelayAccess};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::tungstenite::Message as UpstreamMessage;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::api::AppState;
use crate::error::ApiError;
use crate::host_policy::{DedicatedFilter, HostPolicy};
pub(crate) use crate::limits::RelayHub;
use crate::limits::RelaySlot;
use crate::scope::{ClientAction, ScopedFilter};

/// Largest WebSocket message accepted on a dedicated-session relay. Shared
/// sessions use the (lower) configured `scoped_relay_max_message_bytes`.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const PING_INTERVAL: Duration = Duration::from_secs(30);
const CLIENT_IDLE_LIMIT: Duration = Duration::from_secs(120);
const VALIDITY_POLL: Duration = Duration::from_secs(5);
const REPLY_QUEUE: usize = 64;

pub(crate) async fn cdp_ws(
    State(app): State<AppState>,
    Path((session, token)): Path<(String, String)>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let Ok(id) = SessionId::parse(&session) else {
        return Err(Error::Unauthorized.into());
    };
    let token = LeaseToken::from_client(token);
    let (_info, access) = match app.pool().open_relay(id, &token).await {
        Ok(opened) => opened,
        // Whatever went wrong before the token matched looks the same.
        Err(Error::NotFound(_) | Error::Forbidden(_) | Error::InvalidRequest(_)) => {
            return Err(Error::Unauthorized.into());
        }
        Err(e) => return Err(e.into()),
    };
    // On refusal `access` drops here and the session settles back to idle.
    let slot = app.acquire_relay_slot(id)?;
    let max = match access.isolation {
        Isolation::SharedBrowser => app.limits().scoped_relay_max_message_bytes,
        Isolation::DedicatedBrowser => MAX_MESSAGE_BYTES,
    };
    Ok(ws
        .max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| relay_main(app, socket, access, slot, max)))
}

/// The per-connection filter: host protection for dedicated sessions, host
/// protection plus scoping for shared ones.
enum Filter {
    Dedicated(DedicatedFilter),
    Scoped(Box<Mutex<ScopedFilter>>),
}

/// What to do with a message from the browser.
struct BrowserOut {
    deliver: Option<String>,
    upstream: Vec<String>,
}

impl Filter {
    fn client(&self, text: &str) -> ClientAction {
        match self {
            Self::Dedicated(f) => f.client_message(text),
            Self::Scoped(f) => match f.lock() {
                Ok(mut guard) => guard.client_message(text),
                Err(_) => ClientAction::Drop,
            },
        }
    }

    fn browser(&self, text: &str) -> BrowserOut {
        match self {
            Self::Dedicated(_) => BrowserOut {
                deliver: Some(text.to_owned()),
                upstream: Vec::new(),
            },
            Self::Scoped(f) => match f.lock() {
                Ok(mut guard) => {
                    let deliver = guard.browser_message(text);
                    BrowserOut {
                        deliver,
                        upstream: guard.take_upstream(),
                    }
                }
                Err(_) => BrowserOut {
                    deliver: None,
                    upstream: Vec::new(),
                },
            },
        }
    }

    /// Binary frames cannot be inspected (the browser would read them as CBOR),
    /// so they never travel from the client to the browser.
    fn passes_binary_to_client(&self) -> bool {
        matches!(self, Self::Dedicated(_))
    }
}

async fn relay_main(
    app: AppState,
    mut socket: WebSocket,
    access: RelayAccess,
    slot: RelaySlot,
    max_message: usize,
) {
    let RelayAccess {
        session_id,
        generation,
        isolation,
        ws_url,
        context,
        guard,
    } = access;
    let config = WebSocketConfig::default()
        .max_message_size(Some(max_message))
        .max_frame_size(Some(max_message));
    let upstream = match tokio_tungstenite::connect_async_with_config(&ws_url, Some(config), false)
        .await
    {
        Ok((upstream, _)) => upstream,
        Err(e) => {
            tracing::warn!(session = %session_id, error = %e, "relay could not reach the browser");
            let _ = socket.send(ClientMessage::Close(None)).await;
            return;
        }
    };
    let download_dir = app.limits().download_root.join(session_id.prefixed());
    let policy = HostPolicy::new(download_dir.clone());
    let filter = match (isolation, context) {
        (Isolation::SharedBrowser, Some(ctx)) => {
            Filter::Scoped(Box::new(Mutex::new(ScopedFilter::new(ctx.0, policy))))
        }
        (Isolation::SharedBrowser, None) => {
            tracing::error!(session = %session_id, "shared session without a browser context");
            let _ = socket.send(ClientMessage::Close(None)).await;
            return;
        }
        (Isolation::DedicatedBrowser, _) => Filter::Dedicated(DedicatedFilter::new(policy)),
    };
    tracing::debug!(
        session = %session_id,
        scoped = matches!(filter, Filter::Scoped(_)),
        "relay open"
    );
    let stop = must_stop(&app, session_id, generation);
    pump(socket, upstream, &filter, stop).await;
    tracing::debug!(session = %session_id, "relay closed");
    drop(guard);
    if slot.release()
        && let Err(e) = tokio::fs::remove_dir_all(&download_dir).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(session = %session_id, error = %e, "could not remove the session download directory");
    }
}

/// Resolves when the relay must close: handoff, recovery, release, loss or process shutdown.
async fn must_stop(app: &AppState, id: SessionId, generation: Generation) {
    let mut events = app.pool().subscribe();
    let mut poll = tokio::time::interval(VALIDITY_POLL);
    loop {
        tokio::select! {
            () = app.inner.relay_stop.cancelled() => return,
            _ = poll.tick() => {
                if !app.pool().relay_valid(id, generation).await {
                    return;
                }
            }
            event = events.recv() => match event {
                Ok(e) if e.session_id == id && matches!(
                    e.kind,
                    PoolEventKind::HandedOff
                        | PoolEventKind::Recovering
                        | PoolEventKind::Recovered
                        | PoolEventKind::Draining
                        | PoolEventKind::Closed
                        | PoolEventKind::Lost
                ) => return,
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if !app.pool().relay_valid(id, generation).await {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
        }
    }
}

type Upstream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn pump(
    socket: WebSocket,
    upstream: Upstream,
    filter: &Filter,
    stop: impl Future<Output = ()>,
) {
    let (mut client_tx, mut client_rx) = socket.split();
    let (up_tx, mut up_rx) = upstream.split();
    let up_tx = tokio::sync::Mutex::new(up_tx);
    let (reply_tx, mut reply_rx) = mpsc::channel::<String>(REPLY_QUEUE);
    let started = Instant::now();
    let last_client_frame = AtomicU64::new(0);

    let to_browser = async {
        while let Some(Ok(frame)) = client_rx.next().await {
            last_client_frame.store(elapsed_ms(started), Ordering::Relaxed);
            let sent = match frame {
                ClientMessage::Text(text) => match filter.client(text.as_str()) {
                    ClientAction::Forward(out) => up_tx
                        .lock()
                        .await
                        .send(UpstreamMessage::text(out))
                        .await
                        .is_ok(),
                    ClientAction::Reply(out) => reply_tx.send(out).await.is_ok(),
                    ClientAction::Drop => true,
                },
                ClientMessage::Close(_) => false,
                ClientMessage::Binary(_) | ClientMessage::Ping(_) | ClientMessage::Pong(_) => true,
            };
            if !sent {
                break;
            }
        }
    };

    let to_client = async {
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;
        loop {
            tokio::select! {
                frame = up_rx.next() => {
                    let Some(Ok(frame)) = frame else { break };
                    let out = match frame {
                        UpstreamMessage::Text(text) => {
                            let outcome = filter.browser(text.as_str());
                            let mut failed = false;
                            for command in outcome.upstream {
                                if up_tx.lock().await.send(UpstreamMessage::text(command)).await.is_err() {
                                    failed = true;
                                    break;
                                }
                            }
                            if failed {
                                break;
                            }
                            outcome.deliver.map(ClientMessage::text)
                        }
                        UpstreamMessage::Binary(data) if filter.passes_binary_to_client() => {
                            Some(ClientMessage::Binary(data))
                        }
                        UpstreamMessage::Close(_) => break,
                        _ => None,
                    };
                    if let Some(out) = out
                        && client_tx.send(out).await.is_err() {
                            break;
                        }
                }
                Some(reply) = reply_rx.recv() => {
                    if client_tx.send(ClientMessage::text(reply)).await.is_err() {
                        break;
                    }
                }
                _ = ping.tick() => {
                    let idle_ms = elapsed_ms(started).saturating_sub(last_client_frame.load(Ordering::Relaxed));
                    if Duration::from_millis(idle_ms) > CLIENT_IDLE_LIMIT {
                        break;
                    }
                    if client_tx.send(ClientMessage::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    };

    tokio::select! {
        () = to_browser => {}
        () = to_client => {}
        () = stop => {}
    }
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        client_tx.send(ClientMessage::Close(None)),
    )
    .await;
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        up_tx.lock().await.send(UpstreamMessage::Close(None)).await
    })
    .await;
}

fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}
