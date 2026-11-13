//! The authenticated CDP WebSocket relay.
//!
//! `GET /cdp/{session_id}/{token}` upgrades to a WebSocket that is connected to
//! the browser-level DevTools endpoint of the session's browser. Dedicated
//! sessions get a byte relay; shared sessions get the scoped filter. The route
//! carries the credential in its path, so request paths are never logged.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message as ClientMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::Response;
use browserx_core::{Generation, Isolation, LeaseToken, SessionId};
use browserx_pool::{PoolEventKind, RelayAccess};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::tungstenite::Message as UpstreamMessage;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::api::AppState;
use crate::error::ApiError;
use crate::scope::{ClientAction, ScopedFilter};

/// Largest WebSocket message accepted on either side.
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
    let id = SessionId::parse(&session)?;
    let token = LeaseToken::from_client(token);
    let (_info, access) = app.pool().open_relay(id, &token).await?;
    Ok(ws
        .max_message_size(MAX_MESSAGE_BYTES)
        .max_frame_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| relay_main(app, socket, access)))
}

async fn relay_main(app: AppState, mut socket: WebSocket, access: RelayAccess) {
    let RelayAccess {
        session_id,
        generation,
        isolation,
        ws_url,
        context,
        guard,
    } = access;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
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
    let filter = match (isolation, context) {
        (Isolation::SharedBrowser, Some(ctx)) => Some(Mutex::new(ScopedFilter::new(ctx.0))),
        (Isolation::SharedBrowser, None) => {
            tracing::error!(session = %session_id, "shared session without a browser context");
            let _ = socket.send(ClientMessage::Close(None)).await;
            return;
        }
        (Isolation::DedicatedBrowser, _) => None,
    };
    tracing::debug!(session = %session_id, scoped = filter.is_some(), "relay open");
    let stop = must_stop(&app, session_id, generation);
    pump(socket, upstream, filter, stop).await;
    tracing::debug!(session = %session_id, "relay closed");
    drop(guard);
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
    filter: Option<Mutex<ScopedFilter>>,
    stop: impl Future<Output = ()>,
) {
    let (mut client_tx, mut client_rx) = socket.split();
    let (mut up_tx, mut up_rx) = upstream.split();
    let (reply_tx, mut reply_rx) = mpsc::channel::<String>(REPLY_QUEUE);
    let started = Instant::now();
    let last_client_frame = AtomicU64::new(0);
    let filter = &filter;

    let to_browser = async {
        while let Some(Ok(frame)) = client_rx.next().await {
            last_client_frame.store(elapsed_ms(started), Ordering::Relaxed);
            let sent = match frame {
                ClientMessage::Text(text) => match filter {
                    None => up_tx
                        .send(UpstreamMessage::text(text.as_str()))
                        .await
                        .is_ok(),
                    Some(f) => {
                        let action = match f.lock() {
                            Ok(mut guard) => guard.client_message(text.as_str()),
                            Err(_) => ClientAction::Drop,
                        };
                        match action {
                            ClientAction::Forward(out) => {
                                up_tx.send(UpstreamMessage::text(out)).await.is_ok()
                            }
                            ClientAction::Reply(out) => reply_tx.send(out).await.is_ok(),
                            ClientAction::Drop => true,
                        }
                    }
                },
                ClientMessage::Binary(data) if filter.is_none() => {
                    up_tx.send(UpstreamMessage::Binary(data)).await.is_ok()
                }
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
                        UpstreamMessage::Text(text) => match filter {
                            None => Some(ClientMessage::text(text.as_str())),
                            Some(f) => match f.lock() {
                                Ok(mut guard) => guard.browser_message(text.as_str()).map(ClientMessage::text),
                                Err(_) => None,
                            },
                        },
                        UpstreamMessage::Binary(data) if filter.is_none() => Some(ClientMessage::Binary(data)),
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
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        up_tx.send(UpstreamMessage::Close(None)),
    )
    .await;
}

fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}
