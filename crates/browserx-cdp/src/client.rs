//! The multiplexing client.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::connect_async_with_config;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_util::sync::CancellationToken;

use crate::error::CdpError;

/// Frames queued towards the writer task.
const OUTBOUND_QUEUE: usize = 256;
/// How long `close` waits for the background tasks to finish.
const CLOSE_GRACE: Duration = Duration::from_secs(3);
/// How long the reader waits for the peer's close reply after a local close.
const CLOSE_REPLY_WAIT: Duration = Duration::from_secs(1);

/// Resource bounds of one [`CdpClient`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CdpLimits {
    /// Per-command reply deadline (also bounds the WebSocket handshake). Default 30 s.
    pub command_timeout: Duration,
    /// Largest message accepted from, or sent to, the browser. Default 64 MiB.
    pub max_message_bytes: usize,
    /// Commands allowed to await a reply at once. Default 1024.
    pub max_pending: usize,
    /// Events buffered per subscriber before the oldest are dropped. Default 1024.
    pub event_buffer: usize,
}

impl Default for CdpLimits {
    fn default() -> Self {
        Self {
            command_timeout: Duration::from_secs(30),
            max_message_bytes: 64 * 1024 * 1024,
            max_pending: 1024,
            event_buffer: 1024,
        }
    }
}

/// A protocol event pushed by the browser.
#[derive(Clone, Debug, PartialEq)]
pub struct CdpEvent {
    /// Event name, e.g. `Target.targetCreated`.
    pub method: String,
    /// Event parameters (`null` when the browser sent none).
    pub params: Value,
    /// Flattened session the event belongs to; `None` for browser-level events.
    pub session_id: Option<String>,
}

#[derive(Clone, Debug)]
enum CloseReason {
    Local,
    Remote,
    MessageTooLarge(usize),
    Transport(String),
}

impl CloseReason {
    fn to_error(&self) -> CdpError {
        match self {
            Self::Local => CdpError::Closed("closed locally".into()),
            Self::Remote => CdpError::Closed("closed by the browser".into()),
            Self::MessageTooLarge(limit) => CdpError::MessageTooLarge { limit: *limit },
            Self::Transport(detail) => CdpError::Closed(detail.clone()),
        }
    }
}

type Reply = oneshot::Sender<Result<Value, CdpError>>;

struct State {
    closed: Option<CloseReason>,
    pending: HashMap<u64, Reply>,
}

struct Shared {
    state: Mutex<State>,
    events: broadcast::Sender<CdpEvent>,
    cancel: CancellationToken,
    max_message_bytes: usize,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Marks the connection closed (first reason wins), fails every pending call
    /// and stops both background tasks.
    fn terminate(&self, reason: CloseReason) {
        let (reason, drained) = {
            let mut state = self.lock();
            let reason = state.closed.get_or_insert(reason).clone();
            (reason, std::mem::take(&mut state.pending))
        };
        for (_, reply) in drained {
            // The caller may already have given up; nothing to do then.
            let _ = reply.send(Err(reason.to_error()));
        }
        self.cancel.cancel();
    }

    fn take_pending(&self, id: u64) -> Option<Reply> {
        self.lock().pending.remove(&id)
    }
}

/// Removes a pending entry when its call future ends, however it ends.
struct PendingGuard<'a> {
    shared: &'a Shared,
    id: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        drop(self.shared.take_pending(self.id));
    }
}

struct Inner {
    shared: Arc<Shared>,
    outbound: mpsc::Sender<Message>,
    next_id: AtomicU64,
    limits: CdpLimits,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.shared.terminate(CloseReason::Local);
    }
}

/// A connection to one CDP endpoint. Cheap to clone; clones share the connection.
#[derive(Clone)]
pub struct CdpClient {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for CdpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CdpClient")
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Incoming {
    id: Option<u64>,
    result: Option<Value>,
    error: Option<ProtocolError>,
    method: Option<String>,
    params: Option<Value>,
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
}

#[derive(Deserialize)]
struct ProtocolError {
    code: i64,
    message: String,
}

impl CdpClient {
    /// Opens the WebSocket (`ws://…`) and starts the reader and writer tasks.
    ///
    /// The URL is never included in error messages: browser-level endpoints are
    /// credentials.
    pub async fn connect(ws_url: &str, limits: CdpLimits) -> Result<Self, CdpError> {
        let max = limits.max_message_bytes.max(1);
        let config = WebSocketConfig::default()
            .max_message_size(Some(max))
            .max_frame_size(Some(max));
        let (ws, _response) = tokio::time::timeout(
            limits.command_timeout,
            connect_async_with_config(ws_url, Some(config), true),
        )
        .await
        .map_err(|_| CdpError::Connect("handshake timed out".into()))?
        .map_err(|e| CdpError::Connect(e.to_string()))?;
        let (sink, stream) = ws.split();

        let (events, _) = broadcast::channel(limits.event_buffer.max(1));
        let (outbound, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                closed: None,
                pending: HashMap::new(),
            }),
            events,
            cancel: CancellationToken::new(),
            max_message_bytes: max,
        });

        let reader = tokio::spawn(read_loop(shared.clone(), stream));
        let writer = tokio::spawn(write_loop(shared.clone(), sink, outbound_rx));
        Ok(Self {
            inner: Arc::new(Inner {
                shared,
                outbound,
                next_id: AtomicU64::new(1),
                limits,
                tasks: Mutex::new(vec![reader, writer]),
            }),
        })
    }

    /// Sends one command and waits for its reply.
    ///
    /// `session_id` routes the command to a flattened target session. Fails with
    /// [`CdpError::TooManyPending`] when `max_pending` calls are already in
    /// flight, [`CdpError::Timeout`] when no reply arrives in time, and
    /// [`CdpError::Closed`] when the connection ends first.
    pub async fn call(
        &self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> Result<Value, CdpError> {
        let inner = &*self.inner;
        let id = inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut state = inner.shared.lock();
            if let Some(reason) = &state.closed {
                return Err(reason.to_error());
            }
            if state.pending.len() >= inner.limits.max_pending {
                return Err(CdpError::TooManyPending {
                    limit: inner.limits.max_pending,
                });
            }
            state.pending.insert(id, tx);
        }
        let _guard = PendingGuard {
            shared: &inner.shared,
            id,
        };

        let mut command = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session_id {
            command["sessionId"] = Value::String(session.to_owned());
        }
        let text = serde_json::to_string(&command).map_err(|e| CdpError::Encode(e.to_string()))?;
        if text.len() > inner.limits.max_message_bytes {
            return Err(CdpError::MessageTooLarge {
                limit: inner.limits.max_message_bytes,
            });
        }

        let exchange = async {
            if inner.outbound.send(Message::text(text)).await.is_err() {
                return Err(self.closed_error());
            }
            match rx.await {
                Ok(reply) => reply,
                Err(_) => Err(self.closed_error()),
            }
        };
        match tokio::time::timeout(inner.limits.command_timeout, exchange).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(CdpError::Protocol { code, message, .. })) => Err(CdpError::Protocol {
                method: method.to_owned(),
                code,
                message,
            }),
            Ok(Err(other)) => Err(other),
            Err(_) => Err(CdpError::Timeout {
                method: method.to_owned(),
                timeout: inner.limits.command_timeout,
            }),
        }
    }

    /// Subscribes to events. Each receiver sees every event sent after it was
    /// created; a slow receiver loses the oldest events (`RecvError::Lagged`).
    #[must_use]
    pub fn events(&self) -> broadcast::Receiver<CdpEvent> {
        self.inner.shared.events.subscribe()
    }

    /// True once the connection has ended for any reason.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.shared.lock().closed.is_some()
    }

    /// Closes the connection: sends a WebSocket close frame, fails pending calls
    /// and waits (bounded) for the background tasks. Idempotent.
    pub async fn close(&self) {
        self.inner.shared.terminate(CloseReason::Local);
        let tasks = {
            let mut tasks = self
                .inner
                .tasks
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *tasks)
        };
        let join_all = async {
            for task in tasks {
                // A panicked task has nothing left to clean up.
                let _ = task.await;
            }
        };
        if tokio::time::timeout(CLOSE_GRACE, join_all).await.is_err() {
            tracing::warn!("cdp background tasks did not stop within the grace period");
        }
    }

    fn closed_error(&self) -> CdpError {
        self.inner.shared.lock().closed.as_ref().map_or_else(
            || CdpError::Closed("connection ended".into()),
            CloseReason::to_error,
        )
    }
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn read_loop(shared: Arc<Shared>, mut stream: futures_util::stream::SplitStream<WsStream>) {
    loop {
        let next = tokio::select! {
            biased;
            () = shared.cancel.cancelled() => break,
            next = stream.next() => next,
        };
        match next {
            Some(Ok(Message::Text(text))) => {
                if text.len() > shared.max_message_bytes {
                    shared.terminate(CloseReason::MessageTooLarge(shared.max_message_bytes));
                    break;
                }
                dispatch(&shared, text.as_str());
            }
            Some(Ok(Message::Close(_))) | None => {
                shared.terminate(CloseReason::Remote);
                break;
            }
            Some(Ok(_)) => {}
            Some(Err(tungstenite::Error::Capacity(_))) => {
                shared.terminate(CloseReason::MessageTooLarge(shared.max_message_bytes));
                break;
            }
            Some(Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed)) => {
                shared.terminate(CloseReason::Remote);
                break;
            }
            Some(Err(err)) => {
                shared.terminate(CloseReason::Transport(err.to_string()));
                break;
            }
        }
    }
    // After a local close, give the peer a moment to answer the close frame so
    // the handshake finishes cleanly.
    if shared
        .lock()
        .closed
        .as_ref()
        .is_some_and(|r| matches!(r, CloseReason::Local))
    {
        let drain = async {
            while let Some(Ok(message)) = stream.next().await {
                if message.is_close() {
                    break;
                }
            }
        };
        let _ = tokio::time::timeout(CLOSE_REPLY_WAIT, drain).await;
    }
}

fn dispatch(shared: &Shared, text: &str) {
    let incoming: Incoming = match serde_json::from_str(text) {
        Ok(incoming) => incoming,
        Err(err) => {
            tracing::warn!(error = %err, "ignoring undecodable cdp message");
            return;
        }
    };
    if let Some(id) = incoming.id {
        let Some(reply) = shared.take_pending(id) else {
            // Late reply to a call that already timed out or was cancelled.
            return;
        };
        let outcome = match incoming.error {
            Some(error) => Err(CdpError::Protocol {
                method: String::new(),
                code: error.code,
                message: error.message,
            }),
            None => Ok(incoming.result.unwrap_or(Value::Null)),
        };
        // The caller may have just timed out; the reply is then dropped.
        let _ = reply.send(outcome);
    } else if let Some(method) = incoming.method {
        // No subscribers is normal.
        let _ = shared.events.send(CdpEvent {
            method,
            params: incoming.params.unwrap_or(Value::Null),
            session_id: incoming.session_id,
        });
    }
}

async fn write_loop(
    shared: Arc<Shared>,
    mut sink: futures_util::stream::SplitSink<WsStream, Message>,
    mut outbound: mpsc::Receiver<Message>,
) {
    loop {
        tokio::select! {
            biased;
            () = shared.cancel.cancelled() => {
                // Best effort: the peer may already be gone.
                let _ = tokio::time::timeout(CLOSE_REPLY_WAIT, sink.send(Message::Close(None))).await;
                break;
            }
            message = outbound.recv() => match message {
                Some(message) => {
                    if let Err(err) = sink.send(message).await {
                        shared.terminate(CloseReason::Transport(err.to_string()));
                        break;
                    }
                }
                None => break,
            },
        }
    }
}

#[cfg(test)]
mod tests;
