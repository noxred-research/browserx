//! An in-process fake [`BrowserRuntime`] for tests of the scheduler and of the
//! server. Each fake browser serves a tiny mock DevTools endpoint on loopback so
//! relays can be exercised without a real browser.
//!
//! Mock endpoint behavior: `Target.createTarget` records the request and answers
//! `{targetId}`; `Target.getTargets` lists recorded targets; `Target.attachToTarget`
//! answers `{sessionId}`; any other method is answered with
//! `{echo: <method>, params, sessionId}` so tests can see exactly what the relay
//! forwarded.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use browserx_core::snapshot::CookieRecord;
use browserx_core::snapshot::STATE_FORMAT_VERSION;
use browserx_core::{
    BrowserHandle, BrowserId, BrowserRuntime, ContextId, Error, LaunchRequest, Result,
    RuntimeHealth, StateSnapshot,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One recorded call of the mock endpoint.
#[derive(Clone, Debug)]
pub struct RecordedCall {
    /// CDP method.
    pub method: String,
    /// CDP params.
    pub params: Value,
}

/// State of one fake browser, shared with tests.
pub struct FakeBrowserState {
    /// Scheduler-assigned id.
    pub id: BrowserId,
    /// The launch request that produced it.
    pub request: LaunchRequest,
    alive: AtomicBool,
    unresponsive: AtomicBool,
    shutdowns: AtomicUsize,
    default_cookies: Mutex<Vec<CookieRecord>>,
    contexts: Mutex<HashMap<String, Vec<CookieRecord>>>,
    targets: Mutex<Vec<(String, Option<String>)>>,
    calls: Mutex<Vec<RecordedCall>>,
    next_context: AtomicU64,
    ws_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    ws_url: String,
}

impl FakeBrowserState {
    /// Simulates a crash: the browser reports `Exited` from now on.
    pub fn kill(&self) {
        self.alive.store(false, Ordering::SeqCst);
        if let Some(task) = lock(&self.ws_task).take() {
            task.abort();
        }
    }

    /// Makes health probes report `Unresponsive` (or healthy again).
    pub fn set_unresponsive(&self, value: bool) {
        self.unresponsive.store(value, Ordering::SeqCst);
    }

    /// Whether the process is still "running".
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// How many times `shutdown_confirmed` was called.
    #[must_use]
    pub fn shutdown_calls(&self) -> usize {
        self.shutdowns.load(Ordering::SeqCst)
    }

    /// Number of live contexts.
    #[must_use]
    pub fn context_count(&self) -> usize {
        lock(&self.contexts).len()
    }

    /// Stores a cookie in a context (default context when `None`). With a
    /// user-data directory the cookie also persists on disk, like a real profile.
    pub fn set_cookie(&self, context: Option<&ContextId>, name: &str, value: &str) {
        let cookie = CookieRecord {
            name: name.into(),
            value: value.into(),
            domain: "example.test".into(),
            path: "/".into(),
            expires: None,
            http_only: false,
            secure: false,
            same_site: None,
        };
        match context {
            Some(c) => lock(&self.contexts)
                .entry(c.0.clone())
                .or_default()
                .push(cookie),
            None => {
                let mut jar = lock(&self.default_cookies);
                jar.push(cookie);
                if let Some(dir) = &self.request.user_data_dir
                    && let Ok(text) = serde_json::to_string(&*jar)
                {
                    let _ = std::fs::write(dir.join("fake-cookies.json"), text);
                }
            }
        }
    }

    /// Cookie names currently held by a context (default context when `None`).
    #[must_use]
    pub fn cookie_names(&self, context: Option<&ContextId>) -> Vec<String> {
        let jar: Vec<CookieRecord> = match context {
            Some(c) => lock(&self.contexts).get(&c.0).cloned().unwrap_or_default(),
            None => lock(&self.default_cookies).clone(),
        };
        jar.into_iter().map(|c| c.name).collect()
    }

    /// Calls the mock endpoint received, oldest first.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        lock(&self.calls).clone()
    }
}

#[derive(Default)]
struct Shared {
    launches: AtomicUsize,
    fail_next: AtomicUsize,
    delay_ms: AtomicU64,
    context_delay_ms: AtomicU64,
    browsers: Mutex<Vec<Arc<FakeBrowserState>>>,
}

/// Fake runtime. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct FakeRuntime {
    shared: Arc<Shared>,
    profiles: Vec<String>,
}

impl Default for FakeRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeRuntime {
    /// A runtime offering launch profiles `default` and `alt`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shared: Arc::default(),
            profiles: vec!["default".into(), "alt".into()],
        }
    }

    /// Makes the next `n` launches fail.
    pub fn fail_next_launches(&self, n: usize) {
        self.shared.fail_next.store(n, Ordering::SeqCst);
    }

    /// Delays every launch.
    pub fn set_launch_delay(&self, delay: Duration) {
        self.shared.delay_ms.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    /// Delays every context creation (shared isolation).
    pub fn set_context_delay(&self, delay: Duration) {
        self.shared.context_delay_ms.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    /// Total launch attempts that succeeded.
    #[must_use]
    pub fn launch_count(&self) -> usize {
        self.shared.launches.load(Ordering::SeqCst)
    }

    /// Every browser ever launched, oldest first.
    #[must_use]
    pub fn browsers(&self) -> Vec<Arc<FakeBrowserState>> {
        lock(&self.shared.browsers).clone()
    }

    /// Browsers that are still running.
    #[must_use]
    pub fn alive(&self) -> Vec<Arc<FakeBrowserState>> {
        self.browsers()
            .into_iter()
            .filter(|b| b.is_alive())
            .collect()
    }

    /// The most recently launched browser.
    #[must_use]
    pub fn last(&self) -> Option<Arc<FakeBrowserState>> {
        lock(&self.shared.browsers).last().cloned()
    }
}

struct FakeHandle {
    state: Arc<FakeBrowserState>,
    shared: Arc<Shared>,
}

#[async_trait]
impl BrowserHandle for FakeHandle {
    fn id(&self) -> BrowserId {
        self.state.id
    }
    fn browser_ws_url(&self) -> &str {
        &self.state.ws_url
    }
    fn version(&self) -> &str {
        "FakeChromium/0.0"
    }
    fn pid(&self) -> Option<u32> {
        Some(4_000_000)
    }
    async fn health(&self) -> RuntimeHealth {
        if !self.state.is_alive() {
            RuntimeHealth::Exited {
                detail: "killed".into(),
            }
        } else if self.state.unresponsive.load(Ordering::SeqCst) {
            RuntimeHealth::Unresponsive {
                detail: "no answer".into(),
            }
        } else {
            RuntimeHealth::Healthy
        }
    }
    async fn create_context(&self) -> Result<ContextId> {
        let delay = self.shared.context_delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        if !self.state.is_alive() {
            return Err(Error::Browser("browser exited".into()));
        }
        let n = self.state.next_context.fetch_add(1, Ordering::SeqCst);
        let id = format!("CTX{n}");
        lock(&self.state.contexts).insert(id.clone(), Vec::new());
        Ok(ContextId(id))
    }
    async fn dispose_context(&self, context: &ContextId) -> Result<()> {
        lock(&self.state.contexts).remove(&context.0);
        Ok(())
    }
    async fn capture_state(&self, context: Option<&ContextId>) -> Result<StateSnapshot> {
        if !self.state.is_alive() {
            return Err(Error::Browser("browser exited".into()));
        }
        let cookies = match context {
            Some(c) => lock(&self.state.contexts)
                .get(&c.0)
                .cloned()
                .unwrap_or_default(),
            None => lock(&self.state.default_cookies).clone(),
        };
        Ok(StateSnapshot {
            format_version: STATE_FORMAT_VERSION,
            browser_version: "FakeChromium/0.0".into(),
            cookies,
            origins: Vec::new(),
            open_urls: Vec::new(),
        })
    }
    async fn restore_state(
        &self,
        context: Option<&ContextId>,
        state: &StateSnapshot,
    ) -> Result<()> {
        match context {
            Some(c) => {
                lock(&self.state.contexts).insert(c.0.clone(), state.cookies.clone());
            }
            None => *lock(&self.state.default_cookies) = state.cookies.clone(),
        }
        Ok(())
    }
    async fn shutdown_confirmed(&self) -> Result<()> {
        self.state.shutdowns.fetch_add(1, Ordering::SeqCst);
        self.state.kill();
        Ok(())
    }
}

#[async_trait]
impl BrowserRuntime for FakeRuntime {
    async fn launch(&self, request: LaunchRequest) -> Result<Box<dyn BrowserHandle>> {
        let delay = self.shared.delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        let failing = self
            .shared
            .fail_next
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if failing {
            return Err(Error::Browser("injected launch failure".into()));
        }
        if let Some(name) = &request.launch_profile
            && !self.profiles.contains(name)
        {
            return Err(Error::InvalidRequest(format!(
                "unknown launch profile {name}"
            )));
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| Error::Browser(format!("fake endpoint: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| Error::Browser(e.to_string()))?
            .port();
        let mut cookies = Vec::new();
        if let Some(dir) = &request.user_data_dir
            && let Ok(text) = std::fs::read_to_string(dir.join("fake-cookies.json"))
        {
            cookies = serde_json::from_str(&text).unwrap_or_default();
        }
        let state = Arc::new(FakeBrowserState {
            id: request.browser_id,
            ws_url: format!("ws://127.0.0.1:{port}/devtools/browser/fake"),
            request,
            alive: AtomicBool::new(true),
            unresponsive: AtomicBool::new(false),
            shutdowns: AtomicUsize::new(0),
            default_cookies: Mutex::new(cookies),
            contexts: Mutex::new(HashMap::new()),
            targets: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
            next_context: AtomicU64::new(1),
            ws_task: Mutex::new(None),
        });
        let serving = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let conn = serving.clone();
                tokio::spawn(async move { serve_connection(conn, stream).await });
            }
        });
        *lock(&state.ws_task) = Some(task);
        lock(&self.shared.browsers).push(state.clone());
        self.shared.launches.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(FakeHandle {
            state,
            shared: self.shared.clone(),
        }))
    }

    fn launch_profiles(&self) -> Vec<String> {
        self.profiles.clone()
    }
}

async fn serve_connection(state: Arc<FakeBrowserState>, stream: tokio::net::TcpStream) {
    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };
    while let Some(Ok(message)) = ws.next().await {
        let Message::Text(text) = message else {
            continue;
        };
        let Ok(request) = serde_json::from_str::<Value>(text.as_str()) else {
            continue;
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let params = request.get("params").cloned().unwrap_or(Value::Null);
        let session = request.get("sessionId").cloned();
        lock(&state.calls).push(RecordedCall {
            method: method.clone(),
            params: params.clone(),
        });
        let result = match method.as_str() {
            "Target.createTarget" => {
                let n = lock(&state.targets).len();
                let target = format!("TARGET{n}");
                let context = params
                    .get("browserContextId")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                lock(&state.targets).push((target.clone(), context));
                json!({ "targetId": target })
            }
            "Target.getTargets" => {
                let infos: Vec<Value> = lock(&state.targets)
                    .iter()
                    .map(|(t, c)| json!({ "targetId": t, "browserContextId": c, "type": "page" }))
                    .collect();
                json!({ "targetInfos": infos })
            }
            "Target.attachToTarget" => {
                let target = params.get("targetId").and_then(Value::as_str).unwrap_or("");
                json!({ "sessionId": format!("SESSION-{target}") })
            }
            _ => json!({ "echo": method, "params": params, "sessionId": session }),
        };
        let mut reply = json!({ "id": id, "result": result });
        if let (Some(session), Some(obj)) = (&session, reply.as_object_mut()) {
            obj.insert("sessionId".into(), session.clone());
        }
        let reply = reply.to_string();
        if ws.send(Message::text(reply)).await.is_err() {
            break;
        }
    }
}

/// Path helper for tests that inspect profile directories.
#[must_use]
pub fn profile_dir_of(state: &FakeBrowserState) -> Option<PathBuf> {
    state.request.user_data_dir.clone()
}
