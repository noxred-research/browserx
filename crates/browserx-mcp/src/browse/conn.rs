//! One CDP connection to a session's browser: the tab table, the event pump that fills the
//! network and console rings, and the primitives the page and interaction operations build on.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use browserx_cdp::{CdpClient, CdpEvent, CdpLimits};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;

use super::Limits;
use super::ax::Refs;
use super::snapshot::SnapshotStore;
use crate::error::{ToolError, ToolResult};
use crate::safety::Scope;

/// Longest console message kept.
const MAX_CONSOLE_CHARS: usize = 500;
/// Longest URL kept in the network log.
const MAX_LOG_URL_CHARS: usize = 400;
/// Poll interval while waiting for a page to settle.
const SETTLE_POLL: Duration = Duration::from_millis(50);

/// One request in the network log.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct NetEntry {
    /// CDP request id (internal).
    #[serde(skip)]
    pub request_id: String,
    /// Milliseconds since the connection was made.
    pub at_ms: u64,
    /// HTTP method.
    pub method: String,
    /// Request URL (bounded).
    pub url: String,
    /// Response status, once known.
    pub status: Option<u16>,
    /// Resource type (`Document`, `XHR`, `Image`, ...).
    pub resource_type: String,
    /// Response MIME type, once known.
    pub mime: Option<String>,
    /// Encoded response size in bytes, once known.
    pub size: Option<u64>,
    /// Failure text, when the request failed.
    pub error: Option<String>,
}

/// One console message.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ConsoleEntry {
    /// Milliseconds since the connection was made.
    pub at_ms: u64,
    /// `log`, `info`, `warning`, `error` or `debug`.
    pub level: String,
    /// The message (bounded).
    pub text: String,
}

#[derive(Debug, Default)]
pub(super) struct Tab {
    pub num: u32,
    pub target_id: String,
    pub session_id: Option<String>,
    pub url: String,
    pub title: String,
    pub main_frame: Option<String>,
    pub loading: bool,
    /// Origin and reason code of the last main-document request the scope blocked.
    pub blocked: Option<(String, &'static str)>,
    pub loads: u64,
    pub navigations: u64,
    pub refs: Refs,
    pub snaps: SnapshotStore,
    pub net: VecDeque<NetEntry>,
    pub console: VecDeque<ConsoleEntry>,
}

#[derive(Debug, Default)]
pub(super) struct State {
    pub tabs: Vec<Tab>,
    pub next_tab: u32,
    pub current: Option<u32>,
}

impl State {
    pub(super) fn tab(&self, num: u32) -> Option<&Tab> {
        self.tabs.iter().find(|t| t.num == num)
    }

    pub(super) fn tab_mut(&mut self, num: u32) -> Option<&mut Tab> {
        self.tabs.iter_mut().find(|t| t.num == num)
    }
}

/// The part of the connection the event pump shares.
pub(super) struct Shared {
    state: Mutex<State>,
    limits: Limits,
    scope: Arc<Scope>,
    started: Instant,
}

/// The decision about one paused top-level request.
pub(super) struct Paused {
    pub session: String,
    pub request_id: String,
    pub allow: bool,
}

impl Paused {
    /// The CDP command that resolves the request.
    fn command(&self) -> (&'static str, Value) {
        if self.allow {
            (
                "Fetch.continueRequest",
                json!({ "requestId": self.request_id }),
            )
        } else {
            (
                "Fetch.failRequest",
                json!({ "requestId": self.request_id, "errorReason": "BlockedByClient" }),
            )
        }
    }
}

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push('…');
    out
}

fn push_capped<T>(ring: &mut VecDeque<T>, item: T, cap: usize) {
    if ring.len() >= cap {
        ring.pop_front();
    }
    ring.push_back(item);
}

fn remote_text(object: &Value) -> String {
    object
        .get("value")
        .map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .or_else(|| {
            object
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| {
            object
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        })
}

impl Shared {
    pub(super) fn new(limits: Limits, scope: Arc<Scope>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            limits,
            scope,
            started: Instant::now(),
        }
    }

    /// Decides a `Fetch.requestPaused` event: the main document of a tab may load only when its
    /// URL (every redirect hop included) is inside the scope. Sub-frames and subresources are
    /// page content and pass.
    pub(super) fn on_paused(&self, event: &CdpEvent) -> Option<Paused> {
        let session = event.session_id.clone()?;
        let p = &event.params;
        let request_id = p["requestId"].as_str()?.to_owned();
        let url = p["request"]["url"].as_str().unwrap_or("");
        let mut state = self.state();
        let tab = state
            .tabs
            .iter_mut()
            .find(|t| t.session_id.as_deref() == Some(session.as_str()))?;
        let main_document = p["resourceType"].as_str() == Some("Document")
            && tab
                .main_frame
                .as_deref()
                .is_none_or(|main| p["frameId"].as_str() == Some(main));
        let refusal = if main_document {
            let method = p["request"]["method"].as_str().unwrap_or("GET");
            self.scope.navigation_refusal_as(method, url)
        } else {
            None
        };
        let allow = refusal.is_none();
        if let Some(refusal) = refusal {
            tab.blocked = Some((
                url::Url::parse(url).map_or_else(
                    |_| "an unparsable URL".to_owned(),
                    |u| u.origin().ascii_serialization(),
                ),
                refusal.code(),
            ));
        }
        Some(Paused {
            session,
            request_id,
            allow,
        })
    }

    pub(super) fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn at_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Applies one browser event to the tab it belongs to.
    pub(super) fn on_event(&self, event: &CdpEvent) {
        let Some(session) = event.session_id.as_deref() else {
            return;
        };
        let at_ms = self.at_ms();
        let mut state = self.state();
        let Some(tab) = state
            .tabs
            .iter_mut()
            .find(|t| t.session_id.as_deref() == Some(session))
        else {
            return;
        };
        let p = &event.params;
        match event.method.as_str() {
            "Network.requestWillBeSent" => {
                let id = p["requestId"].as_str().unwrap_or("");
                if p.get("redirectResponse").is_some_and(Value::is_object)
                    && let Some(previous) = tab.net.iter_mut().rev().find(|e| e.request_id == id)
                {
                    previous.status = p["redirectResponse"]["status"]
                        .as_u64()
                        .and_then(|s| u16::try_from(s).ok());
                }
                push_capped(
                    &mut tab.net,
                    NetEntry {
                        request_id: id.to_owned(),
                        at_ms,
                        method: p["request"]["method"].as_str().unwrap_or("GET").to_owned(),
                        url: clip(
                            p["request"]["url"].as_str().unwrap_or(""),
                            MAX_LOG_URL_CHARS,
                        ),
                        status: None,
                        resource_type: p["type"].as_str().unwrap_or("Other").to_owned(),
                        mime: None,
                        size: None,
                        error: None,
                    },
                    self.limits.net_entries,
                );
            }
            "Network.responseReceived" => {
                let id = p["requestId"].as_str().unwrap_or("");
                if let Some(entry) = tab.net.iter_mut().rev().find(|e| e.request_id == id) {
                    entry.status = p["response"]["status"]
                        .as_u64()
                        .and_then(|s| u16::try_from(s).ok());
                    entry.mime = p["response"]["mimeType"].as_str().map(str::to_owned);
                    if let Some(kind) = p["type"].as_str() {
                        kind.clone_into(&mut entry.resource_type);
                    }
                }
            }
            "Network.loadingFinished" => {
                let id = p["requestId"].as_str().unwrap_or("");
                if let Some(entry) = tab.net.iter_mut().rev().find(|e| e.request_id == id) {
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    {
                        entry.size = p["encodedDataLength"].as_f64().map(|n| n.max(0.0) as u64);
                    }
                }
            }
            "Network.loadingFailed" => {
                let id = p["requestId"].as_str().unwrap_or("");
                if let Some(entry) = tab.net.iter_mut().rev().find(|e| e.request_id == id) {
                    let text = p["errorText"].as_str().unwrap_or("failed");
                    entry.error = Some(if p["canceled"].as_bool() == Some(true) {
                        format!("{text} (canceled)")
                    } else {
                        text.to_owned()
                    });
                }
            }
            "Runtime.consoleAPICalled" => {
                let text = p["args"]
                    .as_array()
                    .map(|args| args.iter().map(remote_text).collect::<Vec<_>>().join(" "))
                    .unwrap_or_default();
                let level = match p["type"].as_str().unwrap_or("log") {
                    "warning" => "warning",
                    "error" | "assert" => "error",
                    "info" => "info",
                    "debug" | "trace" => "debug",
                    _ => "log",
                };
                push_capped(
                    &mut tab.console,
                    ConsoleEntry {
                        at_ms,
                        level: level.to_owned(),
                        text: clip(&text, MAX_CONSOLE_CHARS),
                    },
                    self.limits.console_entries,
                );
            }
            "Runtime.exceptionThrown" => {
                let details = &p["exceptionDetails"];
                let text = details["exception"]["description"]
                    .as_str()
                    .or_else(|| details["text"].as_str())
                    .unwrap_or("uncaught exception");
                push_capped(
                    &mut tab.console,
                    ConsoleEntry {
                        at_ms,
                        level: "error".into(),
                        text: clip(text, MAX_CONSOLE_CHARS),
                    },
                    self.limits.console_entries,
                );
            }
            "Log.entryAdded" => {
                let entry = &p["entry"];
                let level = match entry["level"].as_str().unwrap_or("info") {
                    "verbose" => "debug",
                    "warning" => "warning",
                    "error" => "error",
                    _ => "info",
                };
                push_capped(
                    &mut tab.console,
                    ConsoleEntry {
                        at_ms,
                        level: level.to_owned(),
                        text: clip(entry["text"].as_str().unwrap_or(""), MAX_CONSOLE_CHARS),
                    },
                    self.limits.console_entries,
                );
            }
            "Page.frameNavigated" => {
                let frame = &p["frame"];
                if frame.get("parentId").is_none() {
                    tab.main_frame = frame["id"].as_str().map(str::to_owned);
                    tab.url = frame["url"].as_str().unwrap_or("").to_owned();
                    tab.navigations += 1;
                    tab.refs.clear();
                    tab.snaps.clear();
                }
            }
            "Page.navigatedWithinDocument" => {
                if let Some(url) = p["url"].as_str() {
                    url.clone_into(&mut tab.url);
                }
            }
            "Page.frameStartedLoading" => {
                if tab
                    .main_frame
                    .as_deref()
                    .is_none_or(|main| p["frameId"].as_str() == Some(main))
                {
                    tab.loading = true;
                }
            }
            "Page.frameStoppedLoading" => {
                if tab
                    .main_frame
                    .as_deref()
                    .is_none_or(|main| p["frameId"].as_str() == Some(main))
                {
                    tab.loading = false;
                }
            }
            "Page.loadEventFired" => {
                tab.loads += 1;
                tab.loading = false;
            }
            _ => {}
        }
    }
}

/// A tab an operation works on.
#[derive(Debug, Clone)]
pub struct TabRef {
    /// Internal number.
    pub num: u32,
    /// The id shown to the model (`t1`).
    pub id: String,
    /// CDP target id.
    pub target_id: String,
    /// Flattened CDP session id.
    pub session_id: String,
}

/// One tab as listed to the model.
#[derive(Debug, Clone, Serialize)]
pub struct TabInfo {
    /// Tab id (`t1`).
    pub id: String,
    /// Current URL.
    pub url: String,
    /// Page title.
    pub title: String,
    /// Whether this is the tab operations use by default.
    pub current: bool,
    /// Whether the tab's origin is inside the authorized scope.
    pub in_scope: bool,
}

/// A CDP connection to one session's browser.
pub struct Conn {
    pub(super) client: CdpClient,
    pub(super) shared: Arc<Shared>,
    pub(super) scope: Arc<Scope>,
    pub(super) limits: Limits,
    pump: JoinHandle<()>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// The refusal for a navigation the scope guard stopped before it left the browser.
pub(super) fn blocked_error(origin: &str, code: &str) -> ToolError {
    ToolError::refused_with(
        code,
        format!(
            "the page tried to load {origin}, which is outside the authorized scope: the request was blocked before it was sent \
             and the tab stays on its previous page"
        ),
    )
}

fn map_cdp(error: browserx_cdp::CdpError) -> ToolError {
    match error {
        browserx_cdp::CdpError::Closed(_) | browserx_cdp::CdpError::MessageTooLarge { .. } => {
            ToolError::browser(
                "the connection to the browser closed: the session may have been recovered or released; call the tool again to reconnect",
            )
        }
        other => ToolError::browser(other.to_string()),
    }
}

impl Conn {
    /// Connects to the browser-level endpoint and attaches to the existing page tabs.
    pub(super) async fn connect(url: &str, limits: Limits, scope: Arc<Scope>) -> ToolResult<Self> {
        let client = CdpClient::connect(
            url,
            CdpLimits {
                command_timeout: limits.command_timeout,
                max_message_bytes: limits.max_message_bytes,
                max_pending: 64,
                event_buffer: 4096,
            },
        )
        .await
        .map_err(|e| ToolError::browser(format!("cannot connect to the browser: {e}")))?;
        let shared = Arc::new(Shared::new(limits, Arc::clone(&scope)));
        let mut events = client.events();
        let pump_shared = Arc::clone(&shared);
        let pump_client = client.clone();
        let pump = tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) if event.method == "Fetch.requestPaused" => {
                        if let Some(paused) = pump_shared.on_paused(&event) {
                            let client = pump_client.clone();
                            tokio::spawn(async move {
                                let (method, params) = paused.command();
                                if let Err(error) =
                                    client.call(method, params, Some(&paused.session)).await
                                {
                                    tracing::debug!(%error, "cannot resolve a paused request");
                                }
                            });
                        }
                    }
                    Ok(event) => pump_shared.on_event(&event),
                    Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => break,
                }
            }
        });
        let conn = Self {
            client,
            shared,
            scope,
            limits,
            pump,
        };
        conn.sync_tabs().await?;
        Ok(conn)
    }

    /// Whether the browser connection is gone.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.client.is_closed()
    }

    /// Forgets every element reference and stored snapshot of every tab.
    pub(super) fn forget_refs(&self) {
        for tab in &mut self.shared.state().tabs {
            tab.refs.clear();
            tab.snaps.clear();
        }
    }

    /// Closes the connection.
    pub async fn close(&self) {
        self.client.close().await;
    }

    pub(super) async fn browser_call(&self, method: &str, params: Value) -> ToolResult<Value> {
        self.client
            .call(method, params, None)
            .await
            .map_err(map_cdp)
    }

    pub(super) async fn call(
        &self,
        tab: &TabRef,
        method: &str,
        params: Value,
    ) -> ToolResult<Value> {
        self.client
            .call(method, params, Some(&tab.session_id))
            .await
            .map_err(map_cdp)
    }

    /// Reconciles the tab table with the browser's page targets, closing tabs beyond the limit.
    pub(super) async fn sync_tabs(&self) -> ToolResult<()> {
        let targets = self.browser_call("Target.getTargets", json!({})).await?;
        let infos: Vec<&Value> = targets["targetInfos"]
            .as_array()
            .map(|list| list.iter().filter(|t| t["type"] == "page").collect())
            .unwrap_or_default();
        let mut to_attach: Vec<u32> = Vec::new();
        let mut to_close: Vec<String> = Vec::new();
        {
            let mut state = self.shared.state();
            state.tabs.retain(|tab| {
                infos
                    .iter()
                    .any(|i| i["targetId"].as_str() == Some(&tab.target_id))
            });
            for info in &infos {
                let Some(target_id) = info["targetId"].as_str() else {
                    continue;
                };
                if let Some(tab) = state.tabs.iter_mut().find(|t| t.target_id == target_id) {
                    if tab.session_id.is_none() || tab.url.is_empty() {
                        info["url"].as_str().unwrap_or("").clone_into(&mut tab.url);
                    }
                    info["title"]
                        .as_str()
                        .unwrap_or("")
                        .clone_into(&mut tab.title);
                    if tab.session_id.is_none() {
                        to_attach.push(tab.num);
                    }
                    continue;
                }
                if state.tabs.len() >= self.limits.max_tabs {
                    to_close.push(target_id.to_owned());
                    continue;
                }
                state.next_tab += 1;
                let num = state.next_tab;
                state.tabs.push(Tab {
                    num,
                    target_id: target_id.to_owned(),
                    url: info["url"].as_str().unwrap_or("").to_owned(),
                    title: info["title"].as_str().unwrap_or("").to_owned(),
                    ..Tab::default()
                });
                to_attach.push(num);
            }
            if state.current.is_none_or(|c| state.tab(c).is_none()) {
                state.current = state.tabs.first().map(|t| t.num);
            }
        }
        for target_id in to_close {
            tracing::warn!("closing a tab beyond the per-session limit");
            let _ = self
                .browser_call("Target.closeTarget", json!({ "targetId": target_id }))
                .await;
        }
        for num in to_attach {
            self.attach_tab(num).await?;
        }
        Ok(())
    }

    async fn attach_tab(&self, num: u32) -> ToolResult<()> {
        let Some(target_id) = self.shared.state().tab(num).map(|t| t.target_id.clone()) else {
            return Ok(());
        };
        let attached = self
            .browser_call(
                "Target.attachToTarget",
                json!({ "targetId": target_id, "flatten": true }),
            )
            .await?;
        let session_id = attached["sessionId"]
            .as_str()
            .ok_or_else(|| ToolError::browser("Target.attachToTarget returned no session"))?
            .to_owned();
        if let Some(tab) = self.shared.state().tab_mut(num) {
            tab.session_id = Some(session_id.clone());
        }
        let tab = TabRef {
            num,
            id: format!("t{num}"),
            target_id,
            session_id,
        };
        for (method, params) in [
            ("Page.enable", json!({})),
            ("Runtime.enable", json!({})),
            (
                "Network.enable",
                json!({ "maxTotalBufferSize": 1_048_576, "maxResourceBufferSize": 1_048_576 }),
            ),
            ("Log.enable", json!({})),
            ("DOM.enable", json!({})),
            ("Accessibility.enable", json!({})),
        ] {
            self.call(&tab, method, params).await?;
        }
        if let Ok(tree) = self.call(&tab, "Page.getFrameTree", json!({})).await
            && let Some(tab) = self.shared.state().tab_mut(num)
        {
            tab.main_frame = tree["frameTree"]["frame"]["id"].as_str().map(str::to_owned);
        }
        // Hold every top-level document request until its URL is checked against the scope, so
        // an out-of-scope navigation or redirect hop is never fetched. The check after the
        // navigation settles stays as the second line.
        if let Err(error) = self
            .call(
                &tab,
                "Fetch.enable",
                json!({ "patterns": [{ "urlPattern": "*", "resourceType": "Document", "requestStage": "Request" }] }),
            )
            .await
        {
            tracing::warn!(%error, "request interception is unavailable; scope is enforced after navigation only");
        }
        Ok(())
    }

    /// Resolves a tab (`None` = the current one), creating a blank tab when the browser has
    /// none, and refuses a tab that sits outside the authorized scope.
    pub async fn tab(&self, id: Option<&str>) -> ToolResult<TabRef> {
        self.sync_tabs().await?;
        if self.shared.state().tabs.is_empty() {
            self.browser_call("Target.createTarget", json!({ "url": "about:blank" }))
                .await?;
            self.sync_tabs().await?;
        }
        let tab = {
            let state = self.shared.state();
            let tab = match id {
                Some(id) => {
                    let num = id
                        .strip_prefix('t')
                        .and_then(|n| n.parse::<u32>().ok())
                        .ok_or_else(|| {
                            ToolError::invalid(format!("tab id {id:?} must look like t1"))
                        })?;
                    state
                        .tab(num)
                        .ok_or_else(|| ToolError::invalid(format!("no tab {id}: call list_tabs")))?
                }
                None => state
                    .current
                    .and_then(|c| state.tab(c))
                    .or_else(|| state.tabs.first())
                    .ok_or_else(|| ToolError::browser("the browser has no tab"))?,
            };
            let session_id = tab
                .session_id
                .clone()
                .ok_or_else(|| ToolError::browser("the tab is not attached yet; try again"))?;
            (
                TabRef {
                    num: tab.num,
                    id: format!("t{}", tab.num),
                    target_id: tab.target_id.clone(),
                    session_id,
                },
                tab.url.clone(),
            )
        };
        if let Err(refusal) = self.scope.check_final(&tab.1) {
            let _ = self.reset_blank(&tab.0).await;
            return Err(ToolError::refused(format!(
                "tab {} was at {}: {} The tab was reset to about:blank.",
                tab.0.id, tab.1, refusal.0
            )));
        }
        Ok(tab.0)
    }

    /// Navigates to `about:blank` and waits for it. Used after an out-of-scope landing.
    pub(super) async fn reset_blank(&self, tab: &TabRef) -> ToolResult<()> {
        self.call(tab, "Page.navigate", json!({ "url": "about:blank" }))
            .await?;
        self.wait_settled(tab, Duration::from_millis(100)).await;
        Ok(())
    }

    /// Waits until the tab's main frame stops loading (after at least `min_wait`). Returns
    /// whether it settled before the navigation timeout.
    pub(super) async fn wait_settled(&self, tab: &TabRef, min_wait: Duration) -> bool {
        let started = Instant::now();
        tokio::time::sleep(min_wait).await;
        loop {
            if !self.shared.state().tab(tab.num).is_some_and(|t| t.loading) {
                return true;
            }
            if started.elapsed() >= self.limits.navigation_timeout {
                return false;
            }
            tokio::time::sleep(SETTLE_POLL).await;
        }
    }

    /// The URL the tab is at now, from the navigation history (authoritative after redirects).
    pub(super) async fn current_url(&self, tab: &TabRef) -> ToolResult<String> {
        let history = self
            .call(tab, "Page.getNavigationHistory", json!({}))
            .await?;
        let index = history["currentIndex"].as_u64().unwrap_or(0);
        let index = usize::try_from(index).unwrap_or(0);
        Ok(history["entries"]
            .as_array()
            .and_then(|entries| entries.get(index))
            .and_then(|entry| entry["url"].as_str())
            .unwrap_or("")
            .to_owned())
    }

    /// Evaluates a fixed expression and returns its value.
    pub(super) async fn eval(
        &self,
        tab: &TabRef,
        expression: &str,
        timeout_ms: u64,
    ) -> ToolResult<Value> {
        self.eval_in(tab, expression, timeout_ms, None).await
    }

    /// Evaluates a fixed expression in the execution context `context` (the page's main world
    /// when `None`) and returns its value.
    pub(super) async fn eval_in(
        &self,
        tab: &TabRef,
        expression: &str,
        timeout_ms: u64,
        context: Option<i64>,
    ) -> ToolResult<Value> {
        let mut params = json!({
            "expression": expression,
            "returnByValue": true,
            "awaitPromise": true,
            "timeout": timeout_ms,
            "userGesture": false,
        });
        if let Some(context) = context {
            params["contextId"] = json!(context);
        }
        let result = self.call(tab, "Runtime.evaluate", params).await?;
        if let Some(details) = result.get("exceptionDetails") {
            let text = details["exception"]["description"]
                .as_str()
                .or_else(|| details["text"].as_str())
                .unwrap_or("the script threw");
            return Err(ToolError::browser(format!(
                "script error: {}",
                clip(text, 300)
            )));
        }
        Ok(result["result"]
            .get("value")
            .cloned()
            .unwrap_or(Value::Null))
    }

    /// The title of the page.
    pub(super) async fn title(&self, tab: &TabRef) -> String {
        match self.eval(tab, "document.title", 2000).await {
            Ok(Value::String(title)) => clip(&title, 300),
            _ => String::new(),
        }
    }

    /// After something may have moved the page: waits for it to settle, reads the final URL and
    /// enforces the scope. An out-of-scope landing resets the tab to `about:blank` and fails.
    pub(super) async fn settle_and_check(
        &self,
        tab: &TabRef,
        min_wait: Duration,
    ) -> ToolResult<(String, bool)> {
        let settled = self.wait_settled(tab, min_wait).await;
        if let Some((origin, code)) = self.take_blocked(tab) {
            return Err(blocked_error(&origin, code));
        }
        let url = self.current_url(tab).await?;
        if url.starts_with("chrome-error://") {
            return Err(ToolError::browser(
                "the page failed to load (the browser shows an error page). If the destination is internal, \
                 the egress policy may have refused it; call assess.",
            ));
        }
        if let Err(refusal) = self.scope.check_final(&url) {
            let _ = self.reset_blank(tab).await;
            return Err(ToolError::refused(format!(
                "the page ended at {url}: {} The tab was reset to about:blank.",
                refusal.0
            )));
        }
        Ok((url, settled))
    }

    /// The origin of a navigation the scope guard blocked since the last call, if any.
    pub(super) fn take_blocked(&self, tab: &TabRef) -> Option<(String, &'static str)> {
        self.shared
            .state()
            .tab_mut(tab.num)
            .and_then(|t| t.blocked.take())
    }

    /// Lists the tabs.
    pub async fn list_tabs(&self) -> ToolResult<Vec<TabInfo>> {
        self.sync_tabs().await?;
        let state = self.shared.state();
        Ok(state
            .tabs
            .iter()
            .map(|t| TabInfo {
                id: format!("t{}", t.num),
                url: t.url.clone(),
                title: t.title.clone(),
                current: state.current == Some(t.num),
                in_scope: self.scope.check_final(&t.url).is_ok(),
            })
            .collect())
    }

    /// Makes `id` the default tab.
    pub async fn switch_tab(&self, id: &str) -> ToolResult<TabRef> {
        let tab = self.tab(Some(id)).await?;
        self.shared.state().current = Some(tab.num);
        let _ = self
            .browser_call(
                "Target.activateTarget",
                json!({ "targetId": tab.target_id }),
            )
            .await;
        Ok(tab)
    }

    /// Closes a tab.
    pub async fn close_tab(&self, id: Option<&str>) -> ToolResult<String> {
        let tab = self.tab(id).await?;
        self.browser_call("Target.closeTarget", json!({ "targetId": tab.target_id }))
            .await?;
        self.shared.state().tabs.retain(|t| t.num != tab.num);
        self.sync_tabs().await?;
        Ok(tab.id)
    }

    /// Opens a new blank tab (within the tab limit) and makes it current.
    pub async fn new_tab(&self) -> ToolResult<TabRef> {
        self.sync_tabs().await?;
        if self.shared.state().tabs.len() >= self.limits.max_tabs {
            return Err(ToolError::refused(format!(
                "the tab limit ({}) is reached: close_tab first",
                self.limits.max_tabs
            )));
        }
        let created = self
            .browser_call("Target.createTarget", json!({ "url": "about:blank" }))
            .await?;
        let target_id = created["targetId"].as_str().unwrap_or("").to_owned();
        self.sync_tabs().await?;
        let num = {
            let state = self.shared.state();
            state
                .tabs
                .iter()
                .find(|t| t.target_id == target_id)
                .map(|t| t.num)
                .ok_or_else(|| ToolError::browser("the new tab did not appear"))?
        };
        self.shared.state().current = Some(num);
        self.tab(Some(&format!("t{num}"))).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn shared() -> Shared {
        let shared = Shared::new(
            Limits {
                net_entries: 3,
                console_entries: 2,
                ..Limits::default()
            },
            Arc::new(Scope::new(
                vec!["http://site.test".into()],
                true,
                crate::config::Window::default(),
            )),
        );
        shared.state().tabs.push(Tab {
            num: 1,
            target_id: "T".into(),
            session_id: Some("S".into()),
            ..Tab::default()
        });
        shared
    }

    fn event(method: &str, session: Option<&str>, params: Value) -> CdpEvent {
        CdpEvent {
            method: method.into(),
            params,
            session_id: session.map(str::to_owned),
        }
    }

    #[test]
    fn network_requests_accumulate_status_mime_size_and_failures_in_a_bounded_ring() {
        let shared = shared();
        let send = |e: CdpEvent| shared.on_event(&e);
        send(event(
            "Network.requestWillBeSent",
            Some("S"),
            json!({
                "requestId": "1", "type": "Document", "request": {"url": "http://site.test/", "method": "GET"}
            }),
        ));
        send(event(
            "Network.responseReceived",
            Some("S"),
            json!({
                "requestId": "1", "type": "Document", "response": {"status": 200, "mimeType": "text/html"}
            }),
        ));
        send(event(
            "Network.loadingFinished",
            Some("S"),
            json!({"requestId": "1", "encodedDataLength": 512.0}),
        ));
        send(event(
            "Network.requestWillBeSent",
            Some("S"),
            json!({
                "requestId": "2", "type": "Image", "request": {"url": "http://site.test/x.png", "method": "GET"}
            }),
        ));
        send(event(
            "Network.loadingFailed",
            Some("S"),
            json!({"requestId": "2", "errorText": "net::ERR_BLOCKED", "canceled": true}),
        ));
        let state = shared.state();
        let net = &state.tab(1).unwrap().net;
        assert_eq!(net.len(), 2);
        assert_eq!(
            (net[0].status, net[0].size, net[0].mime.as_deref()),
            (Some(200), Some(512), Some("text/html"))
        );
        assert_eq!(net[1].error.as_deref(), Some("net::ERR_BLOCKED (canceled)"));
        drop(state);
        for id in ["3", "4", "5"] {
            send(event(
                "Network.requestWillBeSent",
                Some("S"),
                json!({
                    "requestId": id, "request": {"url": "http://site.test/", "method": "POST"}
                }),
            ));
        }
        let state = shared.state();
        let net = &state.tab(1).unwrap().net;
        assert_eq!(net.len(), 3);
        assert_eq!(net[0].request_id, "3");
        assert_eq!(net[0].method, "POST");
        assert_eq!(net[0].resource_type, "Other");
    }

    #[test]
    fn console_messages_and_exceptions_are_bounded_and_leveled() {
        let shared = shared();
        let send = |e: CdpEvent| shared.on_event(&e);
        send(event(
            "Runtime.consoleAPICalled",
            Some("S"),
            json!({
                "type": "warning", "args": [{"type": "string", "value": "careful"}, {"type": "number", "value": 3}]
            }),
        ));
        send(event(
            "Runtime.exceptionThrown",
            Some("S"),
            json!({
                "exceptionDetails": {"text": "Uncaught", "exception": {"description": "Error: boom"}}
            }),
        ));
        send(event(
            "Log.entryAdded",
            Some("S"),
            json!({"entry": {"level": "info", "text": "x".repeat(900)}}),
        ));
        let state = shared.state();
        let console = &state.tab(1).unwrap().console;
        assert_eq!(console.len(), 2);
        assert_eq!(
            (console[0].level.as_str(), console[0].text.as_str()),
            ("error", "Error: boom")
        );
        assert_eq!(console[1].text.chars().count(), MAX_CONSOLE_CHARS + 1);
    }

    #[test]
    fn navigation_clears_references_and_tracks_loading() {
        let shared = shared();
        let send = |e: CdpEvent| shared.on_event(&e);
        send(event(
            "Page.frameStartedLoading",
            Some("S"),
            json!({"frameId": "F"}),
        ));
        assert!(shared.state().tab(1).unwrap().loading);
        send(event(
            "Page.frameNavigated",
            Some("S"),
            json!({"frame": {"id": "F", "url": "http://site.test/next"}}),
        ));
        send(event(
            "Page.frameNavigated",
            Some("S"),
            json!({"frame": {"id": "G", "parentId": "F", "url": "http://ads.test/"}}),
        ));
        {
            let state = shared.state();
            let tab = state.tab(1).unwrap();
            assert_eq!(
                (tab.url.as_str(), tab.navigations),
                ("http://site.test/next", 1)
            );
        }
        send(event(
            "Page.frameStoppedLoading",
            Some("S"),
            json!({"frameId": "G"}),
        ));
        assert!(
            shared.state().tab(1).unwrap().loading,
            "a sub-frame stopping is not the page settling"
        );
        send(event(
            "Page.frameStoppedLoading",
            Some("S"),
            json!({"frameId": "F"}),
        ));
        assert!(!shared.state().tab(1).unwrap().loading);
    }

    #[test]
    fn a_protected_post_is_held_back_whatever_started_it() {
        let manifest = crate::manifest::Manifest::parse(
            "[engagement]\nid = \"e\"\noperator = \"o\"\nauthorization_note = \"n\"\n\
             [[scope]]\nhost = \"site.test\"\nmode = \"attack\"\n\
             [[protected]]\npattern = \"POST /delete\"\nmode = \"blocked\"\n",
        )
        .unwrap();
        let scope = Scope::new(
            vec!["http://site.test".into()],
            true,
            crate::config::Window::default(),
        )
        .with_manifest(Arc::new(crate::manifest::Loaded {
            manifest,
            digest: "d".into(),
            signature: crate::manifest::Signature::Valid("op".into()),
        }));
        let shared = Shared::new(Limits::default(), Arc::new(scope));
        shared.state().tabs.push(Tab {
            num: 1,
            target_id: "T".into(),
            session_id: Some("S".into()),
            main_frame: Some("F".into()),
            ..Tab::default()
        });
        let paused = |method: &str, url: &str| {
            shared
                .on_paused(&event(
                    "Fetch.requestPaused",
                    Some("S"),
                    json!({"requestId": "r", "resourceType": "Document", "frameId": "F",
                           "request": {"url": url, "method": method}}),
                ))
                .unwrap()
        };
        // A script-submitted form: the document request is a POST.
        let post = paused("POST", "http://site.test/delete");
        assert!(!post.allow, "the POST is protected");
        assert_eq!(post.command().0, "Fetch.failRequest");
        assert_eq!(
            shared.state().tab(1).unwrap().blocked.as_ref().map(|b| b.1),
            Some("blocked_protected")
        );
        assert!(!paused("POST", "http://site.test/Delete/?x=1").allow);
        // The same URL fetched with GET, and another POST, are not covered by the pattern.
        assert!(paused("GET", "http://site.test/delete").allow);
        assert!(paused("POST", "http://site.test/save").allow);
    }

    #[test]
    fn only_in_scope_top_level_documents_are_released() {
        let shared = shared();
        shared.state().tab_mut(1).unwrap().main_frame = Some("F".into());
        let paused = |url: &str, kind: &str, frame: &str, session: &str| {
            shared.on_paused(&event("Fetch.requestPaused", Some(session), json!({
                "requestId": "r", "resourceType": kind, "frameId": frame, "request": {"url": url}
            })))
        };
        assert!(
            paused("http://site.test/a", "Document", "F", "S")
                .unwrap()
                .allow
        );
        let blocked = paused("http://evil.test/a", "Document", "F", "S").unwrap();
        assert!(!blocked.allow);
        assert_eq!(blocked.command().0, "Fetch.failRequest");
        assert_eq!(
            shared
                .state()
                .tab(1)
                .unwrap()
                .blocked
                .as_ref()
                .map(|(origin, _)| origin.as_str()),
            Some("http://evil.test")
        );
        // Frames of other origins and subresources are page content.
        assert!(
            paused("http://widgets.test/frame", "Document", "CHILD", "S")
                .unwrap()
                .allow
        );
        assert!(
            paused("http://evil.test/x.js", "Script", "F", "S")
                .unwrap()
                .allow
        );
        assert!(paused("http://site.test/a", "Document", "F", "UNKNOWN").is_none());
        assert_eq!(
            blocked_error("http://evil.test", "out_of_scope").kind,
            crate::error::FailKind::Refused
        );
    }

    #[test]
    fn events_of_other_sessions_and_browser_level_events_are_ignored() {
        let shared = shared();
        shared.on_event(&event(
            "Network.requestWillBeSent",
            Some("OTHER"),
            json!({"requestId": "1", "request": {"url": "x", "method": "GET"}}),
        ));
        shared.on_event(&event("Network.requestWillBeSent", None, json!({})));
        assert!(shared.state().tab(1).unwrap().net.is_empty());
    }
}
