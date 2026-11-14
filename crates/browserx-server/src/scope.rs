//! The scoped CDP filter used for shared-browser sessions.
//!
//! A shared session owns one browser context inside a browser that other
//! sessions also use. The relay therefore never forwards what a client sends
//! verbatim: it keeps an allow-list of the targets and CDP sessions that belong
//! to the context and applies default-deny rules.
//!
//! * Browser-level methods are allow-listed (`Target.*` subset, `Browser.getVersion`,
//!   context-scoped `Browser.*`/`Storage.*` helpers). Everything else is refused.
//! * `Target.createTarget` is pinned to the session's context; context
//!   management, `Browser.close`/`crash*`, `SystemInfo.*`, browser-level
//!   attachment and non-flat messaging are refused.
//! * Page-session traffic (`sessionId`) is allowed only for sessions that were
//!   attached to targets of this context (directly, via auto-attach, or as child
//!   sessions of such a session), and only for an allow-list of protocol
//!   domains: `Tracing`, `Memory`, `SystemInfo` and unknown domains are refused,
//!   `Storage` commands naming another context are refused.
//! * Requests are tracked by `(sessionId, id)`. A second request with an id
//!   that is still in flight is refused, so a response can never be matched to
//!   the wrong request. Entries of a CDP session that detaches or whose target
//!   is destroyed are dropped, so unanswered commands cannot fill the table.
//! * Responses and `Target.*` events, at browser level and on page sessions,
//!   are filtered to the session's own targets and contexts; other browser-level
//!   events are dropped.
//! * A foreign `Target.attachedToTarget` (a browser-wide auto-attach reaching
//!   targets of other contexts) is not delivered, and the relay resumes and
//!   detaches that attachment upstream so the foreign target is never left
//!   paused waiting for a debugger. See [`ScopedFilter::take_upstream`].
//! * Downloads, navigation URLs and the other host-protection rules of
//!   [`HostPolicy`] apply as well.
//!
//! This confines a cooperative client; it is not a boundary against a hostile
//! tenant (see `Isolation::SharedBrowser`).

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value, json};

use crate::host_policy::{Envelope, HostPolicy, refusal_reply};

/// Outstanding requests tracked per connection.
const MAX_PENDING: usize = 4096;
/// Targets and sessions remembered per connection.
const MAX_TRACKED: usize = 65_536;
/// Commands the relay itself sends upstream use ids from here up; a client
/// may not use them.
const INTERNAL_ID_BASE: i64 = 2_000_000_000;
const INTERNAL_ID_END: i64 = 2_147_000_000;
/// Upstream commands queued at most between two drains.
const MAX_UPSTREAM_QUEUE: usize = 256;

/// Protocol domains a relay client may use (page sessions of a shared relay, and
/// every session of a dedicated relay). Anything else is refused.
pub(crate) const PAGE_DOMAINS: &[&str] = &[
    "Accessibility",
    "Animation",
    "Audits",
    "Autofill",
    "BackgroundService",
    "BluetoothEmulation",
    "Browser",
    "CSS",
    "Cast",
    "Console",
    "DOM",
    "DOMDebugger",
    "DOMSnapshot",
    "DOMStorage",
    "Debugger",
    "DeviceAccess",
    "DeviceOrientation",
    "Emulation",
    "EventBreakpoints",
    "FedCm",
    "Fetch",
    "FileSystem",
    "HeadlessExperimental",
    "HeapProfiler",
    "IO",
    "IndexedDB",
    "Input",
    "Inspector",
    "LayerTree",
    "Log",
    "Media",
    "Network",
    "Overlay",
    "PWA",
    "Page",
    "Performance",
    "PerformanceTimeline",
    "Preload",
    "Profiler",
    "Runtime",
    "Schema",
    "Security",
    "ServiceWorker",
    "Storage",
    "Target",
    "WebAudio",
    "WebAuthn",
];

/// What to do with a client message.
#[derive(Debug, PartialEq, Eq)]
pub enum ClientAction {
    /// Send this text to the browser.
    Forward(String),
    /// Answer the client with this text; nothing reaches the browser.
    Reply(String),
    /// Ignore the message.
    Drop,
}

enum Pending {
    Pass,
    CreateTarget,
    GetTargets,
    GetContexts,
    Attach { target: String },
}

struct SessionInfo {
    target: Option<String>,
    parent: Option<String>,
}

/// Per-connection filter state.
pub struct ScopedFilter {
    context: String,
    host: HostPolicy,
    targets: HashSet<String>,
    sessions: HashMap<String, SessionInfo>,
    pending: HashMap<(String, i64), Pending>,
    upstream: Vec<String>,
    next_internal_id: i64,
}

impl ScopedFilter {
    /// A filter confined to browser context `context`, applying `host`.
    #[must_use]
    pub fn new(context: String, host: HostPolicy) -> Self {
        Self {
            context,
            host,
            targets: HashSet::new(),
            sessions: HashMap::new(),
            pending: HashMap::new(),
            upstream: Vec::new(),
            next_internal_id: INTERNAL_ID_BASE,
        }
    }

    /// The download directory this filter forces.
    #[must_use]
    pub fn download_dir(&self) -> &std::path::Path {
        self.host.download_dir()
    }

    fn refuse(id: i64, session: Option<&str>, why: &str) -> ClientAction {
        ClientAction::Reply(refusal_reply(
            id,
            session,
            &format!("refused by the scoped relay: {why}"),
        ))
    }

    fn track_target(&mut self, id: &str) {
        if self.targets.len() < MAX_TRACKED {
            self.targets.insert(id.to_owned());
        }
    }

    fn track_session(&mut self, id: &str, target: Option<&str>, parent: Option<&str>) {
        if self.sessions.len() < MAX_TRACKED {
            self.sessions.insert(
                id.to_owned(),
                SessionInfo {
                    target: target.map(str::to_owned),
                    parent: parent.map(str::to_owned),
                },
            );
        }
    }

    /// Forgets a CDP session, its child sessions and every request still waiting on them.
    fn remove_session(&mut self, session: &str) {
        let mut stack = vec![session.to_owned()];
        while let Some(s) = stack.pop() {
            if self.sessions.remove(&s).is_some() {
                stack.extend(
                    self.sessions
                        .iter()
                        .filter(|(_, info)| info.parent.as_deref() == Some(s.as_str()))
                        .map(|(child, _)| child.clone()),
                );
            }
        }
        let sessions = &self.sessions;
        self.pending
            .retain(|(s, _), _| s.is_empty() || sessions.contains_key(s));
    }

    fn remove_target(&mut self, target: &str) {
        self.targets.remove(target);
        let attached: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, info)| info.target.as_deref() == Some(target))
            .map(|(s, _)| s.clone())
            .collect();
        for s in attached {
            self.remove_session(&s);
        }
    }

    fn queue_upstream(&mut self, message: String) {
        if self.upstream.len() < MAX_UPSTREAM_QUEUE {
            self.upstream.push(message);
        }
    }

    fn internal_id(&mut self) -> i64 {
        let id = self.next_internal_id;
        self.next_internal_id = if id + 1 >= INTERNAL_ID_END {
            INTERNAL_ID_BASE
        } else {
            id + 1
        };
        id
    }

    /// Commands the relay must send to the browser on its own, oldest first.
    /// Their responses are consumed by the filter and never reach the client.
    pub fn take_upstream(&mut self) -> Vec<String> {
        std::mem::take(&mut self.upstream)
    }

    /// Filters one text message from the client.
    pub fn client_message(&mut self, text: &str) -> ClientAction {
        let Ok(env) = serde_json::from_str::<Envelope<'_>>(text) else {
            return ClientAction::Drop;
        };
        let (Some(id), Some(method)) = (env.id, env.method.as_deref()) else {
            return ClientAction::Drop;
        };
        let session = env.session_id.as_deref();
        if id >= INTERNAL_ID_BASE {
            return Self::refuse(id, session, "request ids from 2000000000 up are reserved");
        }
        if let Some(s) = session
            && !self.sessions.contains_key(s)
        {
            return Self::refuse(id, session, "unknown CDP session");
        }
        if self.pending.len() >= MAX_PENDING {
            return Self::refuse(id, session, "too many outstanding requests");
        }
        let key = (session.unwrap_or_default().to_owned(), id);
        if self.pending.contains_key(&key) {
            return Self::refuse(id, session, "request id is already in flight");
        }
        if let Some(why) = HostPolicy::method_refusal(method) {
            return Self::refuse(id, session, why);
        }
        let verdict = match self.classify(method, session.is_none()) {
            Rule::Pass if HostPolicy::is_sensitive(method) => Rule::Rewrite,
            other => other,
        };
        match verdict {
            Rule::Refuse(why) => Self::refuse(id, session, why),
            Rule::Pass => {
                self.pending.insert(key, Pending::Pass);
                ClientAction::Forward(text.to_owned())
            }
            Rule::Rewrite => self.rewrite(key, method, session, text),
        }
    }

    fn classify(&self, method: &str, browser_level: bool) -> Rule {
        if !browser_level {
            let domain = method.split_once('.').map_or(method, |(d, _)| d);
            if !PAGE_DOMAINS.contains(&domain) {
                return Rule::Refuse("protocol domain is not available in a shared session");
            }
        }
        match method {
            "Target.createBrowserContext" | "Target.disposeBrowserContext" => {
                Rule::Refuse("browser contexts are managed by the session")
            }
            "Target.attachToBrowserTarget"
            | "Target.sendMessageToTarget"
            | "Target.exposeDevToolsProtocol" => Rule::Refuse("not available in a shared session"),
            "Browser.close" => Rule::Refuse("a shared browser cannot be closed by one session"),
            m if m.starts_with("Browser.crash") => Rule::Refuse("crash commands are not allowed"),
            m if m.starts_with("SystemInfo.") => {
                Rule::Refuse("system information is not available")
            }
            "Target.createTarget"
            | "Target.getTargets"
            | "Target.getBrowserContexts"
            | "Target.attachToTarget"
            | "Target.getTargetInfo"
            | "Target.closeTarget"
            | "Target.activateTarget"
            | "Target.autoAttachRelated"
            | "Target.detachFromTarget"
            | "Target.setAutoAttach"
            | "Browser.setDownloadBehavior"
            | "Browser.grantPermissions"
            | "Browser.resetPermissions"
            | "Browser.setPermission"
            | "Browser.getWindowForTarget" => Rule::Rewrite,
            "Target.setDiscoverTargets" | "Browser.getVersion" => Rule::Pass,
            m if m.starts_with("Target.") => {
                Rule::Refuse("unsupported Target command in a shared session")
            }
            m if m.starts_with("Browser.") => {
                Rule::Refuse("unsupported Browser command in a shared session")
            }
            "Storage.getCookies" | "Storage.setCookies" | "Storage.clearCookies" => Rule::Rewrite,
            m if m.starts_with("Storage.") => {
                if browser_level {
                    Rule::Refuse("browser-level command is not allowed")
                } else {
                    Rule::Rewrite
                }
            }
            m if browser_level && !m.is_empty() => {
                Rule::Refuse("browser-level command is not allowed")
            }
            _ => Rule::Pass,
        }
    }

    fn rewrite(
        &mut self,
        key: (String, i64),
        method: &str,
        session: Option<&str>,
        text: &str,
    ) -> ClientAction {
        let id = key.1;
        let Ok(mut msg) = serde_json::from_str::<Value>(text) else {
            return ClientAction::Drop;
        };
        let Some(root) = msg.as_object_mut() else {
            return ClientAction::Drop;
        };
        match root.get("params") {
            Some(Value::Object(_)) => {}
            None | Some(Value::Null) => {
                root.insert("params".into(), Value::Object(Map::new()));
            }
            Some(_) => return Self::refuse(id, session, "params must be an object"),
        }
        let Some(params) = root.get_mut("params").and_then(Value::as_object_mut) else {
            return ClientAction::Drop;
        };
        let mut pending = Pending::Pass;
        match method {
            "Target.createTarget"
            | "Browser.setDownloadBehavior"
            | "Browser.grantPermissions"
            | "Browser.resetPermissions"
            | "Browser.setPermission"
            | "Storage.getCookies"
            | "Storage.setCookies"
            | "Storage.clearCookies" => {
                if let Err(why) = pin_context(params, &self.context) {
                    return Self::refuse(id, session, why);
                }
                if method == "Target.createTarget" {
                    pending = Pending::CreateTarget;
                }
            }
            m if m.starts_with("Storage.") => {
                if params
                    .get("browserContextId")
                    .is_some_and(|c| c.as_str() != Some(self.context.as_str()))
                {
                    return Self::refuse(
                        id,
                        session,
                        "browserContextId belongs to another session",
                    );
                }
            }
            "Target.getTargets" => pending = Pending::GetTargets,
            "Target.getBrowserContexts" => pending = Pending::GetContexts,
            "Target.attachToTarget"
            | "Target.getTargetInfo"
            | "Target.closeTarget"
            | "Target.activateTarget"
            | "Target.autoAttachRelated"
            | "Browser.getWindowForTarget" => {
                let target = match params.get("targetId").and_then(Value::as_str) {
                    Some(t) if self.targets.contains(t) => Some(t.to_owned()),
                    Some(_) => {
                        return Self::refuse(id, session, "target belongs to another session");
                    }
                    None if method == "Browser.getWindowForTarget" && session.is_some() => None,
                    None => return Self::refuse(id, session, "targetId is required"),
                };
                if method == "Target.attachToTarget" {
                    params.insert("flatten".into(), Value::Bool(true));
                    if let Some(target) = target {
                        pending = Pending::Attach { target };
                    }
                }
            }
            "Target.detachFromTarget" => {
                if let Some(s) = params.get("sessionId").and_then(Value::as_str)
                    && !self.sessions.contains_key(s)
                {
                    return Self::refuse(id, session, "unknown CDP session");
                }
                if let Some(t) = params.get("targetId").and_then(Value::as_str)
                    && !self.targets.contains(t)
                {
                    return Self::refuse(id, session, "target belongs to another session");
                }
            }
            "Target.setAutoAttach" => {
                params.insert("flatten".into(), Value::Bool(true));
            }
            _ => {}
        }
        if HostPolicy::is_sensitive(method)
            && let Err(why) = self.host.apply(method, params)
        {
            return Self::refuse(id, session, why);
        }
        self.pending.insert(key, pending);
        ClientAction::Forward(msg.to_string())
    }

    /// Filters one text message from the browser. `None` means do not deliver.
    pub fn browser_message(&mut self, text: &str) -> Option<String> {
        let env = serde_json::from_str::<Envelope<'_>>(text).ok()?;
        match (env.id, env.method.as_deref()) {
            (Some(id), _) => self.response(id, env.session_id.as_deref(), text),
            (None, Some(method)) => self.event(method, env.session_id.as_deref(), text),
            (None, None) => None,
        }
    }

    fn response(&mut self, id: i64, session: Option<&str>, text: &str) -> Option<String> {
        if id >= INTERNAL_ID_BASE {
            return None;
        }
        if let Some(s) = session
            && !self.sessions.contains_key(s)
        {
            return None;
        }
        let key = (session.unwrap_or_default().to_owned(), id);
        let kind = self.pending.remove(&key)?;
        if matches!(kind, Pending::Pass) {
            return Some(text.to_owned());
        }
        let mut msg: Value = serde_json::from_str(text).ok()?;
        if msg.get("error").is_some() {
            return Some(text.to_owned());
        }
        match kind {
            Pending::Pass => {}
            Pending::CreateTarget => {
                if let Some(t) = msg.pointer("/result/targetId").and_then(Value::as_str) {
                    let t = t.to_owned();
                    self.track_target(&t);
                }
            }
            Pending::Attach { target } => {
                if let Some(s) = msg.pointer("/result/sessionId").and_then(Value::as_str) {
                    let s = s.to_owned();
                    self.track_session(&s, Some(&target), session);
                }
            }
            Pending::GetTargets => {
                let own = self.context.clone();
                let mut learned = Vec::new();
                if let Some(infos) = msg
                    .pointer_mut("/result/targetInfos")
                    .and_then(Value::as_array_mut)
                {
                    infos.retain(|i| {
                        let keep = i.get("browserContextId").and_then(Value::as_str)
                            == Some(own.as_str())
                            || i.get("targetId")
                                .and_then(Value::as_str)
                                .is_some_and(|t| self.targets.contains(t));
                        if keep && let Some(t) = i.get("targetId").and_then(Value::as_str) {
                            learned.push(t.to_owned());
                        }
                        keep
                    });
                }
                for t in learned {
                    self.track_target(&t);
                }
            }
            Pending::GetContexts => {
                if let Some(result) = msg.pointer_mut("/result").and_then(Value::as_object_mut) {
                    result.insert("browserContextIds".into(), json!([self.context]));
                }
            }
        }
        Some(msg.to_string())
    }

    fn in_scope(&self, info: &Value) -> bool {
        info.get("browserContextId").and_then(Value::as_str) == Some(self.context.as_str())
            || info
                .get("targetId")
                .and_then(Value::as_str)
                .is_some_and(|t| self.targets.contains(t))
    }

    fn event(&mut self, method: &str, session: Option<&str>, text: &str) -> Option<String> {
        if let Some(s) = session
            && !self.sessions.contains_key(s)
        {
            return None;
        }
        if !method.starts_with("Target.") {
            return session.map(|_| text.to_owned());
        }
        let msg: Value = serde_json::from_str(text).ok()?;
        match method {
            "Target.targetCreated" | "Target.targetInfoChanged" => {
                let info = msg.pointer("/params/targetInfo")?;
                if !self.in_scope(info) {
                    return None;
                }
                if let Some(t) = info.get("targetId").and_then(Value::as_str) {
                    let t = t.to_owned();
                    self.track_target(&t);
                }
                Some(text.to_owned())
            }
            "Target.targetDestroyed" | "Target.targetCrashed" => {
                let target = msg.pointer("/params/targetId").and_then(Value::as_str)?;
                if !self.targets.contains(target) {
                    return None;
                }
                if method == "Target.targetDestroyed" {
                    let target = target.to_owned();
                    self.remove_target(&target);
                }
                Some(text.to_owned())
            }
            "Target.attachedToTarget" => {
                let info = msg.pointer("/params/targetInfo")?;
                let child = msg.pointer("/params/sessionId").and_then(Value::as_str)?;
                let target = info
                    .get("targetId")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                // A child of one of our own sessions is ours by construction; at
                // browser level the target's context decides.
                if session.is_none() && !self.in_scope(info) {
                    let child = child.to_owned();
                    self.release_foreign_attachment(&child);
                    return None;
                }
                let child = child.to_owned();
                if let Some(t) = &target {
                    self.track_target(t);
                }
                self.track_session(&child, target.as_deref(), session);
                Some(text.to_owned())
            }
            "Target.detachedFromTarget" => {
                let s = msg.pointer("/params/sessionId").and_then(Value::as_str)?;
                if !self.sessions.contains_key(s) {
                    return None;
                }
                let s = s.to_owned();
                self.remove_session(&s);
                Some(text.to_owned())
            }
            _ => None,
        }
    }

    /// A browser-wide auto-attach reached a target of another context. The
    /// target may be paused waiting for a debugger, so resume it and drop the
    /// attachment instead of leaving a sibling session stalled.
    fn release_foreign_attachment(&mut self, session: &str) {
        let resume = self.internal_id();
        let detach = self.internal_id();
        self.queue_upstream(
            json!({
                "id": resume,
                "sessionId": session,
                "method": "Runtime.runIfWaitingForDebugger",
            })
            .to_string(),
        );
        self.queue_upstream(
            json!({
                "id": detach,
                "method": "Target.detachFromTarget",
                "params": { "sessionId": session },
            })
            .to_string(),
        );
    }
}

enum Rule {
    Refuse(&'static str),
    Pass,
    Rewrite,
}

fn pin_context(params: &mut Map<String, Value>, context: &str) -> Result<(), &'static str> {
    match params.get("browserContextId") {
        None | Some(Value::Null) => {
            params.insert("browserContextId".into(), Value::String(context.to_owned()));
            Ok(())
        }
        Some(Value::String(c)) if c == context => Ok(()),
        Some(_) => Err("browserContextId belongs to another session"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::path::PathBuf;

    use super::*;

    fn filter() -> ScopedFilter {
        ScopedFilter::new(
            "CTX-A".into(),
            HostPolicy::new(PathBuf::from("/state/downloads/ses_x")),
        )
    }

    fn forwarded(action: ClientAction) -> Value {
        match action {
            ClientAction::Forward(s) => serde_json::from_str(&s).unwrap(),
            other => panic!("expected forward, got {other:?}"),
        }
    }

    fn refused(action: ClientAction) -> String {
        match action {
            ClientAction::Reply(s) => {
                let v: Value = serde_json::from_str(&s).unwrap();
                assert!(v.get("error").is_some(), "{s}");
                s
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    /// Teaches the filter target `T1` and flattened session `S1`.
    fn with_session(f: &mut ScopedFilter) {
        f.client_message(r#"{"id":1,"method":"Target.createTarget","params":{}}"#);
        f.browser_message(r#"{"id":1,"result":{"targetId":"T1"}}"#)
            .unwrap();
        f.client_message(r#"{"id":2,"method":"Target.attachToTarget","params":{"targetId":"T1"}}"#);
        f.browser_message(r#"{"id":2,"result":{"sessionId":"S1"}}"#)
            .unwrap();
    }

    #[test]
    fn create_target_is_pinned_to_the_context() {
        let mut f = filter();
        let sent = forwarded(f.client_message(
            r#"{"id":1,"method":"Target.createTarget","params":{"url":"about:blank"}}"#,
        ));
        assert_eq!(sent["params"]["browserContextId"], "CTX-A");
        let sent = forwarded(f.client_message(r#"{"id":2,"method":"Target.createTarget","params":{"url":"about:blank","browserContextId":"CTX-A"}}"#));
        assert_eq!(sent["params"]["browserContextId"], "CTX-A");
        refused(f.client_message(r#"{"id":3,"method":"Target.createTarget","params":{"url":"about:blank","browserContextId":"CTX-B"}}"#));
        let sent = forwarded(f.client_message(r#"{"id":4,"method":"Target.createTarget"}"#));
        assert_eq!(sent["params"]["browserContextId"], "CTX-A");
        refused(f.client_message(
            r#"{"id":5,"method":"Target.createTarget","params":{"url":"file:///etc/hostname"}}"#,
        ));
    }

    #[test]
    fn dangerous_methods_are_refused() {
        let mut f = filter();
        for method in [
            "Target.createBrowserContext",
            "Target.disposeBrowserContext",
            "Target.attachToBrowserTarget",
            "Target.sendMessageToTarget",
            "Browser.close",
            "Browser.crash",
            "Browser.crashGpuProcess",
            "SystemInfo.getInfo",
            "Tracing.start",
            "Memory.getDOMCounters",
            "IO.read",
            "Storage.getUsageAndQuota",
            "Browser.setWindowBounds",
            "Target.somethingNew",
            "Extensions.loadUnpacked",
            "DOM.setFileInputFiles",
        ] {
            let text = format!(r#"{{"id":9,"method":"{method}","params":{{}}}}"#);
            let reply = refused(f.client_message(&text));
            assert!(reply.contains("\"id\":9"));
        }
    }

    #[test]
    fn page_session_traffic_needs_an_attached_session() {
        let mut f = filter();
        refused(
            f.client_message(r#"{"id":1,"sessionId":"S1","method":"Page.navigate","params":{}}"#),
        );
        f.client_message(r#"{"id":1,"method":"Target.createTarget","params":{}}"#);
        f.browser_message(r#"{"id":1,"result":{"targetId":"T1"}}"#)
            .unwrap();
        let sent = forwarded(f.client_message(
            r#"{"id":2,"method":"Target.attachToTarget","params":{"targetId":"T1"}}"#,
        ));
        assert_eq!(sent["params"]["flatten"], true);
        f.browser_message(r#"{"id":2,"result":{"sessionId":"S1"}}"#)
            .unwrap();
        let sent = forwarded(f.client_message(
            r#"{"id":3,"sessionId":"S1","method":"Page.navigate","params":{"url":"http://example.test/"}}"#,
        ));
        assert_eq!(sent["params"]["url"], "http://example.test/");
        assert!(
            f.browser_message(r#"{"sessionId":"S1","method":"Page.loadEventFired","params":{}}"#)
                .is_some()
        );
        assert!(
            f.browser_message(
                r#"{"sessionId":"OTHER","method":"Page.loadEventFired","params":{}}"#
            )
            .is_none()
        );
        // Page-level calls may not escape through Target either.
        refused(f.client_message(
            r#"{"id":4,"sessionId":"S1","method":"Target.createBrowserContext","params":{}}"#,
        ));
        // Nor navigate to the host's files.
        refused(f.client_message(
            r#"{"id":5,"sessionId":"S1","method":"Page.navigate","params":{"url":"file:///etc/hostname"}}"#,
        ));
    }

    #[test]
    fn page_sessions_use_an_allow_list_of_domains() {
        let mut f = filter();
        with_session(&mut f);
        for method in [
            "Tracing.start",
            "Tracing.end",
            "Memory.getAllTimeSamplingProfile",
            "SystemInfo.getProcessInfo",
            "Extensions.loadUnpacked",
            "NewDomain.doIt",
            "Browser.close",
            "Browser.crash",
            "DOM.setFileInputFiles",
        ] {
            let text = format!(r#"{{"id":10,"sessionId":"S1","method":"{method}","params":{{}}}}"#);
            let reply = refused(f.client_message(&text));
            assert!(reply.contains("\"sessionId\":\"S1\""), "{reply}");
        }
        for method in [
            "Runtime.evaluate",
            "Page.enable",
            "Network.getCookies",
            "IO.read",
        ] {
            let text = format!(r#"{{"id":11,"sessionId":"S1","method":"{method}","params":{{}}}}"#);
            assert_eq!(
                f.client_message(&text),
                ClientAction::Forward(text.clone()),
                "{method}"
            );
            f.browser_message(r#"{"id":11,"sessionId":"S1","result":{}}"#)
                .unwrap();
        }
    }

    #[test]
    fn storage_on_page_sessions_cannot_name_another_context() {
        let mut f = filter();
        with_session(&mut f);
        refused(f.client_message(
            r#"{"id":3,"sessionId":"S1","method":"Storage.getCookies","params":{"browserContextId":"CTX-B"}}"#,
        ));
        refused(f.client_message(
            r#"{"id":4,"sessionId":"S1","method":"Storage.clearDataForOrigin","params":{"origin":"http://example.test","storageTypes":"all","browserContextId":"CTX-B"}}"#,
        ));
        let sent = forwarded(f.client_message(
            r#"{"id":5,"sessionId":"S1","method":"Storage.getCookies","params":{}}"#,
        ));
        assert_eq!(sent["params"]["browserContextId"], "CTX-A");
        let sent = forwarded(f.client_message(
            r#"{"id":6,"sessionId":"S1","method":"Storage.getUsageAndQuota","params":{"origin":"http://example.test"}}"#,
        ));
        assert!(sent["params"].get("browserContextId").is_none());
    }

    #[test]
    fn foreign_targets_cannot_be_attached() {
        let mut f = filter();
        refused(f.client_message(r#"{"id":1,"method":"Target.attachToTarget","params":{"targetId":"FOREIGN","flatten":true}}"#));
        refused(f.client_message(
            r#"{"id":2,"method":"Target.closeTarget","params":{"targetId":"FOREIGN"}}"#,
        ));
        refused(f.client_message(r#"{"id":3,"method":"Target.getTargetInfo","params":{}}"#));
        refused(f.client_message(
            r#"{"id":4,"method":"Target.detachFromTarget","params":{"sessionId":"S-foreign"}}"#,
        ));
    }

    #[test]
    fn get_targets_and_contexts_are_filtered() {
        let mut f = filter();
        f.client_message(r#"{"id":1,"method":"Target.getTargets","params":{}}"#);
        let out = f
            .browser_message(
                r#"{"id":1,"result":{"targetInfos":[
                    {"targetId":"A1","browserContextId":"CTX-A","type":"page"},
                    {"targetId":"B1","browserContextId":"CTX-B","type":"page"},
                    {"targetId":"D1","type":"browser"}]}}"#,
            )
            .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let ids: Vec<&str> = v["result"]["targetInfos"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["targetId"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["A1"]);
        forwarded(f.client_message(
            r#"{"id":2,"method":"Target.attachToTarget","params":{"targetId":"A1"}}"#,
        ));

        f.client_message(r#"{"id":3,"method":"Target.getBrowserContexts"}"#);
        let out = f
            .browser_message(r#"{"id":3,"result":{"browserContextIds":["CTX-A","CTX-B","CTX-C"]}}"#)
            .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["result"]["browserContextIds"], json!(["CTX-A"]));
    }

    #[test]
    fn a_reused_id_cannot_pick_up_another_requests_response() {
        let mut f = filter();
        // The first request is filtered on its way back; the second, with the
        // same id, must not get to replace it.
        forwarded(f.client_message(r#"{"id":1,"method":"Target.getTargets","params":{}}"#));
        refused(f.client_message(r#"{"id":1,"method":"Browser.getVersion"}"#));
        let out = f
            .browser_message(
                r#"{"id":1,"result":{"targetInfos":[{"targetId":"B1","browserContextId":"CTX-B"}]}}"#,
            )
            .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["result"]["targetInfos"], json!([]));
        // Once answered, the id is free again.
        forwarded(f.client_message(r#"{"id":1,"method":"Browser.getVersion"}"#));
        assert!(
            f.browser_message(r#"{"id":1,"result":{"product":"x"}}"#)
                .is_some()
        );
        // Ids are per CDP session.
        with_session(&mut f);
        let text = r#"{"id":1,"sessionId":"S1","method":"Runtime.enable"}"#;
        assert_eq!(f.client_message(text), ClientAction::Forward(text.into()));
        refused(f.client_message(text));
        // A response is matched by session too: an answer without the page
        // session's id does not consume the page-level request.
        assert!(
            f.browser_message(r#"{"id":1,"result":{"product":"x"}}"#)
                .is_none()
        );
        assert!(
            f.browser_message(r#"{"id":1,"sessionId":"S1","result":{}}"#)
                .is_some()
        );
    }

    #[test]
    fn target_events_are_filtered_to_the_context() {
        let mut f = filter();
        let own = r#"{"method":"Target.targetCreated","params":{"targetInfo":{"targetId":"A1","browserContextId":"CTX-A"}}}"#;
        let foreign = r#"{"method":"Target.targetCreated","params":{"targetInfo":{"targetId":"B1","browserContextId":"CTX-B"}}}"#;
        assert!(f.browser_message(own).is_some());
        assert!(f.browser_message(foreign).is_none());
        assert!(
            f.browser_message(r#"{"method":"Target.targetDestroyed","params":{"targetId":"B1"}}"#)
                .is_none()
        );
        assert!(
            f.browser_message(r#"{"method":"Target.targetDestroyed","params":{"targetId":"A1"}}"#)
                .is_some()
        );
        let attached = r#"{"method":"Target.attachedToTarget","params":{"sessionId":"S9","targetInfo":{"targetId":"A2","browserContextId":"CTX-A"},"waitingForDebugger":false}}"#;
        assert!(f.browser_message(attached).is_some());
        let text = r#"{"id":5,"sessionId":"S9","method":"Runtime.enable"}"#;
        assert_eq!(
            f.client_message(text),
            ClientAction::Forward(text.to_owned())
        );
        let foreign_attach = r#"{"method":"Target.attachedToTarget","params":{"sessionId":"S10","targetInfo":{"targetId":"B2","browserContextId":"CTX-B"}}}"#;
        assert!(f.browser_message(foreign_attach).is_none());
        assert!(
            f.browser_message(r#"{"method":"Browser.downloadWillBegin","params":{}}"#)
                .is_none()
        );
    }

    #[test]
    fn target_events_on_page_sessions_are_filtered_too() {
        let mut f = filter();
        with_session(&mut f);
        let foreign = r#"{"sessionId":"S1","method":"Target.targetCreated","params":{"targetInfo":{"targetId":"B1","browserContextId":"CTX-B"}}}"#;
        let own = r#"{"sessionId":"S1","method":"Target.targetCreated","params":{"targetInfo":{"targetId":"A9","browserContextId":"CTX-A"}}}"#;
        assert!(f.browser_message(foreign).is_none());
        assert!(f.browser_message(own).is_some());
        assert!(
            f.browser_message(r#"{"sessionId":"S1","method":"Target.targetInfoChanged","params":{"targetInfo":{"targetId":"B1","browserContextId":"CTX-B"}}}"#)
                .is_none()
        );
        assert!(
            f.browser_message(
                r#"{"sessionId":"S1","method":"Target.targetDestroyed","params":{"targetId":"B1"}}"#
            )
            .is_none()
        );
        assert!(
            f.browser_message(
                r#"{"sessionId":"S1","method":"Target.targetCrashed","params":{"targetId":"B1"}}"#
            )
            .is_none()
        );
        assert!(
            f.browser_message(r#"{"sessionId":"S1","method":"Target.somethingNew","params":{}}"#)
                .is_none()
        );
        // Everything else on a page session is delivered.
        assert!(
            f.browser_message(r#"{"sessionId":"S1","method":"Page.loadEventFired","params":{}}"#)
                .is_some()
        );
    }

    #[test]
    fn a_foreign_attachment_is_resumed_and_detached_upstream() {
        let mut f = filter();
        let foreign = r#"{"method":"Target.attachedToTarget","params":{"sessionId":"SF","targetInfo":{"targetId":"B2","browserContextId":"CTX-B"},"waitingForDebugger":true}}"#;
        assert!(f.browser_message(foreign).is_none());
        let up = f.take_upstream();
        assert_eq!(up.len(), 2);
        let resume: Value = serde_json::from_str(&up[0]).unwrap();
        assert_eq!(resume["method"], "Runtime.runIfWaitingForDebugger");
        assert_eq!(resume["sessionId"], "SF");
        let detach: Value = serde_json::from_str(&up[1]).unwrap();
        assert_eq!(detach["method"], "Target.detachFromTarget");
        assert_eq!(detach["params"]["sessionId"], "SF");
        assert_ne!(resume["id"], detach["id"]);
        assert!(f.take_upstream().is_empty());
        // The relay's own commands are answered silently and cannot be forged by the client.
        let id = resume["id"].as_i64().unwrap();
        assert!(
            f.browser_message(&format!(r#"{{"id":{id},"sessionId":"SF","result":{{}}}}"#))
                .is_none()
        );
        assert!(
            f.browser_message(&format!(r#"{{"id":{},"result":{{}}}}"#, detach["id"]))
                .is_none()
        );
        refused(f.client_message(&format!(r#"{{"id":{id},"method":"Browser.getVersion"}}"#)));
        // The foreign session stays unusable for the client.
        refused(f.client_message(
            r#"{"id":1,"sessionId":"SF","method":"Runtime.evaluate","params":{}}"#,
        ));
        // Own attachments are not touched.
        let own = r#"{"method":"Target.attachedToTarget","params":{"sessionId":"S9","targetInfo":{"targetId":"A2","browserContextId":"CTX-A"}}}"#;
        assert!(f.browser_message(own).is_some());
        assert!(f.take_upstream().is_empty());
    }

    #[test]
    fn child_sessions_inherit_scope() {
        let mut f = filter();
        f.browser_message(r#"{"method":"Target.attachedToTarget","params":{"sessionId":"S1","targetInfo":{"targetId":"A1","browserContextId":"CTX-A"}}}"#).unwrap();
        let child = r#"{"sessionId":"S1","method":"Target.attachedToTarget","params":{"sessionId":"S2","targetInfo":{"targetId":"W1","type":"worker"}}}"#;
        assert!(f.browser_message(child).is_some());
        let text = r#"{"id":1,"sessionId":"S2","method":"Runtime.enable"}"#;
        assert_eq!(
            f.client_message(text),
            ClientAction::Forward(text.to_owned())
        );
        f.browser_message(r#"{"sessionId":"S1","method":"Target.detachedFromTarget","params":{"sessionId":"S2"}}"#).unwrap();
        refused(f.client_message(text));
    }

    #[test]
    fn detach_and_destroy_purge_unanswered_requests() {
        let mut f = filter();
        with_session(&mut f);
        // Child session of S1.
        f.browser_message(r#"{"sessionId":"S1","method":"Target.attachedToTarget","params":{"sessionId":"S2","targetInfo":{"targetId":"W1","type":"worker"}}}"#).unwrap();
        for i in 0..50 {
            for s in ["S1", "S2"] {
                let text = format!(
                    r#"{{"id":{i},"sessionId":"{s}","method":"Runtime.evaluate","params":{{}}}}"#
                );
                forwarded(f.client_message(&text));
            }
        }
        assert_eq!(f.pending.len(), 100);
        // The worker goes away: its requests are dropped.
        f.browser_message(r#"{"sessionId":"S1","method":"Target.detachedFromTarget","params":{"sessionId":"S2"}}"#).unwrap();
        assert_eq!(f.pending.len(), 50);
        // The page goes away with its target: requests and child sessions are dropped.
        f.browser_message(r#"{"method":"Target.targetDestroyed","params":{"targetId":"T1"}}"#)
            .unwrap();
        assert!(f.pending.is_empty());
        assert!(f.sessions.is_empty());
        // Late answers for purged requests are not delivered.
        assert!(
            f.browser_message(r#"{"id":1,"sessionId":"S1","result":{}}"#)
                .is_none()
        );
    }

    #[test]
    fn the_request_table_is_bounded() {
        let mut f = filter();
        for i in 0..MAX_PENDING {
            let text = format!(r#"{{"id":{i},"method":"Browser.getVersion"}}"#);
            if i < MAX_PENDING {
                assert!(matches!(f.client_message(&text), ClientAction::Forward(_)));
            }
        }
        refused(f.client_message(r#"{"id":99999,"method":"Browser.getVersion"}"#));
    }

    #[test]
    fn context_scoped_helpers_and_storage() {
        let mut f = filter();
        let sent =
            forwarded(f.client_message(r#"{"id":1,"method":"Storage.getCookies","params":{}}"#));
        assert_eq!(sent["params"]["browserContextId"], "CTX-A");
        refused(f.client_message(
            r#"{"id":2,"method":"Storage.getCookies","params":{"browserContextId":"CTX-B"}}"#,
        ));
        let sent = forwarded(f.client_message(
            r#"{"id":3,"method":"Browser.setDownloadBehavior","params":{"behavior":"deny"}}"#,
        ));
        assert_eq!(sent["params"]["browserContextId"], "CTX-A");
        let text = r#"{"id":4,"method":"Browser.getVersion"}"#;
        assert_eq!(
            f.client_message(text),
            ClientAction::Forward(text.to_owned())
        );
        assert!(
            f.browser_message(r#"{"id":4,"result":{"product":"x"}}"#)
                .is_some()
        );
        // Responses nobody asked for are dropped.
        assert!(f.browser_message(r#"{"id":77,"result":{}}"#).is_none());
        let sent = forwarded(f.client_message(r#"{"id":5,"method":"Target.setAutoAttach","params":{"autoAttach":true,"waitForDebuggerOnStart":false}}"#));
        assert_eq!(sent["params"]["flatten"], true);
    }

    #[test]
    fn downloads_are_forced_into_the_session_directory() {
        let mut f = filter();
        let sent = forwarded(f.client_message(
            r#"{"id":1,"method":"Browser.setDownloadBehavior","params":{"behavior":"allowAndName","downloadPath":"/etc/cron.d","browserContextId":"CTX-A"}}"#,
        ));
        assert_eq!(sent["params"]["downloadPath"], "/state/downloads/ses_x");
        assert_eq!(sent["params"]["browserContextId"], "CTX-A");
        refused(f.client_message(
            r#"{"id":2,"method":"Browser.setDownloadBehavior","params":{"behavior":"allow","browserContextId":"CTX-B"}}"#,
        ));
        f.browser_message(r#"{"id":1,"result":{}}"#).unwrap();
        with_session(&mut f);
        let sent = forwarded(f.client_message(
            r#"{"id":3,"sessionId":"S1","method":"Page.setDownloadBehavior","params":{"behavior":"allow","downloadPath":"/tmp"}}"#,
        ));
        assert_eq!(sent["params"]["downloadPath"], "/state/downloads/ses_x");
    }

    #[test]
    fn garbage_is_dropped() {
        let mut f = filter();
        assert_eq!(f.client_message("not json"), ClientAction::Drop);
        assert_eq!(
            f.client_message(r#"{"method":"Target.getTargets"}"#),
            ClientAction::Drop
        );
        assert!(f.browser_message("{").is_none());
    }
}
