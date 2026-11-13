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
//! * Responses and events that mention targets or contexts are filtered to the
//!   session's own; unknown browser-level events are dropped.
//! * Page-session traffic (`sessionId`) is allowed only for sessions that were
//!   attached to targets of this context (directly, via auto-attach, or as child
//!   sessions of such a session).
//!
//! This confines a cooperative client; it is not a boundary against a hostile
//! tenant (see `Isolation::SharedBrowser`).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use serde_json::{Map, Value, json};

/// Outstanding requests tracked per connection.
const MAX_PENDING: usize = 4096;
/// Targets and sessions remembered per connection.
const MAX_TRACKED: usize = 65_536;

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

#[derive(Deserialize)]
struct Envelope<'a> {
    id: Option<i64>,
    #[serde(borrow)]
    method: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "sessionId")]
    session_id: Option<Cow<'a, str>>,
}

enum Pending {
    Pass,
    CreateTarget,
    GetTargets,
    GetContexts,
    Attach,
}

/// Per-connection filter state.
pub struct ScopedFilter {
    context: String,
    targets: HashSet<String>,
    sessions: HashSet<String>,
    pending: HashMap<i64, Pending>,
}

impl ScopedFilter {
    /// A filter confined to browser context `context`.
    #[must_use]
    pub fn new(context: String) -> Self {
        Self {
            context,
            targets: HashSet::new(),
            sessions: HashSet::new(),
            pending: HashMap::new(),
        }
    }

    fn refuse(id: i64, session: Option<&str>, why: &str) -> ClientAction {
        let mut msg = json!({
            "id": id,
            "error": { "code": -32000, "message": format!("refused by the scoped relay: {why}") }
        });
        if let (Some(s), Some(obj)) = (session, msg.as_object_mut()) {
            obj.insert("sessionId".into(), Value::String(s.to_owned()));
        }
        ClientAction::Reply(msg.to_string())
    }

    fn track_target(&mut self, id: &str) {
        if self.targets.len() < MAX_TRACKED {
            self.targets.insert(id.to_owned());
        }
    }

    fn track_session(&mut self, id: &str) {
        if self.sessions.len() < MAX_TRACKED {
            self.sessions.insert(id.to_owned());
        }
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
        if let Some(s) = session
            && !self.sessions.contains(s)
        {
            return Self::refuse(id, session, "unknown CDP session");
        }
        if self.pending.len() >= MAX_PENDING {
            return Self::refuse(id, session, "too many outstanding requests");
        }
        let verdict = self.classify(method, session.is_none());
        match verdict {
            Rule::Refuse(why) => Self::refuse(id, session, why),
            Rule::Pass => {
                self.pending.insert(id, Pending::Pass);
                ClientAction::Forward(text.to_owned())
            }
            Rule::Rewrite => self.rewrite(id, method, session, text),
        }
    }

    fn classify(&self, method: &str, browser_level: bool) -> Rule {
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
            "Storage.getCookies" | "Storage.setCookies" | "Storage.clearCookies" => {
                if browser_level {
                    Rule::Rewrite
                } else {
                    Rule::Pass
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
        id: i64,
        method: &str,
        session: Option<&str>,
        text: &str,
    ) -> ClientAction {
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
            "Target.getTargets" => pending = Pending::GetTargets,
            "Target.getBrowserContexts" => pending = Pending::GetContexts,
            "Target.attachToTarget"
            | "Target.getTargetInfo"
            | "Target.closeTarget"
            | "Target.activateTarget"
            | "Target.autoAttachRelated"
            | "Browser.getWindowForTarget" => {
                match params.get("targetId").and_then(Value::as_str) {
                    Some(t) if self.targets.contains(t) => {}
                    Some(_) => {
                        return Self::refuse(id, session, "target belongs to another session");
                    }
                    None if method == "Browser.getWindowForTarget" && session.is_some() => {}
                    None => return Self::refuse(id, session, "targetId is required"),
                }
                if method == "Target.attachToTarget" {
                    params.insert("flatten".into(), Value::Bool(true));
                    pending = Pending::Attach;
                }
            }
            "Target.detachFromTarget" => {
                if let Some(s) = params.get("sessionId").and_then(Value::as_str)
                    && !self.sessions.contains(s)
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
        self.pending.insert(id, pending);
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
        let kind = self.pending.remove(&id);
        match (session, &kind) {
            (Some(s), _) if !self.sessions.contains(s) => return None,
            (None, None) => return None,
            (_, None | Some(Pending::Pass)) => return Some(text.to_owned()),
            _ => {}
        }
        let kind = kind?;
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
            Pending::Attach => {
                if let Some(s) = msg.pointer("/result/sessionId").and_then(Value::as_str) {
                    let s = s.to_owned();
                    self.track_session(&s);
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
        if let Some(s) = session {
            if !self.sessions.contains(s) {
                return None;
            }
            if method == "Target.attachedToTarget" || method == "Target.detachedFromTarget" {
                let msg: Value = serde_json::from_str(text).ok()?;
                if method == "Target.attachedToTarget" {
                    if let Some(child) = msg.pointer("/params/sessionId").and_then(Value::as_str) {
                        let child = child.to_owned();
                        self.track_session(&child);
                    }
                    if let Some(t) = msg
                        .pointer("/params/targetInfo/targetId")
                        .and_then(Value::as_str)
                    {
                        let t = t.to_owned();
                        self.track_target(&t);
                    }
                } else if let Some(child) = msg.pointer("/params/sessionId").and_then(Value::as_str)
                {
                    self.sessions.remove(child);
                }
            }
            return Some(text.to_owned());
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
                    self.targets.remove(&target);
                }
                Some(text.to_owned())
            }
            "Target.attachedToTarget" => {
                let info = msg.pointer("/params/targetInfo")?;
                if !self.in_scope(info) {
                    return None;
                }
                if let Some(t) = info.get("targetId").and_then(Value::as_str) {
                    let t = t.to_owned();
                    self.track_target(&t);
                }
                if let Some(s) = msg.pointer("/params/sessionId").and_then(Value::as_str) {
                    let s = s.to_owned();
                    self.track_session(&s);
                }
                Some(text.to_owned())
            }
            "Target.detachedFromTarget" => {
                let s = msg.pointer("/params/sessionId").and_then(Value::as_str)?;
                if !self.sessions.contains(s) {
                    return None;
                }
                let s = s.to_owned();
                self.sessions.remove(&s);
                Some(text.to_owned())
            }
            _ => None,
        }
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

    use super::*;

    fn filter() -> ScopedFilter {
        ScopedFilter::new("CTX-A".into())
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

    #[test]
    fn create_target_is_pinned_to_the_context() {
        let mut f = filter();
        let sent = forwarded(f.client_message(
            r#"{"id":1,"method":"Target.createTarget","params":{"url":"about:blank"}}"#,
        ));
        assert_eq!(sent["params"]["browserContextId"], "CTX-A");
        let sent = forwarded(f.client_message(r#"{"id":2,"method":"Target.createTarget","params":{"url":"x","browserContextId":"CTX-A"}}"#));
        assert_eq!(sent["params"]["browserContextId"], "CTX-A");
        refused(f.client_message(r#"{"id":3,"method":"Target.createTarget","params":{"url":"x","browserContextId":"CTX-B"}}"#));
        let sent = forwarded(f.client_message(r#"{"id":4,"method":"Target.createTarget"}"#));
        assert_eq!(sent["params"]["browserContextId"], "CTX-A");
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
            "IO.read",
            "Storage.getUsageAndQuota",
            "Browser.setWindowBounds",
            "Target.somethingNew",
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
        // create + attach learns the session
        f.client_message(r#"{"id":1,"method":"Target.createTarget","params":{}}"#);
        f.browser_message(r#"{"id":1,"result":{"targetId":"T1"}}"#)
            .unwrap();
        let sent = forwarded(f.client_message(
            r#"{"id":2,"method":"Target.attachToTarget","params":{"targetId":"T1"}}"#,
        ));
        assert_eq!(sent["params"]["flatten"], true);
        f.browser_message(r#"{"id":2,"result":{"sessionId":"S1"}}"#)
            .unwrap();
        let text = r#"{"id":3,"sessionId":"S1","method":"Page.navigate","params":{"url":"x"}}"#;
        assert_eq!(
            f.client_message(text),
            ClientAction::Forward(text.to_owned())
        );
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
        // A1 is now attachable.
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
        // Auto-attach of an own target teaches the session.
        let attached = r#"{"method":"Target.attachedToTarget","params":{"sessionId":"S9","targetInfo":{"targetId":"A2","browserContextId":"CTX-A"},"waitingForDebugger":false}}"#;
        assert!(f.browser_message(attached).is_some());
        let text = r#"{"id":5,"sessionId":"S9","method":"Runtime.enable"}"#;
        assert_eq!(
            f.client_message(text),
            ClientAction::Forward(text.to_owned())
        );
        let foreign_attach = r#"{"method":"Target.attachedToTarget","params":{"sessionId":"S10","targetInfo":{"targetId":"B2","browserContextId":"CTX-B"}}}"#;
        assert!(f.browser_message(foreign_attach).is_none());
        // Unknown browser-level events are dropped.
        assert!(
            f.browser_message(r#"{"method":"Browser.downloadWillBegin","params":{}}"#)
                .is_none()
        );
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
