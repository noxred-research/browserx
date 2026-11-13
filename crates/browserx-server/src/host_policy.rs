//! Host-protection rules for the CDP relay.
//!
//! A relay client drives a browser that runs as the worker's uid, with the
//! worker's filesystem and network behind it. These rules keep a client from
//! turning the browser into a tool against the host. They apply to **every**
//! relay, dedicated and shared, regardless of which target or CDP session a
//! command addresses:
//!
//! * navigation and target creation accept only `http`, `https`, `data`,
//!   `blob`, `javascript` and `about:blank`/`about:srcdoc` URLs, so `file:`,
//!   `filesystem:`, `view-source:`, `chrome:`, `chrome-untrusted:`, `devtools:`
//!   and the `about:` aliases of internal pages are refused;
//! * `Target.createBrowserContext` cannot carry `proxyServer` or
//!   `proxyBypassList`, which would bypass the session's egress forwarder;
//! * file selection (`DOM.setFileInputFiles`, `Input.dispatchDragEvent` with
//!   files) and extension loading (`Extensions.*`) are refused;
//! * downloads are forced into a per-session directory under the state dir;
//! * `Tracing.*`, `Memory.*`, `SystemInfo.*`, `Browser.close` and
//!   `Browser.crash*` are refused (release a session through the API).
//!
//! Frames are inspected as JSON text. Binary client frames are refused because
//! the browser would read them as CBOR, which is not inspected here. Commands
//! that need a parameter check are forwarded re-serialized from the parsed
//! value, so the browser sees exactly what was checked even when the original
//! text carried duplicate keys.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::scope::ClientAction;

/// The fields every relay needs from a client command.
#[derive(Deserialize)]
pub(crate) struct Envelope<'a> {
    pub id: Option<i64>,
    #[serde(borrow)]
    pub method: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow, rename = "sessionId")]
    pub session_id: Option<std::borrow::Cow<'a, str>>,
}

/// A CDP error reply for command `id`.
pub(crate) fn refusal_reply(id: i64, session: Option<&str>, message: &str) -> String {
    let mut msg = json!({
        "id": id,
        "error": { "code": -32000, "message": message }
    });
    if let (Some(s), Some(obj)) = (session, msg.as_object_mut()) {
        obj.insert("sessionId".into(), Value::String(s.to_owned()));
    }
    msg.to_string()
}

/// Outcome of inspecting one command.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Forward the original text.
    Pass,
    /// Forward this text instead.
    Rewrite(String),
    /// Answer the client with an error.
    Refuse(&'static str),
}

/// The rules, bound to one session's download directory.
#[derive(Clone, Debug)]
pub struct HostPolicy {
    download_dir: PathBuf,
}

impl HostPolicy {
    /// Rules that force downloads into `download_dir`.
    #[must_use]
    pub fn new(download_dir: PathBuf) -> Self {
        Self { download_dir }
    }

    /// The directory downloads are forced into.
    #[must_use]
    pub fn download_dir(&self) -> &Path {
        &self.download_dir
    }

    /// Methods refused outright.
    #[must_use]
    pub fn method_refusal(method: &str) -> Option<&'static str> {
        match method {
            "Browser.close" => Some("the browser is released through the API, not closed over CDP"),
            "Target.sendMessageToTarget" => {
                Some("non-flat target messaging cannot be inspected; use flattened sessions")
            }
            "DOM.setFileInputFiles" | "Page.handleFileChooser" => {
                Some("file selection from the host filesystem is not allowed")
            }
            m if m.starts_with("Browser.crash") => Some("crash commands are not allowed"),
            m if m.starts_with("Extensions.") => Some("extensions cannot be loaded"),
            m if m.starts_with("Tracing.") => Some("tracing exposes browser-wide data"),
            m if m.starts_with("Memory.") => Some("memory commands expose browser-wide data"),
            m if m.starts_with("SystemInfo.") => Some("system information is not available"),
            _ => None,
        }
    }

    /// Whether `method` needs its parameters checked or rewritten.
    #[must_use]
    pub fn is_sensitive(method: &str) -> bool {
        matches!(
            method,
            "Target.createBrowserContext"
                | "Target.createTarget"
                | "Page.navigate"
                | "Network.loadNetworkResource"
                | "Fetch.continueRequest"
                | "Input.dispatchDragEvent"
                | "Browser.setDownloadBehavior"
                | "Page.setDownloadBehavior"
        )
    }

    /// Checks (and where needed rewrites) the parameters of a sensitive command.
    pub fn apply(&self, method: &str, params: &mut Map<String, Value>) -> Result<(), &'static str> {
        match method {
            "Target.createBrowserContext" => {
                let set = |k: &str| params.get(k).is_some_and(|v| !v.is_null());
                if set("proxyServer") || set("proxyBypassList") {
                    return Err("proxy settings are managed by the session");
                }
            }
            "Target.createTarget"
            | "Page.navigate"
            | "Network.loadNetworkResource"
            | "Fetch.continueRequest" => {
                if let Some(Value::String(url)) = params.get("url") {
                    let empty_ok = method == "Target.createTarget" && url.is_empty();
                    if !empty_ok && !url_allowed(url) {
                        return Err("URL scheme is not allowed");
                    }
                }
            }
            "Input.dispatchDragEvent" => {
                let files = params.get("data").and_then(|d| d.get("files"));
                match files {
                    None | Some(Value::Null) => {}
                    Some(Value::Array(a)) if a.is_empty() => {}
                    Some(_) => return Err("dragging host files into a page is not allowed"),
                }
            }
            "Browser.setDownloadBehavior" | "Page.setDownloadBehavior" => {
                match params.get("behavior").and_then(Value::as_str) {
                    Some("deny") => {
                        params.remove("downloadPath");
                    }
                    Some("allow" | "allowAndName" | "default") => {
                        if params.get("behavior").and_then(Value::as_str) == Some("default") {
                            params.insert("behavior".into(), Value::String("allow".into()));
                        }
                        params.insert(
                            "downloadPath".into(),
                            Value::String(self.download_dir.to_string_lossy().into_owned()),
                        );
                    }
                    _ => return Err("unknown download behavior"),
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Inspects one command text for a relay that applies no other rules.
    pub(crate) fn inspect(&self, method: &str, text: &str) -> Verdict {
        if let Some(why) = Self::method_refusal(method) {
            return Verdict::Refuse(why);
        }
        if !Self::is_sensitive(method) {
            return Verdict::Pass;
        }
        let Ok(mut msg) = serde_json::from_str::<Value>(text) else {
            return Verdict::Refuse("malformed message");
        };
        let Some(root) = msg.as_object_mut() else {
            return Verdict::Refuse("malformed message");
        };
        match root.get("params") {
            Some(Value::Object(_)) => {}
            None | Some(Value::Null) => {
                root.insert("params".into(), Value::Object(Map::new()));
            }
            Some(_) => return Verdict::Refuse("params must be an object"),
        }
        let Some(params) = root.get_mut("params").and_then(Value::as_object_mut) else {
            return Verdict::Refuse("params must be an object");
        };
        match self.apply(method, params) {
            Ok(()) => Verdict::Rewrite(msg.to_string()),
            Err(why) => Verdict::Refuse(why),
        }
    }
}

/// Whether a navigation URL may be handed to the browser.
///
/// Mirrors the browser's URL parsing for the scheme only: leading control and
/// space characters are skipped and tabs and newlines are ignored, so
/// `" \tFILE:///x"` is read as `file:` and refused. A string without a
/// scheme is refused too.
#[must_use]
pub fn url_allowed(url: &str) -> bool {
    let mut chars = url
        .chars()
        .skip_while(|c| *c <= ' ')
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'));
    let mut scheme = String::new();
    loop {
        match chars.next() {
            Some(':') => break,
            Some(c)
                if scheme.len() < 32
                    && (c.is_ascii_alphabetic()
                        || (!scheme.is_empty()
                            && (c.is_ascii_digit() || matches!(c, '+' | '-' | '.')))) =>
            {
                scheme.push(c.to_ascii_lowercase());
            }
            _ => return false,
        }
    }
    match scheme.as_str() {
        "http" | "https" | "data" | "blob" | "javascript" => true,
        "about" => {
            let rest: String = chars
                .take(16)
                .take_while(|c| !matches!(c, '?' | '#'))
                .map(|c| c.to_ascii_lowercase())
                .collect();
            matches!(rest.as_str(), "blank" | "srcdoc")
        }
        _ => false,
    }
}

/// The filter of a dedicated relay: the host-protection rules and nothing else.
pub struct DedicatedFilter {
    policy: HostPolicy,
}

impl DedicatedFilter {
    /// A filter applying `policy`.
    #[must_use]
    pub fn new(policy: HostPolicy) -> Self {
        Self { policy }
    }

    /// Filters one text message from the client.
    pub fn client_message(&self, text: &str) -> ClientAction {
        let Ok(env) = serde_json::from_str::<Envelope<'_>>(text) else {
            return ClientAction::Drop;
        };
        let (Some(id), Some(method)) = (env.id, env.method.as_deref()) else {
            return ClientAction::Drop;
        };
        match self.policy.inspect(method, text) {
            Verdict::Pass => ClientAction::Forward(text.to_owned()),
            Verdict::Rewrite(out) => ClientAction::Forward(out),
            Verdict::Refuse(why) => ClientAction::Reply(refusal_reply(
                id,
                env.session_id.as_deref(),
                &format!("refused by the host-protection policy: {why}"),
            )),
        }
    }

    /// The download directory this filter forces.
    #[must_use]
    pub fn download_dir(&self) -> &Path {
        self.policy.download_dir()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn filter() -> DedicatedFilter {
        DedicatedFilter::new(HostPolicy::new(PathBuf::from("/state/downloads/ses_x")))
    }

    fn forwarded(action: ClientAction) -> Value {
        match action {
            ClientAction::Forward(s) => serde_json::from_str(&s).unwrap(),
            other => panic!("expected forward, got {other:?}"),
        }
    }

    fn refused(action: ClientAction) -> Value {
        match action {
            ClientAction::Reply(s) => {
                let v: Value = serde_json::from_str(&s).unwrap();
                assert!(v.get("error").is_some(), "{s}");
                v
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn schemes_are_allow_listed() {
        for ok in [
            "http://example.test/",
            "HTTPS://example.test/",
            "about:blank",
            "about:blank#x",
            "about:srcdoc",
            "data:text/html,hi",
            "blob:http://example.test/uuid",
            "javascript:void(0)",
            "  \thttp://example.test/",
            "ht\ntp://example.test/",
        ] {
            assert!(url_allowed(ok), "{ok:?} must be allowed");
        }
        for bad in [
            "",
            "file:///etc/hostname",
            "FILE:///etc/hostname",
            " \tfile:///etc/hostname",
            "fi\nle:///etc/hostname",
            "filesystem:http://example.test/temporary/x",
            "view-source:http://example.test/",
            "chrome://gpu",
            "chrome-untrusted://x/",
            "chrome-extension://abc/",
            "devtools://devtools/bundled/inspector.html",
            "about:version",
            "about:gpu",
            "about:blank2",
            "/etc/hostname",
            "example.test/path",
            "\u{a0}file:///etc/hostname",
            "ws://example.test/",
            "ftp://example.test/",
        ] {
            assert!(!url_allowed(bad), "{bad:?} must be refused");
        }
    }

    #[test]
    fn navigation_and_target_creation_check_the_url() {
        let f = filter();
        for method in [
            "Page.navigate",
            "Target.createTarget",
            "Network.loadNetworkResource",
        ] {
            let text = format!(
                r#"{{"id":1,"method":"{method}","params":{{"url":"file:///etc/hostname"}}}}"#
            );
            let reply = refused(f.client_message(&text));
            assert_eq!(reply["id"], 1);
            let text = format!(
                r#"{{"id":2,"sessionId":"S","method":"{method}","params":{{"url":"http://example.test/"}}}}"#
            );
            let sent = forwarded(f.client_message(&text));
            assert_eq!(sent["params"]["url"], "http://example.test/");
        }
        // An empty target URL means about:blank.
        forwarded(
            f.client_message(r#"{"id":3,"method":"Target.createTarget","params":{"url":""}}"#),
        );
        // Escaped method names are decoded before matching.
        refused(f.client_message(
            r#"{"id":4,"method":"Page.nav\u0069gate","params":{"url":"file:///x"}}"#,
        ));
        // Duplicate keys cannot hide a value: the checked value is what is sent.
        let sent = forwarded(f.client_message(
            r#"{"id":5,"method":"Page.navigate","params":{"url":"file:///x","url":"http://example.test/"}}"#,
        ));
        assert_eq!(sent["params"]["url"], "http://example.test/");
        assert_eq!(
            f.client_message(r#"{"id":6,"method":"Page.navigate","method":"Page.reload"}"#),
            ClientAction::Drop,
            "duplicate envelope keys are dropped"
        );
    }

    #[test]
    fn browser_contexts_cannot_carry_proxy_settings() {
        let f = filter();
        for params in [
            r#"{"proxyServer":"direct://"}"#,
            r#"{"proxyBypassList":"*"}"#,
            r#"{"proxy\u0053erver":"socks5://127.0.0.1:9"}"#,
        ] {
            let text =
                format!(r#"{{"id":1,"method":"Target.createBrowserContext","params":{params}}}"#);
            refused(f.client_message(&text));
        }
        forwarded(f.client_message(
            r#"{"id":2,"method":"Target.createBrowserContext","params":{"disposeOnDetach":true,"proxyServer":null}}"#,
        ));
        forwarded(f.client_message(r#"{"id":3,"method":"Target.createBrowserContext"}"#));
    }

    #[test]
    fn host_files_and_extensions_are_refused() {
        let f = filter();
        for text in [
            r#"{"id":1,"method":"DOM.setFileInputFiles","params":{"files":["/etc/hostname"],"objectId":"x"}}"#,
            r#"{"id":2,"method":"Page.handleFileChooser","params":{"action":"accept","files":["/etc/hostname"]}}"#,
            r#"{"id":3,"method":"Input.dispatchDragEvent","params":{"type":"drop","x":1,"y":1,"data":{"items":[],"files":["/etc/hostname"],"dragOperationsMask":1}}}"#,
            r#"{"id":4,"method":"Extensions.loadUnpacked","params":{"path":"/tmp/x"}}"#,
        ] {
            refused(f.client_message(text));
        }
        forwarded(f.client_message(
            r#"{"id":5,"method":"Input.dispatchDragEvent","params":{"type":"drop","x":1,"y":1,"data":{"items":[],"dragOperationsMask":1}}}"#,
        ));
    }

    #[test]
    fn browser_wide_and_destructive_commands_are_refused() {
        let f = filter();
        for method in [
            "Tracing.start",
            "Tracing.end",
            "Memory.getAllTimeSamplingProfile",
            "SystemInfo.getInfo",
            "Browser.close",
            "Browser.crash",
            "Browser.crashGpuProcess",
            "Target.sendMessageToTarget",
        ] {
            let text = format!(r#"{{"id":7,"sessionId":"S","method":"{method}","params":{{}}}}"#);
            let reply = refused(f.client_message(&text));
            assert_eq!(reply["id"], 7);
            assert_eq!(reply["sessionId"], "S");
        }
        for method in [
            "Browser.getVersion",
            "Runtime.evaluate",
            "Browser.setWindowBounds",
        ] {
            let text = format!(r#"{{"id":8,"method":"{method}","params":{{}}}}"#);
            let text2 = text.clone();
            assert_eq!(f.client_message(&text), ClientAction::Forward(text2));
        }
    }

    #[test]
    fn downloads_are_forced_into_the_session_directory() {
        let f = filter();
        for method in ["Browser.setDownloadBehavior", "Page.setDownloadBehavior"] {
            let text = format!(
                r#"{{"id":1,"method":"{method}","params":{{"behavior":"allow","downloadPath":"/etc/cron.d"}}}}"#
            );
            let sent = forwarded(f.client_message(&text));
            assert_eq!(sent["params"]["downloadPath"], "/state/downloads/ses_x");
            let text =
                format!(r#"{{"id":2,"method":"{method}","params":{{"behavior":"allowAndName"}}}}"#);
            let sent = forwarded(f.client_message(&text));
            assert_eq!(sent["params"]["downloadPath"], "/state/downloads/ses_x");
            let text =
                format!(r#"{{"id":3,"method":"{method}","params":{{"behavior":"default"}}}}"#);
            let sent = forwarded(f.client_message(&text));
            assert_eq!(sent["params"]["behavior"], "allow");
            assert_eq!(sent["params"]["downloadPath"], "/state/downloads/ses_x");
            let text = format!(
                r#"{{"id":4,"method":"{method}","params":{{"behavior":"deny","downloadPath":"/etc"}}}}"#
            );
            let sent = forwarded(f.client_message(&text));
            assert!(sent["params"].get("downloadPath").is_none());
            let text = format!(r#"{{"id":5,"method":"{method}","params":{{"behavior":"bogus"}}}}"#);
            refused(f.client_message(&text));
        }
    }

    #[test]
    fn garbage_is_dropped() {
        let f = filter();
        assert_eq!(f.client_message("not json"), ClientAction::Drop);
        assert_eq!(
            f.client_message(r#"{"method":"Page.navigate"}"#),
            ClientAction::Drop
        );
        assert_eq!(
            f.client_message(r#"{"id":1,"method":"Page.navigate"} trailing"#),
            ClientAction::Drop
        );
    }
}
