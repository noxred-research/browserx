//! Collecting the [`Features`] the action classifier needs from a live element. One fixed
//! script runs inside the page; nothing the model wrote ever reaches it.

// Remove once the action gate calls these; until then only the tests do.

use serde_json::{Value, json};

use super::conn::{Conn, TabRef};
use crate::classifier::Features;
use crate::error::{ToolError, ToolResult};

/// The longest accessible name returned, in UTF-16 units.
const NAME_CAP: u32 = 160;
/// The longest URL returned, in UTF-16 units.
const URL_CAP: u32 = 2048;

/// Describes `this` (an element) as a JSON object shaped like [`Features`].
///
/// The page is untrusted, so the script uses attribute reads (`getAttribute`) instead of the
/// form properties a hostile page can shadow with a field named `action`; every URL is resolved
/// against the document's base and clipped; the form is the element's own form or the closest
/// `form` ancestor. When the element is not itself a control (a `span` inside a link or button)
/// the closest enclosing actuator is described, because that is what a click activates.
const ELEMENT_FEATURES: &str = r#"function (nameCap, urlCap) {
  function clip(text, max) {
    text = text == null ? '' : String(text);
    return text.length > max ? text.slice(0, max) : text;
  }
  function attr(el, name) { return el && el.getAttribute ? el.getAttribute(name) : null; }
  function absolute(value) {
    if (value == null || String(value).trim() === '') { return null; }
    try { return clip(new URL(String(value), document.baseURI).href, urlCap); } catch (e) { return null; }
  }
  function lower(value) { return value == null ? '' : String(value).trim().toLowerCase(); }
  var el = this;
  var CONTROL = {INPUT: 1, SELECT: 1, TEXTAREA: 1, BUTTON: 1};
  if (!CONTROL[el.tagName]) {
    var actuator = el.closest('a[href],area[href],button,summary,[role="button"],[role="link"],[role="menuitem"],[role="tab"]');
    if (actuator) { el = actuator; }
  }
  var tag = lower(el.tagName);
  var type = (tag === 'input' || tag === 'button') ? lower(attr(el, 'type') || el.type) : '';
  if (tag === 'input' && type === '') { type = 'text'; }
  var form = el.form || el.closest('form');
  function implicitRole() {
    var explicit = lower((attr(el, 'role') || '').split(/\s+/)[0]);
    if (explicit) { return explicit; }
    if ((tag === 'a' || tag === 'area') && el.hasAttribute('href')) { return 'link'; }
    if (tag === 'button' || tag === 'summary') { return 'button'; }
    if (tag === 'select') { return (el.multiple || el.size > 1) ? 'listbox' : 'combobox'; }
    if (tag === 'textarea') { return 'textbox'; }
    if (tag === 'option') { return 'option'; }
    if (tag === 'img') { return 'img'; }
    if (/^h[1-6]$/.test(tag)) { return 'heading'; }
    if (tag === 'p') { return 'paragraph'; }
    if (tag === 'input') {
      if (type === 'button' || type === 'submit' || type === 'reset' || type === 'image') { return 'button'; }
      if (type === 'checkbox') { return 'checkbox'; }
      if (type === 'radio') { return 'radio'; }
      if (type === 'range') { return 'slider'; }
      if (type === 'number') { return 'spinbutton'; }
      if (type === 'search') { return 'searchbox'; }
      if (type === 'file' || type === 'hidden' || type === 'color') { return ''; }
      return 'textbox';
    }
    return '';
  }
  function accessibleName() {
    var label = attr(el, 'aria-label');
    if (label && label.trim()) { return label; }
    var by = attr(el, 'aria-labelledby');
    if (by) {
      var parts = [];
      by.split(/\s+/).forEach(function (id) {
        var node = id ? document.getElementById(id) : null;
        if (node) { parts.push(node.textContent || ''); }
      });
      var joined = parts.join(' ').trim();
      if (joined) { return joined; }
    }
    if (tag === 'input' && (type === 'submit' || type === 'button' || type === 'reset')) {
      return attr(el, 'value') || (type === 'submit' ? 'Submit' : type === 'reset' ? 'Reset' : '');
    }
    if (tag === 'input' && type === 'image') { return attr(el, 'alt') || attr(el, 'value') || ''; }
    if (el.labels && el.labels.length) {
      var texts = [];
      for (var i = 0; i < el.labels.length; i++) { texts.push(el.labels[i].textContent || ''); }
      var text = texts.join(' ').trim();
      if (text) { return text; }
    }
    if (tag !== 'input' && tag !== 'textarea' && tag !== 'select') {
      var inner = (el.innerText || el.textContent || '').trim();
      if (inner) { return inner; }
      var img = el.querySelector('img[alt]');
      if (img && attr(img, 'alt')) { return attr(img, 'alt'); }
    }
    return attr(el, 'title') || attr(el, 'placeholder') || attr(el, 'alt') || '';
  }
  function method(value) {
    var m = lower(value);
    return (m === 'get' || m === 'post' || m === 'dialog') ? m : (m ? 'post' : null);
  }
  var linkLike = tag === 'a' || tag === 'area';
  var expanded = attr(el, 'aria-expanded');
  var popup = attr(el, 'aria-haspopup');
  var action = null;
  var formMethod = null;
  var enctype = null;
  var hasPassword = false;
  var hasFile = false;
  if (form) {
    var rawAction = attr(form, 'action');
    action = (rawAction == null || rawAction.trim() === '') ? clip(document.URL, urlCap) : absolute(rawAction);
    formMethod = method(attr(form, 'method')) || 'get';
    enctype = attr(form, 'enctype') ? lower(attr(form, 'enctype')) : null;
    hasPassword = form.querySelector('input[type="password" i]') !== null;
    hasFile = form.querySelector('input[type="file" i]') !== null;
  }
  var submitter = tag === 'button' || (tag === 'input' && (type === 'submit' || type === 'image'));
  var ids = [];
  if (attr(el, 'id')) { ids.push(attr(el, 'id')); }
  if (attr(el, 'name')) { ids.push(attr(el, 'name')); }
  return {
    role: implicitRole(),
    name: clip(accessibleName().replace(/\s+/g, ' ').trim(), nameCap),
    tag: tag,
    input_type: type,
    autocomplete: clip(lower(attr(el, 'autocomplete')), 200),
    href: linkLike ? absolute(attr(el, 'href')) : null,
    form_action: action,
    form_method: form ? formMethod : null,
    form_enctype: enctype,
    formaction: submitter ? absolute(attr(el, 'formaction')) : null,
    formmethod: submitter ? method(attr(el, 'formmethod')) : null,
    in_form: !!form,
    form_has_password: hasPassword,
    form_has_file_input: hasFile,
    download: linkLike && el.hasAttribute('download'),
    target_blank: lower(attr(el, 'target') || attr(form, 'target')) === '_blank',
    aria_expanded: expanded === 'true' ? true : expanded === 'false' ? false : null,
    aria_controls: el.hasAttribute('aria-controls'),
    aria_haspopup: popup !== null && lower(popup) !== 'false',
    element_id_or_name: clip(ids.join(' '), nameCap),
    page_url: clip(document.URL, urlCap),
    contenteditable: el.isContentEditable === true,
    disabled: el.disabled === true || lower(attr(el, 'aria-disabled')) === 'true'
  };
}"#;

/// The focused element's features (see [`ELEMENT_FEATURES`]), or `null` when nothing but the
/// page itself has focus. Descends into open shadow roots.
fn focused_expression() -> String {
    format!(
        "(function (describe) {{\
           var el = document.activeElement;\
           while (el && el.shadowRoot && el.shadowRoot.activeElement) {{ el = el.shadowRoot.activeElement; }}\
           if (!el || el === document.body || el === document.documentElement) {{ return null; }}\
           return describe.call(el, {NAME_CAP}, {URL_CAP});\
         }})({ELEMENT_FEATURES})"
    )
}

fn parse(value: Value) -> ToolResult<Features> {
    serde_json::from_value(value).map_err(|error| {
        ToolError::internal(format!("the element description is invalid: {error}"))
    })
}

impl Conn {
    /// The URL the tab is at, as last reported by the browser (no round trip).
    pub(crate) fn tab_url(&self, tab: &TabRef) -> String {
        self.shared
            .state()
            .tab(tab.num)
            .map(|t| t.url.clone())
            .unwrap_or_default()
    }

    /// The origins of every frame of the page, the page's own included (from the frame tree).
    pub(crate) async fn frame_origins(&self, tab: &TabRef) -> ToolResult<Vec<String>> {
        let tree = self.call(tab, "Page.getFrameTree", json!({})).await?;
        let mut origins = Vec::new();
        let mut stack = vec![&tree["frameTree"]];
        while let Some(node) = stack.pop() {
            if let Some(url) = node["frame"]["url"].as_str()
                && let Ok(parsed) = url::Url::parse(url)
                && matches!(parsed.scheme(), "http" | "https")
            {
                origins.push(parsed.origin().ascii_serialization());
            }
            for child in node["childFrames"].as_array().into_iter().flatten() {
                stack.push(child);
            }
        }
        origins.sort();
        origins.dedup();
        Ok(origins)
    }

    /// Describes the element behind `backend` (a DOM backend node id) for the action classifier.
    pub(crate) async fn element_features(
        &self,
        tab: &TabRef,
        backend: i64,
    ) -> ToolResult<Features> {
        let object = self
            .call(tab, "DOM.resolveNode", json!({ "backendNodeId": backend }))
            .await?;
        let object_id = object["object"]["objectId"]
            .as_str()
            .ok_or_else(|| ToolError::browser("the element cannot be resolved"))?
            .to_owned();
        let reply = self
            .call(
                tab,
                "Runtime.callFunctionOn",
                json!({
                    "objectId": object_id,
                    "functionDeclaration": ELEMENT_FEATURES,
                    "arguments": [{ "value": NAME_CAP }, { "value": URL_CAP }],
                    "returnByValue": true,
                    "silent": true,
                    "userGesture": false,
                }),
            )
            .await?;
        if reply.get("exceptionDetails").is_some() {
            return Err(ToolError::browser("the element cannot be described"));
        }
        parse(reply["result"]["value"].clone())
    }

    /// Describes the focused element, or `None` when the page itself has focus.
    pub(crate) async fn focused_features(&self, tab: &TabRef) -> ToolResult<Option<Features>> {
        match self.eval(tab, &focused_expression(), 2000).await? {
            Value::Null => Ok(None),
            value => parse(value).map(Some),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::process::Stdio;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::process::{Child, Command};

    use super::*;
    use crate::browse::Limits;
    use crate::classifier::{ActionClass, Intent, classify};
    use crate::config::Window;
    use crate::safety::Scope;

    const PAGE: &str = concat!(
        "<!doctype html><html><head><title>Fixture</title></head><body><main>",
        "<h1>Account</h1>",
        "<form id=\"del\" action=\"/account/delete\" method=\"POST\"><button id=\"cancel\" type=\"submit\">Cancel</button></form>",
        "<form id=\"login\" action=\"/login\" method=\"post\">",
        "<input id=\"user\" name=\"user\" type=\"text\" autocomplete=\"username\" aria-label=\"Email\">",
        "<input id=\"pass\" type=\"password\" aria-label=\"Password\">",
        "<button id=\"signin\">Sign in</button></form>",
        "<form id=\"up\" action=\"/upload\" method=\"post\" enctype=\"multipart/form-data\">",
        "<input id=\"file\" type=\"file\" aria-label=\"Attachment\"></form>",
        "<form id=\"search\" action=\"/search\" method=\"get\"><input id=\"q\" name=\"q\" type=\"search\" aria-label=\"Search\">",
        "<button id=\"find\" type=\"submit\">Find</button></form>",
        "<a id=\"out\" href=\"https://other.example.net/page\">Partner <span id=\"inner\">site</span></a>",
        "<a id=\"mail\" href=\"mailto:team@example.test\">Write to us</a>",
        "<a id=\"bye\" href=\"/logout\">Leave</a>",
        "<a id=\"docs\" href=\"/docs\" download>Manual</a>",
        "<button id=\"menu\" type=\"button\" aria-expanded=\"false\" aria-controls=\"m\">Menu</button>",
        "<button id=\"js\" type=\"button\">Continue</button>",
        "<script>document.getElementById('inner').dataset.x = '1';</script>",
        "</main></body></html>"
    );

    async fn fixture() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PAGE}",
                        PAGE.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        format!("http://{addr}")
    }

    /// Starts a headless Chromium of this test and returns it with its browser endpoint.
    async fn launch(dir: &std::path::Path) -> Option<(Child, String)> {
        let Some(exe) = browserx_runtime::discover_chromium() else {
            eprintln!(
                "SKIP: no Chromium found (set BROWSERX_CHROMIUM_PATH to run the element feature test)"
            );
            return None;
        };
        let extra = std::env::var("BROWSERX_TEST_BROWSER_ARGS")
            .unwrap_or_else(|_| "--no-sandbox --disable-gpu".into());
        let mut child = Command::new(exe)
            .args(extra.split_whitespace())
            .args([
                "--headless=new",
                "--remote-debugging-port=0",
                "--no-first-run",
                "--no-default-browser-check",
            ])
            .arg(format!("--user-data-dir={}", dir.display()))
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        eprintln!("test browser pid: {:?}", child.id());
        let stderr = child.stderr.take().unwrap();
        let mut lines = BufReader::new(stderr).lines();
        let url = tokio::time::timeout(Duration::from_secs(60), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                if let Some(rest) = line.split("DevTools listening on ").nth(1) {
                    return Some(rest.trim().to_owned());
                }
            }
            None
        })
        .await
        .unwrap()
        .expect("the browser did not print its endpoint");
        // Keep draining stderr so the browser never blocks on a full pipe.
        tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
        Some((child, url))
    }

    async fn backend_of(conn: &Conn, tab: &TabRef, selector: &str) -> i64 {
        let object = conn
            .call(
                tab,
                "Runtime.evaluate",
                json!({ "expression": format!("document.querySelector({selector:?})") }),
            )
            .await
            .unwrap();
        let object_id = object["result"]["objectId"].as_str().unwrap().to_owned();
        let node = conn
            .call(tab, "DOM.describeNode", json!({ "objectId": object_id }))
            .await
            .unwrap();
        node["node"]["backendNodeId"].as_i64().unwrap()
    }

    #[tokio::test]
    async fn features_of_a_real_page_classify_as_expected() {
        let scratch = tempfile::tempdir().unwrap();
        let Some((mut browser, endpoint)) = launch(scratch.path()).await else {
            return;
        };
        let origin = fixture().await;
        let scope = Arc::new(Scope::new(vec![origin.clone()], true, Window::default()));
        let conn = Conn::connect(&endpoint, Limits::default(), scope)
            .await
            .unwrap();
        let tab = conn.tab(None).await.unwrap();
        conn.call(
            &tab,
            "Page.navigate",
            json!({ "url": format!("{origin}/") }),
        )
        .await
        .unwrap();
        conn.wait_settled(&tab, Duration::from_millis(300)).await;
        let inside = |url: &str| url == origin || url.starts_with(&format!("{origin}/"));

        let cases: [(&str, Intent, ActionClass); 15] = [
            ("#cancel", Intent::Click, ActionClass::Destructive),
            ("#signin", Intent::Click, ActionClass::CredentialEntry),
            (
                "#user",
                Intent::TypeText { submit: false },
                ActionClass::CredentialEntry,
            ),
            (
                "#pass",
                Intent::TypeText { submit: false },
                ActionClass::CredentialEntry,
            ),
            ("#user", Intent::PressEnter, ActionClass::CredentialEntry),
            ("#file", Intent::Click, ActionClass::FileTransfer),
            ("#out", Intent::Click, ActionClass::NavigateOutOfScope),
            ("#inner", Intent::Click, ActionClass::NavigateOutOfScope),
            ("#mail", Intent::Click, ActionClass::ExternalCommunication),
            ("#bye", Intent::Click, ActionClass::Destructive),
            ("#docs", Intent::Click, ActionClass::FileTransfer),
            (
                "#q",
                Intent::TypeText { submit: true },
                ActionClass::NavigateInScope,
            ),
            ("#find", Intent::Click, ActionClass::NavigateInScope),
            ("#menu", Intent::Click, ActionClass::Read),
            ("#js", Intent::Click, ActionClass::Unknown),
        ];
        for (selector, intent, expected) in cases {
            let backend = backend_of(&conn, &tab, selector).await;
            let features = conn.element_features(&tab, backend).await.unwrap();
            let got = classify(&features, intent, &inside);
            assert_eq!(got.class, expected, "{selector}: {features:?} {got:?}");
        }

        // The collected fields themselves.
        let cancel = conn
            .element_features(&tab, backend_of(&conn, &tab, "#cancel").await)
            .await
            .unwrap();
        assert_eq!(cancel.tag, "button");
        assert_eq!(cancel.role, "button");
        assert_eq!(cancel.name, "Cancel");
        assert_eq!(cancel.input_type, "submit");
        assert_eq!(cancel.form_method.as_deref(), Some("post"));
        assert_eq!(
            cancel.form_action.as_deref(),
            Some(format!("{origin}/account/delete").as_str())
        );
        assert!(cancel.in_form && !cancel.form_has_password);
        assert_eq!(cancel.page_url, format!("{origin}/"));
        let signin = conn
            .element_features(&tab, backend_of(&conn, &tab, "#signin").await)
            .await
            .unwrap();
        assert!(signin.form_has_password);
        let inner = conn
            .element_features(&tab, backend_of(&conn, &tab, "#inner").await)
            .await
            .unwrap();
        assert_eq!(inner.tag, "a", "a nested element describes its link");
        assert_eq!(inner.name, "Partner site");
        let menu = conn
            .element_features(&tab, backend_of(&conn, &tab, "#menu").await)
            .await
            .unwrap();
        assert_eq!(menu.aria_expanded, Some(false));
        assert!(menu.aria_controls && !menu.aria_haspopup);
        let docs = conn
            .element_features(&tab, backend_of(&conn, &tab, "#docs").await)
            .await
            .unwrap();
        assert!(docs.download);
        let file = conn
            .element_features(&tab, backend_of(&conn, &tab, "#file").await)
            .await
            .unwrap();
        assert!(file.in_form && file.form_has_file_input);
        assert_eq!(file.form_enctype.as_deref(), Some("multipart/form-data"));

        // Focus: none on a fresh page, then the field that was focused.
        assert_eq!(conn.focused_features(&tab).await.unwrap(), None);
        conn.eval(&tab, "document.getElementById('user').focus()", 2000)
            .await
            .unwrap();
        let focused = conn.focused_features(&tab).await.unwrap().unwrap();
        assert_eq!(focused.autocomplete, "username");
        assert_eq!(
            classify(&focused, Intent::PressEnter, &inside).class,
            ActionClass::CredentialEntry
        );

        conn.close().await;
        let _ = browser.kill().await;
    }
}
