//! Capturing and replaying logical browser state (cookies, `localStorage`, open pages).

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use browserx_cdp::{CdpClient, CdpError};
use browserx_core::snapshot::{CookieRecord, OriginStorage, STATE_FORMAT_VERSION};
use browserx_core::{ContextId, Error, Result, StateSnapshot};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::broadcast::error::RecvError;

use crate::control::Control;

/// Origins captured or replayed per snapshot.
pub(crate) const MAX_ORIGINS: usize = 64;
/// Bytes of `localStorage` (keys plus values) per origin.
pub(crate) const MAX_ORIGIN_BYTES: usize = 5 * 1024 * 1024;
/// Bytes one capture may add up to (cookies, `localStorage`, page URLs, as the
/// JSON a sealed snapshot holds). Deliberately below the store's 64 MiB sealed
/// limit so that a capture which succeeds can always be stored.
pub(crate) const MAX_CAPTURE_BYTES: usize = 48 * 1024 * 1024;
/// The store accepts at most 64 MiB of sealed bytes (`browserx_store::MAX_SEALED_BYTES`).
const _: () = assert!(MAX_CAPTURE_BYTES < 64 * 1024 * 1024);
/// Fixed JSON overhead assumed per cookie (field names, quotes, flags).
const COOKIE_OVERHEAD: usize = 160;
/// Fixed JSON overhead assumed per storage entry (`["k","v"],`).
const ENTRY_OVERHEAD: usize = 8;
/// Cookies captured per snapshot.
const MAX_COOKIES: usize = 20_000;
/// Pages recorded and reopened per snapshot.
const MAX_OPEN_URLS: usize = 64;
/// The document answered for the seeded origin: empty, and it declares no icon, so the browser
/// has no reason to look for a favicon on the site (base64 of
/// `<!doctype html><link rel="icon" href="data:,">`).
const EMPTY_PAGE_BASE64: &str = "PCFkb2N0eXBlIGh0bWw+PGxpbmsgcmVsPSJpY29uIiBocmVmPSJkYXRhOiwiPg==";

/// Deadline for the interception handshake that seeds one origin.
const ORIGIN_NAVIGATION_TIMEOUT: Duration = Duration::from_secs(20);
/// Attempts (100 ms apart) to write storage once the seeded page is current.
const ORIGIN_WRITE_ATTEMPTS: usize = 30;

#[derive(Deserialize)]
struct TargetInfo {
    #[serde(rename = "targetId")]
    target_id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    url: String,
    #[serde(rename = "browserContextId", default)]
    context_id: Option<String>,
}

#[derive(Deserialize)]
struct RawCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    #[serde(default)]
    expires: Option<f64>,
    #[serde(default, rename = "httpOnly")]
    http_only: bool,
    #[serde(default)]
    secure: bool,
    #[serde(default)]
    session: bool,
    #[serde(default, rename = "sameSite")]
    same_site: Option<String>,
}

fn decode<T: for<'de> Deserialize<'de>>(value: Value, what: &str) -> Result<T> {
    serde_json::from_value(value)
        .map_err(|e| Error::Browser(format!("unexpected {what} reply from the browser: {e}")))
}

/// Length of `text` once JSON-encoded, without the quotes.
fn json_len(text: &str) -> usize {
    text.chars()
        .map(|c| match c {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
            c if (c as u32) < 0x20 => 6,
            c => c.len_utf8(),
        })
        .sum()
}

/// Running total of what a capture would add to the snapshot.
struct Budget {
    used: usize,
    limit: usize,
}

impl Budget {
    fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    fn take(&mut self, bytes: usize) -> Result<()> {
        self.used = self.used.saturating_add(bytes);
        if self.used > self.limit {
            return Err(Error::InvalidRequest(format!(
                "session state is larger than the {} byte snapshot budget; \
                 clear cookies or storage to make it snapshot-able",
                self.limit
            )));
        }
        Ok(())
    }
}

fn context_param(context: Option<&ContextId>) -> Value {
    match context {
        Some(c) => json!({ "browserContextId": c.0 }),
        None => json!({}),
    }
}

/// Origin (`scheme://host[:port]`) of an `http(s)` URL; `None` for anything else.
fn http_origin(raw: &str) -> Option<String> {
    let url = url::Url::parse(raw).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.origin().ascii_serialization())
}

/// Open page targets belonging to `context` (the default context when `None`).
async fn page_targets(cdp: &CdpClient, context: Option<&ContextId>) -> Result<Vec<TargetInfo>> {
    let reply = cdp.call("Target.getTargets", json!({}), None).await?;
    let infos: Vec<TargetInfo> = decode(
        reply.get("targetInfos").cloned().unwrap_or(Value::Null),
        "getTargets",
    )?;
    let named: HashSet<String> = if context.is_none() {
        // The default context is the one `getBrowserContexts` does not list.
        let reply = cdp
            .call("Target.getBrowserContexts", json!({}), None)
            .await?;
        decode::<Vec<String>>(
            reply
                .get("browserContextIds")
                .cloned()
                .unwrap_or(Value::Null),
            "getBrowserContexts",
        )?
        .into_iter()
        .collect()
    } else {
        HashSet::new()
    };
    Ok(infos
        .into_iter()
        .filter(|t| t.kind == "page")
        .filter(|t| match context {
            Some(c) => t.context_id.as_deref() == Some(c.0.as_str()),
            None => t.context_id.as_ref().is_none_or(|id| !named.contains(id)),
        })
        .collect())
}

/// Captures cookies, `localStorage` of the open `http(s)` origins, and open page URLs.
///
/// `localStorage` is read by the browser itself (`DOMStorage`), for the origin
/// the browser reports for each page target. Nothing a page can script - an
/// overridden `JSON.stringify`, a forged `location` - influences which origin an
/// entry is filed under or what it contains. The total captured size is bounded
/// by [`MAX_CAPTURE_BYTES`]; exceeding it is an error, not a silent truncation.
pub(crate) async fn capture(
    control: &Control,
    browser_version: &str,
    context: Option<&ContextId>,
) -> Result<StateSnapshot> {
    capture_with_budget(control, browser_version, context, MAX_CAPTURE_BYTES).await
}

async fn capture_with_budget(
    control: &Control,
    browser_version: &str,
    context: Option<&ContextId>,
    limit: usize,
) -> Result<StateSnapshot> {
    let mut budget = Budget::new(limit);
    let cdp = control.client().await?;
    let reply = cdp
        .call("Storage.getCookies", context_param(context), None)
        .await?;
    let raw: Vec<RawCookie> = decode(
        reply.get("cookies").cloned().unwrap_or(Value::Null),
        "getCookies",
    )?;
    if raw.len() > MAX_COOKIES {
        tracing::warn!(
            count = raw.len(),
            limit = MAX_COOKIES,
            "cookie jar truncated in snapshot"
        );
    }
    let mut cookies = Vec::new();
    for c in raw.into_iter().take(MAX_COOKIES) {
        budget.take(
            COOKIE_OVERHEAD
                + json_len(&c.name)
                + json_len(&c.value)
                + json_len(&c.domain)
                + json_len(&c.path)
                + c.same_site.as_deref().map_or(0, json_len),
        )?;
        cookies.push(CookieRecord {
            expires: if c.session {
                None
            } else {
                c.expires.filter(|e| *e > 0.0)
            },
            name: c.name,
            value: c.value,
            domain: c.domain,
            path: c.path,
            http_only: c.http_only,
            secure: c.secure,
            same_site: c.same_site,
        });
    }

    let pages = page_targets(&cdp, context).await?;
    let mut open_urls = Vec::new();
    let mut origins: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut tried: HashSet<String> = HashSet::new();
    for page in &pages {
        let Some(origin) = http_origin(&page.url) else {
            continue;
        };
        if open_urls.len() < MAX_OPEN_URLS {
            budget.take(json_len(&page.url) + 3)?;
            open_urls.push(page.url.clone());
        }
        if origins.len() >= MAX_ORIGINS || !tried.insert(origin.clone()) {
            continue;
        }
        match read_local_storage(control, &page.target_id, &origin).await {
            Ok(entries) if entries.is_empty() => {}
            Ok(entries) => {
                let cost = json_len(&origin)
                    + ENTRY_OVERHEAD
                    + entries
                        .iter()
                        .map(|(k, v)| json_len(k) + json_len(v) + ENTRY_OVERHEAD)
                        .sum::<usize>();
                budget.take(cost)?;
                origins.insert(origin, entries);
            }
            Err(err) => {
                tracing::warn!(error = %err, "could not read localStorage of a page; skipping its origin");
            }
        }
    }
    Ok(StateSnapshot {
        format_version: STATE_FORMAT_VERSION,
        browser_version: browser_version.to_owned(),
        cookies,
        origins: origins
            .into_iter()
            .map(|(origin, local_storage)| OriginStorage {
                origin,
                local_storage,
            })
            .collect(),
        open_urls,
    })
}

/// Reads `origin`'s `localStorage` through the browser's own `DOMStorage` view,
/// using the page target only as the route to the right storage partition.
///
/// An origin whose storage is over the per-origin limit, or whose reply is too
/// large for the control connection, is skipped (empty result) with a warning;
/// the control connection reconnects on its next use.
async fn read_local_storage(
    control: &Control,
    target_id: &str,
    origin: &str,
) -> Result<Vec<(String, String)>> {
    let cdp = control.client().await?;
    let session = attach(&cdp, target_id).await?;
    let read = cdp
        .call(
            "DOMStorage.getDOMStorageItems",
            json!({ "storageId": { "securityOrigin": origin, "isLocalStorage": true } }),
            Some(&session),
        )
        .await;
    if let Err(err) = cdp
        .call(
            "Target.detachFromTarget",
            json!({ "sessionId": session }),
            None,
        )
        .await
    {
        tracing::debug!(error = %err, "detach after capture failed");
    }
    let reply = match read {
        Ok(reply) => reply,
        Err(CdpError::MessageTooLarge { limit }) => {
            tracing::warn!(
                limit,
                "localStorage reply exceeds the control connection limit; origin skipped"
            );
            return Ok(Vec::new());
        }
        Err(other) => return Err(other.into()),
    };
    let entries: Vec<Vec<String>> = decode(
        reply.get("entries").cloned().unwrap_or(Value::Null),
        "getDOMStorageItems",
    )?;
    let mut out = Vec::with_capacity(entries.len());
    let mut bytes = 0usize;
    for entry in entries {
        let [key, value] = <[String; 2]>::try_from(entry)
            .map_err(|_| Error::Browser("malformed localStorage entry from the browser".into()))?;
        bytes += key.len() + value.len();
        out.push((key, value));
    }
    if bytes > MAX_ORIGIN_BYTES {
        tracing::warn!("localStorage of an origin exceeds the per-origin limit; skipped");
        return Ok(Vec::new());
    }
    Ok(out)
}

async fn attach(cdp: &CdpClient, target_id: &str) -> Result<String> {
    let reply = cdp
        .call(
            "Target.attachToTarget",
            json!({ "targetId": target_id, "flatten": true }),
            None,
        )
        .await?;
    reply
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::Browser("attachToTarget returned no sessionId".into()))
}

fn storage_bytes(entries: &[(String, String)]) -> usize {
    entries.iter().map(|(k, v)| k.len() + v.len()).sum()
}

/// Replays `state` into `context` (the default context when `None`).
pub(crate) async fn restore(
    control: &Control,
    context: Option<&ContextId>,
    state: &StateSnapshot,
) -> Result<()> {
    if state.format_version > STATE_FORMAT_VERSION {
        return Err(Error::InvalidRequest(format!(
            "snapshot format {} is newer than supported {STATE_FORMAT_VERSION}",
            state.format_version
        )));
    }
    if state.origins.len() > MAX_ORIGINS {
        return Err(Error::InvalidRequest(format!(
            "snapshot has more than {MAX_ORIGINS} origins"
        )));
    }
    for origin in &state.origins {
        if storage_bytes(&origin.local_storage) > MAX_ORIGIN_BYTES {
            return Err(Error::InvalidRequest(
                "snapshot origin storage exceeds the per-origin limit".into(),
            ));
        }
    }

    let cdp = &control.client().await?;
    set_cookies(cdp, context, &state.cookies).await?;

    for origin in state.origins.iter().filter(|o| !o.local_storage.is_empty()) {
        restore_origin(cdp, context, origin).await?;
    }

    for url in state.open_urls.iter().take(MAX_OPEN_URLS) {
        if http_origin(url).is_none() {
            tracing::warn!("snapshot page URL is not http(s); not reopened");
            continue;
        }
        let mut params = context_param(context);
        params["url"] = Value::String(url.clone());
        if let Err(err) = cdp.call("Target.createTarget", params, None).await {
            tracing::warn!(error = %err, "could not reopen a page from the snapshot");
        }
    }
    Ok(())
}

fn cookie_json(c: &CookieRecord) -> Value {
    let mut cookie = json!({
        "name": c.name,
        "value": c.value,
        "domain": c.domain,
        "path": c.path,
        "secure": c.secure,
        "httpOnly": c.http_only,
    });
    if let Some(expires) = c.expires.filter(|e| *e > 0.0) {
        cookie["expires"] = json!(expires);
    }
    if let Some(same_site) = &c.same_site {
        cookie["sameSite"] = json!(same_site);
    }
    cookie
}

async fn set_cookies(
    cdp: &CdpClient,
    context: Option<&ContextId>,
    cookies: &[CookieRecord],
) -> Result<()> {
    if cookies.is_empty() {
        return Ok(());
    }
    let mut params = context_param(context);
    params["cookies"] = Value::Array(cookies.iter().map(cookie_json).collect());
    match cdp.call("Storage.setCookies", params, None).await {
        Ok(_) => return Ok(()),
        // The browser rejects the whole batch if one cookie is invalid; fall back
        // to one at a time so a single bad cookie cannot block recovery.
        Err(CdpError::Protocol { .. }) => {}
        Err(other) => return Err(other.into()),
    }
    let mut failed = 0usize;
    for cookie in cookies {
        let mut params = context_param(context);
        params["cookies"] = Value::Array(vec![cookie_json(cookie)]);
        match cdp.call("Storage.setCookies", params, None).await {
            Ok(_) => {}
            Err(CdpError::Protocol { .. }) => failed += 1,
            Err(other) => return Err(other.into()),
        }
    }
    if failed == cookies.len() {
        return Err(Error::Browser(
            "the browser rejected every cookie of the snapshot".into(),
        ));
    }
    tracing::warn!(
        failed,
        total = cookies.len(),
        "some snapshot cookies were rejected by the browser"
    );
    Ok(())
}

/// Seeds `localStorage` for one origin without touching the network: a blank
/// target is navigated to the origin while a fetch interception answers the
/// request with an empty page, so restoring works even when the site (or the
/// proxy) is unreachable and never reveals the restore to the origin.
async fn restore_origin(
    cdp: &CdpClient,
    context: Option<&ContextId>,
    origin: &OriginStorage,
) -> Result<()> {
    let canonical = http_origin(&origin.origin)
        .ok_or_else(|| Error::InvalidRequest("snapshot origin is not an http(s) origin".into()))?;
    let mut params = context_param(context);
    params["url"] = Value::String("about:blank".into());
    let created = cdp.call("Target.createTarget", params, None).await?;
    let target_id = created
        .get("targetId")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Browser("createTarget returned no targetId".into()))?
        .to_owned();
    let outcome = seed_origin(cdp, &target_id, &canonical, &origin.local_storage).await;
    if let Err(err) = cdp
        .call("Target.closeTarget", json!({ "targetId": target_id }), None)
        .await
    {
        tracing::debug!(error = %err, "closing the seeding target failed");
    }
    outcome
}

async fn seed_origin(
    cdp: &CdpClient,
    target_id: &str,
    origin: &str,
    entries: &[(String, String)],
) -> Result<()> {
    let session = attach(cdp, target_id).await?;
    let page_url = format!("{origin}/");
    let mut events = cdp.events();
    // Intercept every request to the origin, not only the page: anything else the browser
    // issues for the blank page (a favicon, for one) must not reach the site either.
    cdp.call(
        "Fetch.enable",
        json!({ "patterns": [{ "urlPattern": format!("{origin}/*"), "requestStage": "Request" }] }),
        Some(&session),
    )
    .await?;

    // Answers the page with an empty document that declares no icon, and refuses every other
    // request to the origin. It runs for as long as the seeding does and ends only on an error.
    let answer = async {
        loop {
            match events.recv().await {
                Ok(event)
                    if event.method == "Fetch.requestPaused"
                        && event.session_id.as_deref() == Some(session.as_str()) =>
                {
                    let request_id = event
                        .params
                        .get("requestId")
                        .and_then(Value::as_str)
                        .ok_or_else(|| Error::Browser("requestPaused without requestId".into()))?
                        .to_owned();
                    let is_page = event.params.pointer("/request/url").and_then(Value::as_str)
                        == Some(page_url.as_str());
                    if is_page {
                        cdp.call(
                            "Fetch.fulfillRequest",
                            json!({
                                "requestId": request_id,
                                "responseCode": 200,
                                "responseHeaders": [{ "name": "Content-Type", "value": "text/html" }],
                                "body": EMPTY_PAGE_BASE64,
                            }),
                            Some(&session),
                        )
                        .await?;
                    } else {
                        // The page is gone or closing when this fails; nothing is left to refuse.
                        let _ = cdp
                            .call(
                                "Fetch.failRequest",
                                json!({ "requestId": request_id, "errorReason": "BlockedByClient" }),
                                Some(&session),
                            )
                            .await;
                    }
                }
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => {
                    return Err::<(), Error>(Error::Browser(
                        "event stream closed while seeding storage".into(),
                    ));
                }
            }
        }
    };
    let navigate = cdp.call("Page.navigate", json!({ "url": page_url }), Some(&session));
    let navigated = tokio::time::timeout(ORIGIN_NAVIGATION_TIMEOUT, async {
        tokio::select! {
            navigated = navigate => navigated.map_err(Error::from),
            failed = answer => failed.map(|()| Value::Null),
        }
    })
    .await
    .map_err(|_| Error::Timeout("seeding an origin's storage timed out".into()))??;
    if let Some(text) = navigated.get("errorText").and_then(Value::as_str) {
        return Err(Error::Browser(format!(
            "could not open the origin to seed storage: {text}"
        )));
    }

    let payload = serde_json::to_string(entries)
        .map_err(|e| Error::Internal(format!("cannot encode storage entries: {e}")))?;
    let literal = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned());
    let expression = format!(
        "(function(){{if(location.origin!=={origin}){{throw new Error('origin mismatch');}}\
         const e=JSON.parse({payload});for(const [k,v] of e){{localStorage.setItem(k,v);}}\
         return e.length;}})()",
        origin = literal(origin),
        payload = literal(&payload),
    );
    let mut last = String::from("not attempted");
    for _ in 0..ORIGIN_WRITE_ATTEMPTS {
        let reply = cdp
            .call(
                "Runtime.evaluate",
                json!({ "expression": expression, "returnByValue": true }),
                Some(&session),
            )
            .await?;
        match reply.get("exceptionDetails") {
            None => return Ok(()),
            Some(details) => {
                last = details
                    .pointer("/exception/description")
                    .and_then(Value::as_str)
                    .unwrap_or("script exception")
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(Error::Browser(format!(
        "could not write localStorage for the origin: {last}"
    )))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn origins_are_canonicalized_and_non_http_refused() {
        assert_eq!(
            http_origin("http://127.0.0.1:8080/a/b?q=1").as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            http_origin("https://Example.TEST/x").as_deref(),
            Some("https://example.test")
        );
        assert_eq!(http_origin("file:///etc/passwd"), None);
        assert_eq!(http_origin("about:blank"), None);
        assert_eq!(http_origin("not a url"), None);
    }

    #[test]
    fn json_len_matches_the_real_encoding() {
        for text in [
            "plain",
            "quo\"te and back\\slash",
            "ctl\u{0}\u{1f}\n\r\t\u{8}\u{c}",
            "unicode \u{e9}\u{4e2d}\u{1f600}",
            "",
        ] {
            let encoded = serde_json::to_string(text).unwrap();
            assert_eq!(json_len(text) + 2, encoded.len(), "{text:?}");
        }
    }

    #[test]
    fn budget_counts_up_and_refuses_overflow_with_a_typed_error() {
        let mut budget = Budget::new(100);
        budget.take(60).unwrap();
        budget.take(40).unwrap();
        match budget.take(1) {
            Err(Error::InvalidRequest(message)) => {
                assert!(message.contains("100 byte"), "{message}")
            }
            other => panic!("expected a budget error, got {other:?}"),
        }
        // saturates instead of overflowing
        assert!(Budget::new(10).take(usize::MAX).is_err());
    }

    #[test]
    fn cookie_json_omits_session_expiry() {
        let mut cookie = CookieRecord {
            name: "a".into(),
            value: "b".into(),
            domain: "example.test".into(),
            path: "/".into(),
            expires: None,
            http_only: true,
            secure: false,
            same_site: Some("Lax".into()),
        };
        let json = cookie_json(&cookie);
        assert!(json.get("expires").is_none());
        assert_eq!(json["sameSite"], "Lax");
        cookie.expires = Some(1_900_000_000.0);
        assert_eq!(cookie_json(&cookie)["expires"], 1_900_000_000.0);
    }
}
