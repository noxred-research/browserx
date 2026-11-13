//! Navigation and observation: open a page, snapshot, text, screenshot, waits, logs, script.

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use super::ax::RefInfo;
use super::conn::{Conn, ConsoleEntry, NetEntry, TabRef};
use super::scripts;
use crate::error::{ToolError, ToolResult};

/// Tallest page captured by a full-page screenshot, in CSS pixels.
const MAX_FULL_PAGE_HEIGHT: f64 = 16_000.0;
/// Longest wait of `wait_for`.
pub const MAX_WAIT: Duration = Duration::from_secs(30);

/// Where a navigation ended.
#[derive(Debug, Clone)]
pub struct NavOutcome {
    /// Final URL (inside the scope, or the call failed).
    pub url: String,
    /// Page title.
    pub title: String,
    /// The page finished loading before the timeout.
    pub settled: bool,
}

/// Readable page content.
#[derive(Debug, Clone)]
pub struct PageText {
    /// Title.
    pub title: String,
    /// URL.
    pub url: String,
    /// Markdown.
    pub text: String,
    /// Cut at the character budget.
    pub truncated: bool,
}

/// A PNG screenshot.
#[derive(Debug, Clone)]
pub struct Screenshot {
    /// Base64 PNG data.
    pub data: String,
    /// Decoded size in bytes.
    pub bytes: usize,
    /// Pixel width.
    pub width: u32,
    /// Pixel height.
    pub height: u32,
}

/// What `wait_for` waits for.
#[derive(Debug, Clone)]
pub enum WaitFor {
    /// Text anywhere in the visible text of the page.
    Text(String),
    /// An element reference.
    Ref(u32),
}

/// Filters of the network log.
#[derive(Debug, Clone, Default)]
pub struct NetFilter {
    /// Entries to return (newest last).
    pub limit: usize,
    /// Keep URLs containing this text.
    pub url_contains: Option<String>,
    /// Keep one resource type (case-insensitive).
    pub resource_type: Option<String>,
    /// Keep failed requests and HTTP errors only.
    pub failed_only: bool,
}

fn png_size(bytes: &[u8]) -> (u32, u32) {
    let be = |at: usize| {
        bytes
            .get(at..at + 4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map_or(0, u32::from_be_bytes)
    };
    (be(16), be(20))
}

impl Conn {
    /// Opens `url` in the tab and enforces the scope before and after.
    pub async fn navigate(&self, tab: &TabRef, url: &str) -> ToolResult<NavOutcome> {
        let target = self
            .scope
            .check_url(url)
            .map_err(|r| ToolError::refused(r.0))?;
        let _ = self.take_blocked(tab);
        let reply = self
            .call(tab, "Page.navigate", json!({ "url": target.as_str() }))
            .await?;
        if let Some(error) = reply["errorText"].as_str() {
            if let Some((origin, code)) = self.take_blocked(tab) {
                return Err(super::conn::blocked_error(&origin, code));
            }
            return Err(ToolError::browser(format!(
                "navigation failed: {error}. If the destination is internal, the egress policy may have refused it; call assess."
            )));
        }
        let (url, settled) = self
            .settle_and_check(tab, Duration::from_millis(100))
            .await?;
        Ok(NavOutcome {
            url,
            title: self.title(tab).await,
            settled,
        })
    }

    /// Goes one entry back (`-1`) or forward (`1`) in the tab's history.
    pub async fn history(&self, tab: &TabRef, delta: i64) -> ToolResult<NavOutcome> {
        let history = self
            .call(tab, "Page.getNavigationHistory", json!({}))
            .await?;
        let current = i64::try_from(history["currentIndex"].as_u64().unwrap_or(0)).unwrap_or(0);
        let entries = history["entries"].as_array().cloned().unwrap_or_default();
        let wanted = current + delta;
        let entry = usize::try_from(wanted)
            .ok()
            .and_then(|i| entries.get(i))
            .ok_or_else(|| {
                ToolError::browser(if delta < 0 {
                    "there is no earlier page in this tab's history"
                } else {
                    "there is no later page in this tab's history"
                })
            })?;
        let entry_id = entry["id"].as_i64().unwrap_or(0);
        self.call(
            tab,
            "Page.navigateToHistoryEntry",
            json!({ "entryId": entry_id }),
        )
        .await?;
        let (url, settled) = self
            .settle_and_check(tab, Duration::from_millis(150))
            .await?;
        Ok(NavOutcome {
            url,
            title: self.title(tab).await,
            settled,
        })
    }

    /// Extracts the readable main content as Markdown.
    pub async fn page_text(&self, tab: &TabRef, max_chars: usize) -> ToolResult<PageText> {
        let value = self
            .eval(tab, &format!("({})({max_chars})", scripts::PAGE_TEXT), 8000)
            .await?;
        let url = value["url"].as_str().unwrap_or("").to_owned();
        self.scope
            .check_final(&url)
            .map_err(|r| ToolError::refused(r.0))?;
        Ok(PageText {
            title: value["title"].as_str().unwrap_or("").to_owned(),
            url,
            text: value["text"].as_str().unwrap_or("").to_owned(),
            truncated: value["truncated"].as_bool().unwrap_or(false),
        })
    }

    /// Captures the viewport or the whole page as PNG.
    pub async fn screenshot(&self, tab: &TabRef, full_page: bool) -> ToolResult<Screenshot> {
        let url = self.current_url(tab).await?;
        self.scope
            .check_final(&url)
            .map_err(|r| ToolError::refused(r.0))?;
        let mut params = json!({ "format": "png", "fromSurface": true });
        if full_page {
            let metrics = self.call(tab, "Page.getLayoutMetrics", json!({})).await?;
            let size = &metrics["cssContentSize"];
            let width = size["width"].as_f64().unwrap_or(0.0).max(1.0);
            let height = size["height"]
                .as_f64()
                .unwrap_or(0.0)
                .clamp(1.0, MAX_FULL_PAGE_HEIGHT);
            params["captureBeyondViewport"] = json!(true);
            params["clip"] =
                json!({ "x": 0, "y": 0, "width": width, "height": height, "scale": 1 });
        }
        let shot = self.call(tab, "Page.captureScreenshot", params).await?;
        let data = shot["data"]
            .as_str()
            .ok_or_else(|| ToolError::browser("the browser returned no screenshot"))?
            .to_owned();
        if data.len() / 4 * 3 > self.limits.max_screenshot_bytes + 3 {
            return Err(ToolError::browser(format!(
                "the screenshot exceeds {} bytes{}",
                self.limits.max_screenshot_bytes,
                if full_page {
                    ": take a viewport screenshot instead of a full-page one"
                } else {
                    ""
                }
            )));
        }
        let bytes = STANDARD
            .decode(&data)
            .map_err(|_| ToolError::browser("the browser returned invalid screenshot data"))?;
        if bytes.len() > self.limits.max_screenshot_bytes {
            return Err(ToolError::browser(format!(
                "the screenshot is {} bytes, over the {} byte limit",
                bytes.len(),
                self.limits.max_screenshot_bytes
            )));
        }
        let (width, height) = png_size(&bytes);
        Ok(Screenshot {
            data,
            bytes: bytes.len(),
            width,
            height,
        })
    }

    /// Waits until the text or element is present (or, with `gone`, absent).
    pub async fn wait_for(
        &self,
        tab: &TabRef,
        target: &WaitFor,
        gone: bool,
        timeout: Duration,
    ) -> ToolResult<Duration> {
        let timeout = timeout.min(MAX_WAIT);
        let started = Instant::now();
        loop {
            let present = match target {
                WaitFor::Text(text) => {
                    let literal = serde_json::to_string(text).unwrap_or_else(|_| "\"\"".into());
                    self.eval(
                        tab,
                        &format!("({})({literal})", scripts::BODY_HAS_TEXT),
                        3000,
                    )
                    .await?
                    .as_bool()
                    .unwrap_or(false)
                }
                WaitFor::Ref(number) => {
                    let info = self.ref_info(tab, *number)?;
                    self.resolve_live(tab, *number, &info).await.is_ok()
                }
            };
            if present != gone {
                return Ok(started.elapsed());
            }
            if started.elapsed() >= timeout {
                return Err(ToolError::browser(format!(
                    "timed out after {} ms waiting for {}{}",
                    timeout.as_millis(),
                    match target {
                        WaitFor::Text(text) => format!("text {text:?}"),
                        WaitFor::Ref(number) => format!("e{number}"),
                    },
                    if gone { " to disappear" } else { " to appear" }
                )));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// The recent requests of a tab, filtered.
    pub fn network_log(&self, tab: &TabRef, filter: &NetFilter) -> Vec<NetEntry> {
        let state = self.shared.state();
        let Some(tab_state) = state.tab(tab.num) else {
            return Vec::new();
        };
        let wanted: Vec<&NetEntry> = tab_state
            .net
            .iter()
            .filter(|e| {
                filter
                    .url_contains
                    .as_ref()
                    .is_none_or(|needle| e.url.contains(needle.as_str()))
            })
            .filter(|e| {
                filter
                    .resource_type
                    .as_ref()
                    .is_none_or(|kind| e.resource_type.eq_ignore_ascii_case(kind))
            })
            .filter(|e| {
                !filter.failed_only || e.error.is_some() || e.status.is_some_and(|s| s >= 400)
            })
            .collect();
        let skip = wanted.len().saturating_sub(filter.limit);
        wanted.into_iter().skip(skip).cloned().collect()
    }

    /// The recent console messages of a tab.
    pub fn console_log(
        &self,
        tab: &TabRef,
        level: Option<&str>,
        limit: usize,
    ) -> Vec<ConsoleEntry> {
        let state = self.shared.state();
        let Some(tab_state) = state.tab(tab.num) else {
            return Vec::new();
        };
        let wanted: Vec<&ConsoleEntry> = tab_state
            .console
            .iter()
            .filter(|e| level.is_none_or(|l| e.level == l))
            .collect();
        let skip = wanted.len().saturating_sub(limit);
        wanted.into_iter().skip(skip).cloned().collect()
    }

    /// Runs operator-enabled JavaScript in the page and returns the bounded JSON result.
    pub async fn evaluate(
        &self,
        tab: &TabRef,
        expression: &str,
        max_chars: usize,
    ) -> ToolResult<(String, bool)> {
        let value = self.eval(tab, expression, 5000).await?;
        let text = match &value {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let truncated = text.chars().count() > max_chars;
        let text: String = text.chars().take(max_chars).collect();
        // The script may have navigated: enforce the scope again.
        self.settle_and_check(tab, Duration::from_millis(150))
            .await?;
        Ok((text, truncated))
    }

    pub(super) fn ref_info(&self, tab: &TabRef, number: u32) -> ToolResult<RefInfo> {
        self.shared
            .state()
            .tab(tab.num)
            .and_then(|t| t.refs.lookup(number).cloned())
            .ok_or_else(|| {
                ToolError::browser(format!(
                    "ref e{number} is unknown: the page navigated since the snapshot that issued it, or it was never issued. \
                     Call page_snapshot again."
                ))
                .with_detail(json!({ "stale_ref": true }))
            })
    }
}
