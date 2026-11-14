//! Interactions: click, type, keys, select, scroll, hover. Every interaction re-resolves its
//! element reference against the live accessibility tree and refuses a stale one.

use std::time::Duration;

use serde_json::{Value, json};

use super::ax::{self, RefInfo, parse_ref};
use super::conn::{Conn, TabRef};
use super::scripts;
use crate::error::{ToolError, ToolResult};

/// Longest text typed in one call, in characters.
pub const MAX_TYPE_CHARS: usize = 4000;
/// Most pixels one scroll call moves.
pub const MAX_SCROLL_PX: i64 = 5000;

/// What an interaction did to the page.
#[derive(Debug, Clone)]
pub struct ActionOutcome {
    /// URL after the action (inside the scope, or the call failed).
    pub url: String,
    /// Title after the action.
    pub title: String,
    /// A new document loaded.
    pub navigated: bool,
    /// The page finished loading before the timeout.
    pub settled: bool,
}

/// How `select_option` finds the option.
#[derive(Debug, Clone)]
pub enum SelectBy {
    /// The option's `value` attribute.
    Value(String),
    /// The option's visible label.
    Label(String),
}

/// Scroll directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Up.
    Up,
    /// Down.
    Down,
    /// Left.
    Left,
    /// Right.
    Right,
}

/// A scroll request.
#[derive(Debug, Clone, Copy)]
pub struct ScrollRequest {
    /// Direction to wheel.
    pub direction: Direction,
    /// Distance in CSS pixels.
    pub amount: i64,
}

struct KeyDef {
    key: String,
    code: String,
    vk: i64,
    text: Option<String>,
}

fn key_def(name: &str) -> Option<KeyDef> {
    let named = |key: &str, code: &str, vk: i64, text: Option<&str>| {
        Some(KeyDef {
            key: key.into(),
            code: code.into(),
            vk,
            text: text.map(str::to_owned),
        })
    };
    match name {
        "Enter" => named("Enter", "Enter", 13, Some("\r")),
        "Tab" => named("Tab", "Tab", 9, None),
        "Escape" => named("Escape", "Escape", 27, None),
        "Backspace" => named("Backspace", "Backspace", 8, None),
        "Delete" => named("Delete", "Delete", 46, None),
        "ArrowUp" => named("ArrowUp", "ArrowUp", 38, None),
        "ArrowDown" => named("ArrowDown", "ArrowDown", 40, None),
        "ArrowLeft" => named("ArrowLeft", "ArrowLeft", 37, None),
        "ArrowRight" => named("ArrowRight", "ArrowRight", 39, None),
        "Home" => named("Home", "Home", 36, None),
        "End" => named("End", "End", 35, None),
        "PageUp" => named("PageUp", "PageUp", 33, None),
        "PageDown" => named("PageDown", "PageDown", 34, None),
        "Space" | " " => named(" ", "Space", 32, Some(" ")),
        single if single.chars().count() == 1 => {
            let c = single.chars().next()?;
            if c.is_ascii_alphabetic() {
                Some(KeyDef {
                    key: single.into(),
                    code: format!("Key{}", c.to_ascii_uppercase()),
                    vk: i64::from(u32::from(c.to_ascii_uppercase())),
                    text: Some(single.into()),
                })
            } else if c.is_ascii_digit() {
                Some(KeyDef {
                    key: single.into(),
                    code: format!("Digit{c}"),
                    vk: i64::from(u32::from(c)),
                    text: Some(single.into()),
                })
            } else if c.is_ascii_graphic() {
                Some(KeyDef {
                    key: single.into(),
                    code: String::new(),
                    vk: 0,
                    text: Some(single.into()),
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

fn modifier_mask(modifiers: &[String]) -> ToolResult<i64> {
    let mut mask = 0;
    for modifier in modifiers {
        mask |= match modifier.as_str() {
            "Alt" => 1,
            "Control" | "Ctrl" => 2,
            "Meta" | "Command" => 4,
            "Shift" => 8,
            other => {
                return Err(ToolError::invalid(format!(
                    "unknown modifier {other:?}: use Alt, Control, Meta or Shift"
                )));
            }
        };
    }
    Ok(mask)
}

fn quad_center(quad: &[Value]) -> Option<(f64, f64, f64)> {
    let nums: Vec<f64> = quad.iter().filter_map(Value::as_f64).collect();
    if nums.len() < 8 {
        return None;
    }
    let xs = [nums[0], nums[2], nums[4], nums[6]];
    let ys = [nums[1], nums[3], nums[5], nums[7]];
    let width =
        xs.iter().copied().fold(f64::MIN, f64::max) - xs.iter().copied().fold(f64::MAX, f64::min);
    let height =
        ys.iter().copied().fold(f64::MIN, f64::max) - ys.iter().copied().fold(f64::MAX, f64::min);
    Some((
        xs.iter().sum::<f64>() / 4.0,
        ys.iter().sum::<f64>() / 4.0,
        width * height,
    ))
}

impl Conn {
    /// Re-resolves `number` against the live tree: the element must still exist with the same
    /// role and name as when the reference was issued.
    pub(super) async fn resolve_live(
        &self,
        tab: &TabRef,
        number: u32,
        info: &RefInfo,
    ) -> ToolResult<()> {
        #[cfg(feature = "fault-injection")]
        if crate::faults::active(crate::faults::Fault::StaleRef) {
            return Ok(());
        }
        let stale = |why: &str| {
            ToolError::browser(format!(
                "ref e{number} is stale ({why}). Call page_snapshot and use the new ref."
            ))
            .with_detail(json!({ "stale_ref": true }))
        };
        let reply = self
            .call(
                tab,
                "Accessibility.getPartialAXTree",
                json!({ "backendNodeId": info.backend, "fetchRelatives": false }),
            )
            .await
            .map_err(|_| stale("the element no longer exists"))?;
        let node = reply["nodes"]
            .as_array()
            .and_then(|nodes| {
                nodes
                    .iter()
                    .find(|n| n["backendDOMNodeId"].as_i64() == Some(info.backend))
            })
            .ok_or_else(|| stale("the element no longer exists"))?;
        if node["ignored"].as_bool() == Some(true) {
            return Err(stale("the element is no longer exposed"));
        }
        let (role, name) = ax::role_and_name(node);
        if role != info.role || name != info.name {
            return Err(stale(&format!(
                "it was {} {:?} and is now {} {:?}",
                info.role, info.name, role, name
            )));
        }
        Ok(())
    }

    pub(crate) async fn resolve(&self, tab: &TabRef, reference: &str) -> ToolResult<RefInfo> {
        let number = parse_ref(reference).ok_or_else(|| {
            ToolError::invalid(format!(
                "{reference:?} is not an element ref: use the eN values from page_snapshot"
            ))
        })?;
        let info = self.ref_info(tab, number)?;
        self.resolve_live(tab, number, &info).await?;
        Ok(info)
    }

    /// Scrolls the element into view and returns the center of its box.
    async fn center_of(&self, tab: &TabRef, info: &RefInfo) -> ToolResult<(f64, f64)> {
        let _ = self
            .call(
                tab,
                "DOM.scrollIntoViewIfNeeded",
                json!({ "backendNodeId": info.backend }),
            )
            .await;
        let model = self
            .call(
                tab,
                "DOM.getBoxModel",
                json!({ "backendNodeId": info.backend }),
            )
            .await
            .map_err(|_| ToolError::browser("the element has no layout box (it may be hidden)"))?;
        let quad = model["model"]["content"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        match quad_center(&quad) {
            Some((x, y, area)) if area > 0.0 => Ok((x, y)),
            _ => Err(ToolError::browser(
                "the element has an empty box (it may be hidden or collapsed)",
            )),
        }
    }

    async fn mouse(
        &self,
        tab: &TabRef,
        kind: &str,
        x: f64,
        y: f64,
        pressed: bool,
    ) -> ToolResult<()> {
        let mut params = json!({ "type": kind, "x": x, "y": y, "button": "none", "buttons": 0 });
        if kind != "mouseMoved" {
            params["button"] = json!("left");
            params["clickCount"] = json!(1);
            params["buttons"] = json!(i32::from(pressed));
        }
        self.call(tab, "Input.dispatchMouseEvent", params)
            .await
            .map(|_| ())
    }

    async fn finish(
        &self,
        tab: &TabRef,
        before: u64,
        settle: Duration,
    ) -> ToolResult<ActionOutcome> {
        let (url, settled) = self.settle_and_check(tab, settle).await?;
        let navigated = self
            .shared
            .state()
            .tab(tab.num)
            .is_some_and(|t| t.navigations != before);
        Ok(ActionOutcome {
            url,
            title: self.title(tab).await,
            navigated,
            settled,
        })
    }

    fn navigations(&self, tab: &TabRef) -> u64 {
        self.shared
            .state()
            .tab(tab.num)
            .map_or(0, |t| t.navigations)
    }

    /// Clicks the element.
    pub async fn click(&self, tab: &TabRef, reference: &str) -> ToolResult<ActionOutcome> {
        let info = self.resolve(tab, reference).await?;
        let (x, y) = self.center_of(tab, &info).await?;
        let before = self.navigations(tab);
        self.mouse(tab, "mouseMoved", x, y, false).await?;
        self.mouse(tab, "mousePressed", x, y, true).await?;
        self.mouse(tab, "mouseReleased", x, y, false).await?;
        self.finish(tab, before, Duration::from_millis(300)).await
    }

    /// Moves the pointer over the element.
    pub async fn hover(&self, tab: &TabRef, reference: &str) -> ToolResult<ActionOutcome> {
        let info = self.resolve(tab, reference).await?;
        let (x, y) = self.center_of(tab, &info).await?;
        let before = self.navigations(tab);
        self.mouse(tab, "mouseMoved", x, y, false).await?;
        self.finish(tab, before, Duration::from_millis(200)).await
    }

    async fn key(&self, tab: &TabRef, name: &str, modifiers: i64) -> ToolResult<()> {
        let def = key_def(name).ok_or_else(|| {
            ToolError::invalid(format!(
                "unknown key {name:?}: use a single character or Enter, Tab, Escape, Backspace, Delete, \
                 Arrow*, Home, End, PageUp, PageDown, Space"
            ))
        })?;
        let text = def.text.as_deref().filter(|_| modifiers & 0b0111 == 0);
        let mut down = json!({
            "type": if text.is_some() { "keyDown" } else { "rawKeyDown" },
            "key": def.key, "code": def.code, "windowsVirtualKeyCode": def.vk, "modifiers": modifiers,
        });
        if let Some(text) = text {
            down["text"] = json!(text);
        }
        self.call(tab, "Input.dispatchKeyEvent", down).await?;
        self.call(
            tab,
            "Input.dispatchKeyEvent",
            json!({
                "type": "keyUp", "key": def.key, "code": def.code,
                "windowsVirtualKeyCode": def.vk, "modifiers": modifiers,
            }),
        )
        .await
        .map(|_| ())
    }

    /// Presses a key (with modifiers) in the focused element.
    pub async fn press_key(
        &self,
        tab: &TabRef,
        key: &str,
        modifiers: &[String],
    ) -> ToolResult<ActionOutcome> {
        let mask = modifier_mask(modifiers)?;
        let before = self.navigations(tab);
        self.key(tab, key, mask).await?;
        self.finish(tab, before, Duration::from_millis(300)).await
    }

    /// Focuses the element and types `text`, optionally replacing its content and pressing Enter.
    pub async fn type_text(
        &self,
        tab: &TabRef,
        reference: &str,
        text: &str,
        clear: bool,
        submit: bool,
    ) -> ToolResult<ActionOutcome> {
        if text.chars().count() > MAX_TYPE_CHARS {
            return Err(ToolError::invalid(format!(
                "text is longer than {MAX_TYPE_CHARS} characters"
            )));
        }
        let info = self.resolve(tab, reference).await?;
        let _ = self
            .call(
                tab,
                "DOM.scrollIntoViewIfNeeded",
                json!({ "backendNodeId": info.backend }),
            )
            .await;
        self.call(tab, "DOM.focus", json!({ "backendNodeId": info.backend }))
            .await
            .map_err(|_| ToolError::browser("the element cannot take focus"))?;
        if clear {
            let object = self
                .call(
                    tab,
                    "DOM.resolveNode",
                    json!({ "backendNodeId": info.backend }),
                )
                .await?;
            if let Some(object_id) = object["object"]["objectId"].as_str() {
                self.call(
                    tab,
                    "Runtime.callFunctionOn",
                    json!({ "objectId": object_id, "functionDeclaration": scripts::SELECT_CONTENT, "returnByValue": true }),
                )
                .await?;
            }
        }
        let before = self.navigations(tab);
        if !text.is_empty() {
            self.call(tab, "Input.insertText", json!({ "text": text }))
                .await?;
        }
        if submit {
            self.key(tab, "Enter", 0).await?;
        }
        self.finish(
            tab,
            before,
            Duration::from_millis(if submit { 400 } else { 100 }),
        )
        .await
    }

    /// Chooses an option of a `<select>`.
    pub async fn select_option(
        &self,
        tab: &TabRef,
        reference: &str,
        by: &SelectBy,
    ) -> ToolResult<(String, ActionOutcome)> {
        let info = self.resolve(tab, reference).await?;
        let object = self
            .call(
                tab,
                "DOM.resolveNode",
                json!({ "backendNodeId": info.backend }),
            )
            .await?;
        let object_id = object["object"]["objectId"]
            .as_str()
            .ok_or_else(|| ToolError::browser("the element cannot be resolved"))?
            .to_owned();
        let (value, label) = match by {
            SelectBy::Value(v) => (json!(v), Value::Null),
            SelectBy::Label(l) => (Value::Null, json!(l)),
        };
        let before = self.navigations(tab);
        let reply = self
            .call(
                tab,
                "Runtime.callFunctionOn",
                json!({
                    "objectId": object_id,
                    "functionDeclaration": scripts::SELECT_OPTION,
                    "arguments": [{ "value": value }, { "value": label }],
                    "returnByValue": true,
                }),
            )
            .await?;
        let result = &reply["result"]["value"];
        if result["ok"].as_bool() != Some(true) {
            let why = result["error"].as_str().map_or_else(
                || format!("no such option; available: {}", result["options"]),
                str::to_owned,
            );
            return Err(ToolError::browser(format!("select_option failed: {why}")));
        }
        let chosen = result["label"].as_str().unwrap_or("").to_owned();
        Ok((
            chosen,
            self.finish(tab, before, Duration::from_millis(300)).await?,
        ))
    }

    /// Scrolls the page (or the element under the pointer at the element's center).
    pub async fn scroll(
        &self,
        tab: &TabRef,
        request: ScrollRequest,
        reference: Option<&str>,
    ) -> ToolResult<Value> {
        let (x, y) = match reference {
            Some(reference) => {
                let info = self.resolve(tab, reference).await?;
                self.center_of(tab, &info).await?
            }
            None => {
                let metrics = self.call(tab, "Page.getLayoutMetrics", json!({})).await?;
                let viewport = &metrics["cssVisualViewport"];
                (
                    viewport["clientWidth"].as_f64().unwrap_or(800.0) / 2.0,
                    viewport["clientHeight"].as_f64().unwrap_or(600.0) / 2.0,
                )
            }
        };
        let amount = request.amount.clamp(1, MAX_SCROLL_PX) as f64;
        let (dx, dy) = match request.direction {
            Direction::Up => (0.0, -amount),
            Direction::Down => (0.0, amount),
            Direction::Left => (-amount, 0.0),
            Direction::Right => (amount, 0.0),
        };
        self.call(
            tab,
            "Input.dispatchMouseEvent",
            json!({ "type": "mouseWheel", "x": x, "y": y, "deltaX": dx, "deltaY": dy }),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(250)).await;
        self.eval(tab, scripts::SCROLL_STATE, 2000).await
    }

    /// Scrolls to the top or bottom of the page.
    pub async fn scroll_to(&self, tab: &TabRef, bottom: bool) -> ToolResult<Value> {
        let target = if bottom {
            "document.documentElement.scrollHeight"
        } else {
            "0"
        };
        self.eval(tab, &format!("window.scrollTo(0, {target})"), 2000)
            .await?;
        tokio::time::sleep(Duration::from_millis(250)).await;
        self.eval(tab, scripts::SCROLL_STATE, 2000).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn key_table_covers_named_and_printable_keys() {
        let enter = key_def("Enter").unwrap();
        assert_eq!((enter.vk, enter.text.as_deref()), (13, Some("\r")));
        let a = key_def("a").unwrap();
        assert_eq!((a.code.as_str(), a.vk), ("KeyA", 65));
        let seven = key_def("7").unwrap();
        assert_eq!(seven.code, "Digit7");
        assert!(key_def("?").unwrap().text.is_some());
        for bad in ["", "Hyper", "ab", "\u{7f}"] {
            assert!(key_def(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn modifiers_map_to_the_cdp_bitmask() {
        assert_eq!(
            modifier_mask(&["Control".into(), "Shift".into()]).unwrap(),
            10
        );
        assert!(modifier_mask(&["Hyper".into()]).is_err());
    }

    #[test]
    fn box_center_and_area() {
        let quad: Vec<Value> = [10.0, 20.0, 110.0, 20.0, 110.0, 60.0, 10.0, 60.0]
            .iter()
            .map(|n| json!(n))
            .collect();
        assert_eq!(quad_center(&quad), Some((60.0, 40.0, 4000.0)));
        assert_eq!(quad_center(&quad[..4]), None);
    }
}
