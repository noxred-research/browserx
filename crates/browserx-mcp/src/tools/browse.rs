//! Browsing and interaction tools (capabilities `browse`, `interact`, `evaluate`).
//!
//! Every tool here resolves the session to one this server controls, locks its browser
//! connection for the duration of the call, and returns trusted metadata separately from
//! page-derived text, which [`Output::page`] wraps as untrusted.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::{Args, Output, session_id};
use crate::browse::parse_ref;
use crate::browse::{
    ActionOutcome, Direction, Handle, NetFilter, ScrollRequest, SelectBy, TabRef, WaitFor,
};
use crate::ctx::Ctx;
use crate::error::{ToolError, ToolResult};

async fn connect(ctx: &Arc<Ctx>, args: &Args) -> ToolResult<(Handle, String)> {
    let id = session_id(args)?;
    let managed = ctx.registry.get(&id).ok_or_else(|| {
        ToolError::refused(format!(
            "{id} is not controlled by this server: browse only sessions it created (create_session) or was configured to adopt"
        ))
    })?;
    let handle = ctx
        .hub
        .connection(&id, &managed.token, &ctx.backend)
        .await?;
    Ok((handle, id))
}

pub(super) async fn open(ctx: &Arc<Ctx>, args: &Args) -> ToolResult<(Handle, String, TabRef)> {
    let (handle, id) = connect(ctx, args).await?;
    let tab = handle.tab(args.str("tab_id")).await?;
    Ok((handle, id, tab))
}

pub(super) fn origin_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .map_or_else(
            || "about:blank".to_owned(),
            |u| u.origin().ascii_serialization(),
        )
}

fn meta(id: &str, tab: &TabRef, handle: &Handle) -> Map<String, Value> {
    let mut meta = Map::new();
    meta.insert("session_id".into(), json!(id));
    meta.insert("tab_id".into(), json!(tab.id));
    if let Some(notice) = &handle.notice {
        meta.insert("notice".into(), json!(notice));
    }
    meta
}

fn chars(ctx: &Ctx, args: &Args) -> usize {
    let cap = ctx.cfg.browse.max_chars_cap;
    args.u64("max_chars")
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(ctx.cfg.browse.default_max_chars)
        .clamp(500, cap)
}

fn at_page(url: &str, title: &str) -> String {
    format!("url: {url}\ntitle: {title}")
}

fn action_output(id: &str, tab: &TabRef, handle: &Handle, outcome: &ActionOutcome) -> Output {
    let mut m = meta(id, tab, handle);
    m.insert("navigated".into(), json!(outcome.navigated));
    m.insert("settled".into(), json!(outcome.settled));
    m.insert(
        "next".into(),
        json!("The page may have changed: take a new page_snapshot before using more refs."),
    );
    Output::page(
        &Value::Object(m),
        &origin_of(&outcome.url),
        &at_page(&outcome.url, &outcome.title),
    )
}

pub(super) async fn open_page(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let url = args.req_str("url")?;
    ctx.scope
        .check_url(url)
        .map_err(|r| ToolError::refused(r.0))?;
    let (handle, id) = connect(ctx, args).await?;
    let tab = if args.bool("new_tab") == Some(true) {
        handle.new_tab().await?
    } else {
        handle.tab(args.str("tab_id")).await?
    };
    let nav = handle.navigate(&tab, url).await?;
    let mut m = meta(&id, &tab, &handle);
    m.insert("settled".into(), json!(nav.settled));
    Ok(Output::page(
        &Value::Object(m),
        &origin_of(&nav.url),
        &at_page(&nav.url, &nav.title),
    ))
}

pub(super) async fn history(ctx: &Arc<Ctx>, args: &Args, delta: i64) -> ToolResult {
    let (handle, id, tab) = open(ctx, args).await?;
    let nav = handle.history(&tab, delta).await?;
    let mut m = meta(&id, &tab, &handle);
    m.insert("settled".into(), json!(nav.settled));
    Ok(Output::page(
        &Value::Object(m),
        &origin_of(&nav.url),
        &at_page(&nav.url, &nav.title),
    ))
}

pub(super) async fn page_snapshot(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, args).await?;
    let snap = handle
        .snapshot(
            &tab,
            chars(ctx, args),
            args.bool("interactive_only").unwrap_or(false),
        )
        .await?;
    let mut m = meta(&id, &tab, &handle);
    m.insert("refs".into(), json!(snap.rendered.refs));
    m.insert("lines".into(), json!(snap.rendered.lines));
    m.insert("truncated".into(), json!(snap.rendered.truncated));
    let body = format!(
        "url: {}\ntitle: {}\n---\n{}",
        snap.url, snap.rendered.title, snap.rendered.text
    );
    Ok(Output::page(
        &Value::Object(m),
        &origin_of(&snap.url),
        &body,
    ))
}

pub(super) async fn page_text(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, args).await?;
    let page = handle.page_text(&tab, chars(ctx, args)).await?;
    let mut m = meta(&id, &tab, &handle);
    m.insert("truncated".into(), json!(page.truncated));
    let body = format!(
        "url: {}\ntitle: {}\n---\n{}",
        page.url, page.title, page.text
    );
    Ok(Output::page(
        &Value::Object(m),
        &origin_of(&page.url),
        &body,
    ))
}

pub(super) async fn screenshot(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, args).await?;
    let shot = handle
        .screenshot(&tab, args.bool("full_page").unwrap_or(false))
        .await?;
    let mut m = meta(&id, &tab, &handle);
    m.insert("width".into(), json!(shot.width));
    m.insert("height".into(), json!(shot.height));
    m.insert("bytes".into(), json!(shot.bytes));
    Ok(Output::image(&Value::Object(m), "image/png", &shot.data))
}

pub(super) async fn list_tabs(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id) = connect(ctx, args).await?;
    let tabs = handle.list_tabs().await?;
    let body: Vec<String> = tabs
        .iter()
        .map(|t| {
            format!(
                "{}{} \"{}\" {} [{}]",
                t.id,
                if t.current { " *" } else { "" },
                t.title,
                t.url,
                if t.in_scope {
                    "in scope"
                } else {
                    "OUT OF SCOPE"
                }
            )
        })
        .collect();
    let m = json!({ "session_id": id, "count": tabs.len(), "notice": handle.notice });
    Ok(Output::page(&m, "browser-tabs", &body.join("\n")))
}

pub(super) async fn switch_tab(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id) = connect(ctx, args).await?;
    let tab = handle.switch_tab(args.req_str("tab_id")?).await?;
    Ok(Output::json(
        json!({ "session_id": id, "current_tab": tab.id }),
    ))
}

pub(super) async fn close_tab(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id) = connect(ctx, args).await?;
    let closed = handle.close_tab(args.str("tab_id")).await?;
    Ok(Output::json(json!({ "session_id": id, "closed": closed })))
}

pub(super) async fn wait_for(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let target = match (args.str("text"), args.str("ref")) {
        (Some(text), None) => WaitFor::Text(text.to_owned()),
        (None, Some(reference)) => WaitFor::Ref(
            parse_ref(reference).ok_or_else(|| ToolError::invalid("ref must look like e12"))?,
        ),
        _ => return Err(ToolError::invalid("give exactly one of `text` or `ref`")),
    };
    let (handle, id, tab) = open(ctx, args).await?;
    let waited = handle
        .wait_for(
            &tab,
            &target,
            args.bool("gone").unwrap_or(false),
            Duration::from_millis(args.u64("timeout_ms").unwrap_or(10_000)),
        )
        .await?;
    Ok(Output::json(json!({
        "session_id": id,
        "tab_id": tab.id,
        "satisfied": true,
        "waited_ms": u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
        "notice": handle.notice,
    })))
}

pub(super) async fn network_log(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, args).await?;
    let entries = handle.network_log(
        &tab,
        &NetFilter {
            limit: usize::try_from(args.u64("limit").unwrap_or(50)).unwrap_or(50),
            url_contains: args.str("url_contains").map(str::to_owned),
            resource_type: args.str("resource_type").map(str::to_owned),
            failed_only: args.bool("failed_only").unwrap_or(false),
        },
    );
    let lines: Vec<String> = entries
        .iter()
        .map(|e| {
            format!(
                "+{}ms {} {} {} {} {}B {}{}",
                e.at_ms,
                e.method,
                e.status.map_or_else(|| "-".to_owned(), |s| s.to_string()),
                e.resource_type,
                e.mime.as_deref().unwrap_or("-"),
                e.size.map_or_else(|| "-".to_owned(), |s| s.to_string()),
                e.url,
                e.error
                    .as_ref()
                    .map_or_else(String::new, |err| format!(" ERROR {err}")),
            )
        })
        .collect();
    let mut m = meta(&id, &tab, &handle);
    m.insert("count".into(), json!(entries.len()));
    Ok(Output::page(
        &Value::Object(m),
        "network-log",
        &lines.join("\n"),
    ))
}

pub(super) async fn console_log(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, args).await?;
    let entries = handle.console_log(
        &tab,
        args.str("level"),
        usize::try_from(args.u64("limit").unwrap_or(50)).unwrap_or(50),
    );
    let lines: Vec<String> = entries
        .iter()
        .map(|e| format!("+{}ms [{}] {}", e.at_ms, e.level, e.text))
        .collect();
    let mut m = meta(&id, &tab, &handle);
    m.insert("count".into(), json!(entries.len()));
    Ok(Output::page(
        &Value::Object(m),
        "console-log",
        &lines.join("\n"),
    ))
}

pub(super) async fn click(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, args).await?;
    let outcome = handle.click(&tab, args.req_str("ref")?).await?;
    Ok(action_output(&id, &tab, &handle, &outcome))
}

pub(super) async fn hover(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, args).await?;
    let outcome = handle.hover(&tab, args.req_str("ref")?).await?;
    Ok(action_output(&id, &tab, &handle, &outcome))
}

pub(super) async fn type_text(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, args).await?;
    let outcome = handle
        .type_text(
            &tab,
            args.req_str("ref")?,
            args.req_str("text")?,
            args.bool("clear").unwrap_or(false),
            args.bool("submit").unwrap_or(false),
        )
        .await?;
    Ok(action_output(&id, &tab, &handle, &outcome))
}

pub(super) async fn press_key(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let modifiers: Vec<String> = args
        .0
        .get("modifiers")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let (handle, id, tab) = open(ctx, args).await?;
    let outcome = handle
        .press_key(&tab, args.req_str("key")?, &modifiers)
        .await?;
    Ok(action_output(&id, &tab, &handle, &outcome))
}

pub(super) async fn select_option(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let by = match (args.str("value"), args.str("label")) {
        (Some(value), None) => SelectBy::Value(value.to_owned()),
        (None, Some(label)) => SelectBy::Label(label.to_owned()),
        _ => return Err(ToolError::invalid("give exactly one of `value` or `label`")),
    };
    let (handle, id, tab) = open(ctx, args).await?;
    let (chosen, outcome) = handle
        .select_option(&tab, args.req_str("ref")?, &by)
        .await?;
    let mut m = meta(&id, &tab, &handle);
    m.insert("navigated".into(), json!(outcome.navigated));
    m.insert("settled".into(), json!(outcome.settled));
    let body = format!(
        "selected: {chosen}\n{}",
        at_page(&outcome.url, &outcome.title)
    );
    Ok(Output::page(
        &Value::Object(m),
        &origin_of(&outcome.url),
        &body,
    ))
}

pub(super) async fn scroll(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, args).await?;
    let position = match args.str("to") {
        Some(to) => handle.scroll_to(&tab, to == "bottom").await?,
        None => {
            let direction = match args.str("direction").unwrap_or("down") {
                "up" => Direction::Up,
                "left" => Direction::Left,
                "right" => Direction::Right,
                _ => Direction::Down,
            };
            let amount = i64::try_from(args.u64("amount").unwrap_or(600)).unwrap_or(600);
            handle
                .scroll(&tab, ScrollRequest { direction, amount }, args.str("ref"))
                .await?
        }
    };
    Ok(Output::json(json!({
        "session_id": id,
        "tab_id": tab.id,
        "scroll": position,
        "notice": handle.notice,
    })))
}

pub(super) async fn evaluate_js(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, args).await?;
    let (text, truncated) = handle
        .evaluate(&tab, args.req_str("expression")?, chars(ctx, args))
        .await?;
    let mut m = meta(&id, &tab, &handle);
    m.insert("truncated".into(), json!(truncated));
    let url = handle
        .list_tabs()
        .await
        .ok()
        .and_then(|tabs| tabs.into_iter().find(|t| t.id == tab.id).map(|t| t.url));
    Ok(Output::page(
        &Value::Object(m),
        &url.as_deref()
            .map_or_else(|| "about:blank".to_owned(), origin_of),
        &text,
    ))
}
