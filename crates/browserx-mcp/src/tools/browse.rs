//! Browsing and interaction tools (capabilities `browse`, `interact`, `evaluate`).
//!
//! Every tool here resolves the session to one this server controls, locks its browser
//! connection for the duration of the call, and returns trusted metadata separately from
//! page-derived text, which [`Output::page`] wraps as untrusted.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::{Args, Call, Output, session_id};
use crate::browse::parse_ref;
use crate::browse::{
    ActionOutcome, Direction, FindQuery, Handle, MAX_FIND_LIMIT, NetFilter, ScrollRequest,
    SelectBy, SnapshotRequest, TabRef, WaitFor,
};
use crate::classifier::{ActionClass, Features, Intent, classify};
use crate::ctx::Ctx;
use crate::error::{ToolError, ToolResult};
use crate::gate::{self, Kind, Subject};
use crate::ledger::Flag;

async fn connect(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult<(Handle, String)> {
    let id = session_id(args)?;
    let managed = ctx.registry.get(&id).ok_or_else(|| {
        ToolError::refused(format!(
            "{id} is not controlled by this server: browse only sessions it created (create_session) or was configured to adopt"
        ))
    })?;
    if managed.adopted {
        ctx.ledger.mark(
            &call.handle,
            Flag::B,
            "an adopted session (its state is not known to be clean) is in use",
        );
    }
    if let Some(reason) = &managed.sensitive {
        ctx.ledger.mark(&call.handle, Flag::B, reason);
    }
    let handle = ctx
        .hub
        .connection(&id, &managed.token, &ctx.backend)
        .await?;
    Ok((handle, id))
}

pub(super) async fn open(
    ctx: &Arc<Ctx>,
    call: &Call<'_>,
    args: &Args,
) -> ToolResult<(Handle, String, TabRef)> {
    let (handle, id) = connect(ctx, call, args).await?;
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

/// Authorizes a read-class call on the page the tab shows (plan, grant, manifest).
pub(super) fn read_gate(
    ctx: &Ctx,
    call: &Call<'_>,
    tool: &'static str,
    handle: &Handle,
    tab: &TabRef,
) -> ToolResult<()> {
    gate::authorize(
        ctx,
        call,
        &Subject::plain(tool, ActionClass::Read, &handle.tab_url(tab)),
    )
}

fn sha(text: &str) -> String {
    crate::audit::sha256_hex(text)
}

/// Classifies the element behind `reference` and authorizes the action.
#[allow(clippy::too_many_arguments)]
async fn authorize_element(
    ctx: &Ctx,
    call: &Call<'_>,
    handle: &Handle,
    tab: &TabRef,
    tool: &'static str,
    reference: &str,
    intent: Intent,
    args_digest: String,
) -> ToolResult<()> {
    let info = handle.resolve(tab, reference).await?;
    let features = handle.element_features(tab, info.backend).await?;
    let target = format!("{} {} ({reference})", info.role, info.name);
    authorize_features(
        ctx,
        call,
        handle,
        tab,
        tool,
        &features,
        intent,
        target,
        args_digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn authorize_features(
    ctx: &Ctx,
    call: &Call<'_>,
    handle: &Handle,
    tab: &TabRef,
    tool: &'static str,
    features: &Features,
    intent: Intent,
    target: String,
    args_digest: String,
) -> ToolResult<()> {
    let classification = classify(features, intent, &|url| ctx.scope.is_rw_url(url));
    let url = if features.page_url.is_empty() {
        handle.tab_url(tab)
    } else {
        features.page_url.clone()
    };
    let submits = |f: &Features| {
        let method = f
            .formmethod
            .as_deref()
            .or(f.form_method.as_deref())
            .unwrap_or("get")
            .to_ascii_uppercase();
        f.formaction
            .clone()
            .or_else(|| f.form_action.clone())
            .map(|action| (method, action))
    };
    let request = match intent {
        Intent::Click | Intent::PressEnter | Intent::TypeText { submit: true } => features
            .href
            .clone()
            .map(|href| ("GET".to_owned(), href))
            .or_else(|| submits(features)),
        _ => None,
    };
    let mut subject = Subject::plain(tool, classification.class, &url);
    subject.kind = Kind::Element;
    subject.target = target;
    subject.request = request;
    subject.args_digest = args_digest;
    subject.rules = classification.rules.clone();
    subject.consequential =
        classification.class.severity() >= ActionClass::SubmitStateChange.severity();
    gate::authorize(ctx, call, &subject)
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

pub(super) async fn open_page(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let url = args.req_str("url")?;
    let mut subject = Subject::plain("open_page", ActionClass::NavigateInScope, url);
    subject.request = Some(("GET".to_owned(), url.to_owned()));
    match ctx.scope.check_model_url(url) {
        Ok(_) => {}
        Err(refusal) if refusal.approvable() => subject.force_approval = Some(refusal.code()),
        Err(refusal) => return Err(refusal.into()),
    }
    if ctx.redactor.text(url) != url {
        return Err(ToolError::refused_with(
            "secret_in_url",
            "the URL contains a secret value: it is never sent to a page",
        ));
    }
    let (handle, id) = connect(ctx, call, args).await?;
    gate::authorize(ctx, call, &subject)?;
    let tab = if args.bool("new_tab") == Some(true) {
        handle.new_tab().await?
    } else {
        handle.tab(args.str("tab_id")).await?
    };
    let nav = handle.navigate(&tab, url).await?;
    gate::note_target(ctx, call, &nav.url);
    let mut m = meta(&id, &tab, &handle);
    m.insert("settled".into(), json!(nav.settled));
    Ok(Output::page(
        &Value::Object(m),
        &origin_of(&nav.url),
        &at_page(&nav.url, &nav.title),
    ))
}

pub(super) async fn history(
    ctx: &Arc<Ctx>,
    call: &Call<'_>,
    args: &Args,
    delta: i64,
) -> ToolResult {
    let (handle, id, tab) = open(ctx, call, args).await?;
    gate::authorize(
        ctx,
        call,
        &Subject::plain(
            call.tool,
            ActionClass::NavigateInScope,
            &handle.tab_url(&tab),
        ),
    )?;
    let nav = handle.history(&tab, delta).await?;
    gate::note_target(ctx, call, &nav.url);
    let mut m = meta(&id, &tab, &handle);
    m.insert("settled".into(), json!(nav.settled));
    Ok(Output::page(
        &Value::Object(m),
        &origin_of(&nav.url),
        &at_page(&nav.url, &nav.title),
    ))
}

pub(super) async fn page_snapshot(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, call, args).await?;
    read_gate(ctx, call, "page_snapshot", &handle, &tab)?;
    let request = SnapshotRequest {
        max_chars: chars(ctx, args),
        interactive_only: args.bool("interactive_only").unwrap_or(false),
        include_hidden: args.bool("include_hidden").unwrap_or(false),
        since: args.str("since").map(str::to_owned),
    };
    let snap = handle
        .snapshot(&tab, &request, &|origin| ctx.scope.read_allowed(origin))
        .await?;
    ctx.scope.observe(snap.links.iter().map(String::as_str));
    let mut m = meta(&id, &tab, &handle);
    m.insert("snapshot_id".into(), json!(snap.snapshot_id));
    m.insert("refs".into(), json!(snap.refs));
    m.insert("lines".into(), json!(snap.lines));
    m.insert("truncated".into(), json!(snap.truncated));
    m.insert("hidden_omitted".into(), json!(snap.hidden_omitted));
    m.insert("hidden_detection".into(), json!(snap.hidden_detection));
    m.insert("frames".into(), json!(snap.frames));
    if let Some(since) = args.str("since") {
        m.insert("since".into(), json!(since));
        if snap.since_unknown {
            m.insert("since_unknown".into(), json!(true));
            if let Some(note) = snap.since_note {
                m.insert("since_note".into(), json!(note));
            }
        }
    }
    if let Some(delta) = snap.delta {
        m.insert(
            "delta".into(),
            json!({
                "added": delta.added,
                "changed": delta.changed,
                "removed": delta.removed,
                "unchanged": delta.unchanged,
            }),
        );
    }
    let body = format!(
        "url: {}\ntitle: {}\nsnapshot_id: {}\n---\n{}",
        snap.url, snap.title, snap.snapshot_id, snap.text
    );
    Ok(Output::page(
        &Value::Object(m),
        &origin_of(&snap.url),
        &body,
    ))
}

pub(super) async fn find_in_snapshot(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let text = args.str("text").filter(|t| !t.is_empty());
    let role = args.str("role").filter(|r| !r.is_empty());
    if text.is_none() && role.is_none() {
        return Err(ToolError::invalid(
            "give `text` (part of the accessible name or value) and/or `role`",
        ));
    }
    let limit = args
        .u64("limit")
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(20)
        .clamp(1, MAX_FIND_LIMIT);
    let query = FindQuery {
        text: text.map(str::to_owned),
        role: role.map(str::to_owned),
        limit,
        snapshot_id: args.str("snapshot_id").map(str::to_owned),
    };
    let (handle, id, tab) = open(ctx, call, args).await?;
    read_gate(ctx, call, "find_in_snapshot", &handle, &tab)?;
    let found = handle
        .find_in_snapshot(&tab, &query, &|origin| ctx.scope.read_allowed(origin))
        .await?;
    let mut m = meta(&id, &tab, &handle);
    m.insert("matches".into(), json!(found.matches));
    m.insert("snapshot_id".into(), json!(found.snapshot_id));
    m.insert("truncated".into(), json!(found.truncated));
    if found.fresh {
        m.insert("fresh_snapshot".into(), json!(true));
    }
    let body = if found.lines.is_empty() {
        "no matches".to_owned()
    } else {
        found.lines.join("\n")
    };
    Ok(Output::page(
        &Value::Object(m),
        &origin_of(&found.url),
        &body,
    ))
}

pub(super) async fn page_text(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, call, args).await?;
    read_gate(ctx, call, "page_text", &handle, &tab)?;
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

pub(super) async fn screenshot(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, call, args).await?;
    read_gate(ctx, call, "screenshot", &handle, &tab)?;
    if ctx.scope.grant().is_some() {
        // Pixels cannot be filtered by origin: a frame the grant does not let the session read
        // would be in the image.
        let frames = handle.frame_origins(&tab).await?;
        if frames.unknown > 0 {
            return Err(ToolError::refused_with(
                "frame_not_in_ro",
                format!(
                    "the page embeds {} frame(s) whose origin the browser did not report: a screenshot could show content the scope grant does not let this session read",
                    frames.unknown
                ),
            ));
        }
        for origin in frames.origins {
            if !ctx.scope.read_allowed(&origin) {
                return Err(ToolError::refused_with(
                    "frame_not_in_ro",
                    format!(
                        "the page embeds content from {origin}, which the scope grant does not let this session read: a screenshot would show it"
                    ),
                ));
            }
        }
    }
    let shot = handle
        .screenshot(&tab, args.bool("full_page").unwrap_or(false))
        .await?;
    let mut m = meta(&id, &tab, &handle);
    m.insert("width".into(), json!(shot.width));
    m.insert("height".into(), json!(shot.height));
    m.insert("bytes".into(), json!(shot.bytes));
    Ok(Output::image(&Value::Object(m), "image/png", &shot.data))
}

pub(super) async fn list_tabs(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id) = connect(ctx, call, args).await?;
    gate::authorize(
        ctx,
        call,
        &Subject::plain("list_tabs", ActionClass::Read, "about:blank"),
    )?;
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

pub(super) async fn switch_tab(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id) = connect(ctx, call, args).await?;
    gate::authorize(
        ctx,
        call,
        &Subject::plain("switch_tab", ActionClass::Read, "about:blank"),
    )?;
    let tab = handle.switch_tab(args.req_str("tab_id")?).await?;
    Ok(Output::json(
        json!({ "session_id": id, "current_tab": tab.id }),
    ))
}

pub(super) async fn close_tab(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id) = connect(ctx, call, args).await?;
    gate::authorize(
        ctx,
        call,
        &Subject::plain("close_tab", ActionClass::Read, "about:blank"),
    )?;
    let closed = handle.close_tab(args.str("tab_id")).await?;
    Ok(Output::json(json!({ "session_id": id, "closed": closed })))
}

pub(super) async fn wait_for(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let target = match (args.str("text"), args.str("ref")) {
        (Some(text), None) => WaitFor::Text(text.to_owned()),
        (None, Some(reference)) => WaitFor::Ref(
            parse_ref(reference).ok_or_else(|| ToolError::invalid("ref must look like e12"))?,
        ),
        _ => return Err(ToolError::invalid("give exactly one of `text` or `ref`")),
    };
    let (handle, id, tab) = open(ctx, call, args).await?;
    read_gate(ctx, call, "wait_for", &handle, &tab)?;
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

pub(super) async fn network_log(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, call, args).await?;
    read_gate(ctx, call, "network_log", &handle, &tab)?;
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

pub(super) async fn console_log(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, call, args).await?;
    read_gate(ctx, call, "console_log", &handle, &tab)?;
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

pub(super) async fn click(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, call, args).await?;
    let reference = args.req_str("ref")?;
    authorize_element(
        ctx,
        call,
        &handle,
        &tab,
        "click",
        reference,
        Intent::Click,
        String::new(),
    )
    .await?;
    let outcome = handle.click(&tab, reference).await?;
    gate::note_target(ctx, call, &outcome.url);
    Ok(action_output(&id, &tab, &handle, &outcome))
}

pub(super) async fn hover(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, call, args).await?;
    read_gate(ctx, call, "hover", &handle, &tab)?;
    let outcome = handle.hover(&tab, args.req_str("ref")?).await?;
    Ok(action_output(&id, &tab, &handle, &outcome))
}

pub(super) async fn type_text(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, call, args).await?;
    let reference = args.req_str("ref")?;
    let text = args.req_str("text")?;
    let submit = args.bool("submit").unwrap_or(false);
    authorize_element(
        ctx,
        call,
        &handle,
        &tab,
        "type_text",
        reference,
        Intent::TypeText { submit },
        sha(text),
    )
    .await?;
    let outcome = handle
        .type_text(
            &tab,
            reference,
            text,
            args.bool("clear").unwrap_or(false),
            submit,
        )
        .await?;
    gate::note_target(ctx, call, &outcome.url);
    Ok(action_output(&id, &tab, &handle, &outcome))
}

pub(super) async fn press_key(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
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
    let (handle, id, tab) = open(ctx, call, args).await?;
    let key = args.req_str("key")?;
    let intent = match key {
        "Enter" => Some(Intent::PressEnter),
        "Space" | " " => Some(Intent::Click),
        _ => None,
    };
    match intent {
        Some(intent) => match handle.focused_features(&tab).await? {
            Some(features) => {
                let target = format!("{} {} (focused)", features.role, features.name);
                authorize_features(
                    ctx,
                    call,
                    &handle,
                    &tab,
                    "press_key",
                    &features,
                    intent,
                    target,
                    sha(key),
                )?;
            }
            None => read_gate(ctx, call, "press_key", &handle, &tab)?,
        },
        None => {
            let mut subject =
                Subject::plain("press_key", ActionClass::FormEdit, &handle.tab_url(&tab));
            subject.kind = Kind::Element;
            subject.args_digest = sha(key);
            gate::authorize(ctx, call, &subject)?;
        }
    }
    let outcome = handle.press_key(&tab, key, &modifiers).await?;
    gate::note_target(ctx, call, &outcome.url);
    Ok(action_output(&id, &tab, &handle, &outcome))
}

pub(super) async fn select_option(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let by = match (args.str("value"), args.str("label")) {
        (Some(value), None) => SelectBy::Value(value.to_owned()),
        (None, Some(label)) => SelectBy::Label(label.to_owned()),
        _ => return Err(ToolError::invalid("give exactly one of `value` or `label`")),
    };
    let (handle, id, tab) = open(ctx, call, args).await?;
    let reference = args.req_str("ref")?;
    authorize_element(
        ctx,
        call,
        &handle,
        &tab,
        "select_option",
        reference,
        Intent::SelectOption,
        sha(&format!("{by:?}")),
    )
    .await?;
    let (chosen, outcome) = handle.select_option(&tab, reference, &by).await?;
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

pub(super) async fn scroll(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, call, args).await?;
    read_gate(ctx, call, "scroll", &handle, &tab)?;
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

pub(super) async fn evaluate_js(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let (handle, id, tab) = open(ctx, call, args).await?;
    let expression = args.req_str("expression")?;
    let mut subject = Subject::plain("evaluate_js", ActionClass::Unknown, &handle.tab_url(&tab));
    subject.kind = Kind::Evaluate;
    subject.target = format!("a script of {} characters", expression.chars().count());
    subject.args_digest = sha(expression);
    subject.consequential = true;
    gate::authorize(ctx, call, &subject)?;
    let (text, truncated) = handle.evaluate(&tab, expression, chars(ctx, args)).await?;
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
