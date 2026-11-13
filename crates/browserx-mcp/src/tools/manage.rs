//! Session lifecycle tools (capabilities `sessions` and `handoff`).

use std::collections::BTreeMap;
use std::sync::Arc;

use browserx_core::{Isolation, PersistenceMode, ProfileId, RecoveryPolicy, SessionSpec};
use serde_json::{Value, json};

use super::{Args, Output, session_id};
use crate::backend::BackendError;
use crate::ctx::Ctx;
use crate::error::{ToolError, ToolResult};
use crate::sessions::Managed;

/// Labels a model may set.
const MAX_MODEL_LABELS: usize = 8;

fn pick<T: serde::de::DeserializeOwned>(args: &Args, key: &str) -> ToolResult<Option<T>> {
    args.0
        .get(key)
        .map(|v| {
            serde_json::from_value(v.clone())
                .map_err(|_| ToolError::invalid(format!("`{key}` has an unsupported value")))
        })
        .transpose()
}

/// Stops controlling sessions the worker no longer runs (expired, lost, closed or purged), so a
/// session that ended on its own does not hold one of the controlled-session slots forever.
pub(super) async fn prune(ctx: &Ctx, listed: &[Value]) {
    let alive: std::collections::BTreeSet<&str> = listed
        .iter()
        .filter(|view| !matches!(view["status"].as_str(), Some("closed" | "lost")))
        .filter_map(|view| view["session_id"].as_str())
        .collect();
    for id in ctx.registry.ids() {
        if !alive.contains(id.as_str()) {
            ctx.registry.remove(&id);
            ctx.hub.forget(&id).await;
        }
    }
}

pub(super) async fn create_session(
    ctx: &Arc<Ctx>,
    call: &super::Call<'_>,
    args: &Args,
) -> ToolResult {
    if ctx.registry.created().len() >= ctx.cfg.sessions.max_tracked
        && let Ok(listed) = ctx.backend.list_sessions(None).await
    {
        prune(ctx, &listed).await;
    }
    if ctx.registry.created().len() >= ctx.cfg.sessions.max_tracked {
        return Err(ToolError::refused(format!(
            "this server already controls {} sessions (the limit); release one first",
            ctx.cfg.sessions.max_tracked
        )));
    }
    let mut labels: BTreeMap<String, String> = BTreeMap::new();
    if let Some(Value::Object(map)) = args.0.get("labels") {
        if map.len() > MAX_MODEL_LABELS {
            return Err(ToolError::invalid(format!(
                "at most {MAX_MODEL_LABELS} labels"
            )));
        }
        for (key, value) in map {
            if key.len() > 64 || key == "mcp" {
                return Err(ToolError::invalid(
                    "label keys are at most 64 bytes and `mcp` is reserved",
                ));
            }
            labels.insert(key.clone(), value.as_str().unwrap_or("").to_owned());
        }
    }
    labels.insert("mcp".into(), "true".into());

    let proxy = match args.str("proxy_route") {
        None => None,
        Some(name) => Some(
            ctx.routes
                .get(name)
                .cloned()
                .ok_or_else(|| ToolError::invalid(format!("no proxy route named {name:?}")))?,
        ),
    };
    let ttl = args
        .u64("ttl_secs")
        .unwrap_or(ctx.cfg.sessions.default_ttl_secs)
        .min(ctx.cfg.sessions.max_ttl_secs);
    let spec = SessionSpec {
        launch_profile: args.str("launch_profile").map(str::to_owned),
        persistence: pick::<PersistenceMode>(args, "persistence")?.unwrap_or_default(),
        isolation: pick::<Isolation>(args, "isolation")?.unwrap_or_default(),
        profile_id: args
            .str("profile_id")
            .map(|p| {
                ProfileId::parse(p).map_err(|_| {
                    ToolError::invalid("profile_id must look like prf_ followed by 32 hex digits")
                })
            })
            .transpose()?,
        proxy,
        ttl_secs: Some(ttl),
        max_lifetime_secs: None,
        idle_timeout_secs: args.u64("idle_timeout_secs"),
        recovery: pick::<RecoveryPolicy>(args, "recovery")?.unwrap_or_default(),
        labels,
    };
    spec.validate()?;
    let body = serde_json::to_value(&spec).map_err(|e| ToolError::internal(e.to_string()))?;
    let created = ctx.backend.create_session(&body).await?;
    let id = created.session["session_id"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let out = Output::json(json!({
        "session": created.session,
        "controlled": true,
        "note": "This server holds the controller token. Use the browse tools with this session_id; release it with release_session when done.",
    }));
    let out = if ctx.cfg.mcp.reveal_endpoints {
        out.reveal(created.token.expose(), created.cdp_url.expose())
    } else {
        out
    };
    let reason = match (
        args.str("persistence"),
        args.str("profile_id"),
        args.str("proxy_route"),
    ) {
        (Some("snapshot" | "profile"), _, _) => {
            Some("a session with persistent browser state was created")
        }
        (_, Some(_), _) => Some("a session that reuses a persistent identity was created"),
        (_, _, Some(_)) => Some("a session behind an upstream proxy route was created"),
        _ => None,
    };
    if let Some(reason) = reason {
        ctx.ledger
            .mark(&call.handle, crate::ledger::Flag::B, reason);
    }
    ctx.registry.insert(Managed {
        id,
        token: created.token,
        adopted: false,
        sensitive: reason.map(str::to_owned),
    });
    Ok(out)
}

fn controlled(ctx: &Ctx, id: &str) -> ToolResult<Managed> {
    ctx.registry.get(id).ok_or_else(|| {
        ToolError::refused(format!(
            "{id} is not controlled by this server: only sessions it created (this run) or was configured to adopt can be changed. list_sessions shows `controlled`."
        ))
    })
}

pub(super) async fn renew_session(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let id = session_id(args)?;
    let managed = controlled(ctx, &id)?;
    let current = ctx.backend.get_session(&id).await?;
    let generation = current["generation"].as_u64().unwrap_or(0);
    let ttl = args
        .u64("ttl_secs")
        .map(|t| t.min(ctx.cfg.sessions.max_ttl_secs));
    let view = ctx
        .backend
        .renew(&id, &managed.token, generation, ttl)
        .await?;
    Ok(Output::json(json!({ "session": view })))
}

pub(super) async fn snapshot_session(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let id = session_id(args)?;
    let managed = controlled(ctx, &id)?;
    let snapshot = ctx.backend.snapshot(&id, &managed.token).await?;
    Ok(Output::json(json!({ "snapshot": snapshot })))
}

pub(super) async fn release_session(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let id = session_id(args)?;
    let view = match ctx.registry.get(&id) {
        Some(managed) => {
            ctx.hub.forget(&id).await;
            match ctx.backend.release(&id, Some(&managed.token), None).await {
                Ok(view) => view,
                // Purged after it ended on its own: nothing is left to release.
                Err(BackendError::Api { status: 404, .. }) => Value::Null,
                Err(error) => return Err(error.into()),
            }
        }
        None => {
            // After a restart the token is gone, but the API key still owns the session.
            let current = ctx.backend.get_session(&id).await?;
            if current["labels"]["mcp"].as_str() != Some("true") {
                return Err(ToolError::refused(format!(
                    "{id} was not created by an MCP server: only sessions labelled mcp=true or controlled by this server can be released here"
                )));
            }
            ctx.backend.release(&id, None, None).await?
        }
    };
    ctx.registry.remove(&id);
    ctx.hub.forget(&id).await;
    Ok(Output::json(json!({ "released": true, "session": view })))
}

pub(super) async fn handoff_session(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let id = session_id(args)?;
    let managed = controlled(ctx, &id)?;
    let current = ctx.backend.get_session(&id).await?;
    let generation = current["generation"].as_u64().unwrap_or(0);
    let created = ctx.backend.handoff(&id, &managed.token, generation).await?;
    ctx.hub.forget(&id).await;
    let out = Output::json(json!({
        "session": created.session,
        "rotated": true,
        "note": "The previous token and every CDP URL issued with it are invalid now. The new token stays inside this server.",
    }));
    let out = if ctx.cfg.mcp.reveal_endpoints {
        out.reveal(created.token.expose(), created.cdp_url.expose())
    } else {
        out
    };
    ctx.registry.insert(Managed {
        id,
        token: created.token,
        adopted: managed.adopted,
        sensitive: managed.sensitive,
    });
    Ok(out)
}
