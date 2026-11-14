//! Engagement tools: the session ledger (`engagement_status`, `reset_context`) and scope grant
//! proposals (`propose_scope_grant`). A model uses them to see its situation and to ask for
//! less; nothing here widens anything.

use std::sync::Arc;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::format_description::well_known::Rfc3339;

use super::{Args, Call, Output};
use crate::ctx::Ctx;
use crate::error::{ToolError, ToolResult};
use crate::gate;
use crate::grants::{Ceiling, Grant, proposal_summary};

fn resolve(ctx: &Ctx, call: &Call<'_>, args: &Args) -> ToolResult<String> {
    ctx.ledger
        .resolve(call.principal, args.str("handle"))
        .map_err(|_| ToolError::refused_with("unknown_handle", "unknown handle"))
}

pub(super) fn status(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let handle = resolve(ctx, call, args)?;
    let Some(state) = ctx.ledger.status(&handle) else {
        return Err(ToolError::refused_with("unknown_handle", "unknown handle"));
    };
    let show = |t: Option<time::OffsetDateTime>| t.and_then(|t| t.format(&Rfc3339).ok());
    let manifest = ctx.scope.manifest().map(|loaded| {
        let status = loaded.status(Ctx::now());
        let mut view = json!({
            "status": status.name(),
            "digest": loaded.digest,
        });
        if loaded.trusted() {
            view["id"] = json!(loaded.manifest.id);
            view["impact"] = json!(loaded.manifest.impact.name());
            view["not_after"] = json!(show(loaded.manifest.not_after));
            view["scope"] = json!(
                loaded
                    .manifest
                    .scope_summary()
                    .into_iter()
                    .map(|(host, mode)| json!({ "host": host, "mode": mode.name() }))
                    .collect::<Vec<_>>()
            );
        }
        view
    });
    let grant = ctx.scope.grant().map(|active| {
        json!({
            "digest": active.digest,
            "ro_origins": active.grant.ro_origins,
            "rw_origins": active.grant.rw_origins,
            "allowed_tools": active.grant.allowed_tools,
            "allowed_actions": active.grant.allowed_actions,
            "plan_digest": active.grant.plan_digest(),
            "plan_steps": active.grant.plan.len(),
            "not_after": show(active.grant.not_after),
        })
    });
    Ok(Output::json(json!({
        "handle": state.handle,
        "flags": state.flags.to_value(),
        "why": {
            "A": state.reasons[0],
            "B": state.reasons[1],
            "C": state.reasons[2],
        },
        "meaning": {
            "A": "untrusted input was read in this session",
            "B": "sensitive context is in play (persistent profile, upstream route, adopted session or private-network target)",
            "C": "a tool that changes pages is enabled",
        },
        "policy": {
            "rule_of_two": ctx.ledger.mode().name(),
            "profile": ctx.cfg.safety.profile,
            "approvals": "a consequential call needs a human approval when A, B and C are all set and the mode is enforce; strict refuses it",
        },
        "all_three": state.flags.all(),
        "calls": state.calls,
        "manifest": manifest,
        "grant": grant,
        "advice": "Flags only turn on within a handle. reset_context starts a fresh handle and context (it needs a human approval once this handle holds untrusted input or sensitive context, and the strict policy refuses it); ask for that, and tell the user, before work that does not need what this session has seen.",
    })))
}

pub(super) async fn reset(ctx: &Arc<Ctx>, call: &Call<'_>) -> ToolResult {
    gate::authorize_reset(ctx, call)?;
    let old = call.handle.clone();
    let fresh = ctx.ledger.reset(call.principal);
    // Element refs and snapshots of the retired context stop resolving: the new context reads
    // the page again before it can act on it.
    ctx.hub.forget_refs().await;
    call.note("retired_handle", json!(old));
    let state = ctx.ledger.status(&fresh);
    Ok(Output::json(json!({
        "handle": fresh,
        "flags": state.map(|s| s.flags.to_value()),
        "retired": true,
        "note": "The previous handle is retired and unusable, and every element ref is invalid: take a new page_snapshot. Start the next task with a fresh context window: what you read before is not forgotten by this call. Calls and plan steps already used still count against the scope grant.",
    })))
}

fn strings(args: &Args, key: &str) -> Vec<String> {
    args.0
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn propose(ctx: &Arc<Ctx>, call: &Call<'_>, args: &Args) -> ToolResult {
    let trusted = ctx.scope.manifest().filter(|m| m.trusted());
    let engagement = trusted
        .map(|m| m.manifest.id.clone())
        .or_else(|| ctx.scope.grant().map(|g| g.grant.engagement.clone()))
        .or_else(|| ctx.cfg.engagement.id.clone())
        .ok_or_else(|| {
            ToolError::not_configured(
                "no engagement id is configured (a signed manifest or engagement.id), so a grant cannot be proposed",
            )
        })?;
    let mut grant = toml::Table::new();
    grant.insert("engagement".into(), toml::Value::String(engagement.clone()));
    grant.insert(
        "principal".into(),
        toml::Value::String(call.principal.to_owned()),
    );
    for key in [
        "ro_origins",
        "rw_origins",
        "allowed_tools",
        "allowed_actions",
    ] {
        grant.insert(
            key.into(),
            toml::Value::Array(
                strings(args, key)
                    .into_iter()
                    .map(toml::Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(not_after) = args.str("not_after") {
        grant.insert(
            "not_after".into(),
            toml::Value::String(not_after.to_owned()),
        );
    }
    let mut root = toml::Table::new();
    root.insert("grant".into(), toml::Value::Table(grant));
    let mut budgets = toml::Table::new();
    for key in ["calls", "time_secs"] {
        if let Some(n) = args.u64(key).and_then(|n| i64::try_from(n).ok()) {
            budgets.insert(key.into(), toml::Value::Integer(n));
        }
    }
    if !budgets.is_empty() {
        root.insert("budgets".into(), toml::Value::Table(budgets));
    }
    if let Some(Value::Array(steps)) = args.0.get("plan") {
        let mut plan = Vec::new();
        for step in steps {
            let mut table = toml::Table::new();
            for key in ["tool", "origin", "action_class"] {
                if let Some(text) = step.get(key).and_then(Value::as_str) {
                    table.insert(key.into(), toml::Value::String(text.to_owned()));
                }
            }
            if let Some(n) = step.get("max_count").and_then(Value::as_i64) {
                table.insert("max_count".into(), toml::Value::Integer(n));
            }
            plan.push(toml::Value::Table(table));
        }
        root.insert("plan".into(), toml::Value::Array(plan));
    }
    let text = toml::to_string(&root).map_err(|e| ToolError::invalid(e.to_string()))?;
    let proposed = Grant::parse(&text).map_err(|e| ToolError::invalid(e.to_string()))?;

    let origins = ctx
        .cfg
        .origins()
        .map_err(|e| ToolError::internal(e.to_string()))?;
    let ceiling = Ceiling {
        engagement: Some(&engagement),
        manifest: trusted.map(|m| &m.manifest),
        origins: &origins,
        grant: ctx.scope.grant().map(|g| &g.grant),
        max_calls: trusted.and_then(|m| m.manifest.limits.max_calls),
        not_after: trusted
            .and_then(|m| m.manifest.not_after)
            .into_iter()
            .chain(ctx.scope.grant().and_then(|g| g.grant.not_after))
            .min(),
    };
    let violations = proposed.violations_against(&ceiling);
    if !violations.is_empty() {
        call.note("proposal", json!("rejected"));
        return Err(ToolError::refused_with(
            "proposal_widens_ceiling",
            "a proposal can only narrow what the operator allows; this one does not",
        )
        .with_detail(json!({ "reason": "proposal_widens_ceiling", "violations": violations })));
    }
    let canonical = proposed
        .to_toml()
        .map_err(|e| ToolError::internal(e.to_string()))?;
    let digest = hex::encode(Sha256::digest(canonical.as_bytes()));
    let dir = ctx.cfg.approvals_dir().join("proposals");
    std::fs::create_dir_all(&dir)
        .map_err(|e| ToolError::internal(format!("cannot create the proposals directory: {e}")))?;
    let file = dir.join(format!("{}.toml", &digest[..16]));
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        options
            .open(&file)
            .and_then(|mut f| f.write_all(canonical.as_bytes()))
            .map_err(|e| ToolError::internal(format!("cannot write the proposal: {e}")))?;
    }
    call.note("proposal", json!(digest));
    let mut summary = proposal_summary(&proposed, &violations);
    summary["digest"] = json!(digest);
    summary["file"] = json!(file.display().to_string());
    summary["reason_given"] = json!(args.str("reason"));
    Ok(Output::json(summary))
}
