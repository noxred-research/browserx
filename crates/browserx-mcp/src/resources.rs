//! MCP resources: the bundled documentation and live session views.

use serde_json::{Value, json};

use crate::ctx::Ctx;

struct Doc {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    text: &'static str,
}

const DOCS: [Doc; 7] = [
    Doc {
        name: "sessions",
        title: "Sessions and leases",
        description: "The lease record, lifecycle states, generations, tokens, time limits and admission.",
        text: include_str!("../../../docs/design/sessions-and-leases.md"),
    },
    Doc {
        name: "persistence",
        title: "Persistence",
        description: "Ephemeral, snapshot and profile persistence: what each keeps and what it cannot keep.",
        text: include_str!("../../../docs/design/persistence.md"),
    },
    Doc {
        name: "recovery",
        title: "Recovery",
        description: "The four attach outcomes, health monitoring, relaunch and startup reconciliation.",
        text: include_str!("../../../docs/design/recovery.md"),
    },
    Doc {
        name: "handoff",
        title: "Handoff",
        description: "Moving control of a live session to another client without losing the browser.",
        text: include_str!("../../../docs/design/handoff.md"),
    },
    Doc {
        name: "security",
        title: "Isolation and security",
        description: "Dedicated and shared isolation, the scoped relay, credentials, threat model and limits.",
        text: include_str!("../../../docs/design/isolation-and-security.md"),
    },
    Doc {
        name: "egress",
        title: "Egress",
        description: "The loopback forwarder, destination policy, upstream proxies and sticky exits.",
        text: include_str!("../../../docs/design/egress.md"),
    },
    Doc {
        name: "mcp",
        title: "MCP server guide",
        description: "Setup, configuration, tools, resources, prompts, safety model and audit log of the MCP server.",
        text: include_str!("../../../docs/guides/mcp.md"),
    },
];

const DOCS_PREFIX: &str = "browserx://docs/";
const SESSIONS_PREFIX: &str = "browserx://sessions/";

/// Why a read failed.
pub enum ReadError {
    /// No such resource.
    NotFound,
    /// The resource exists but could not be produced.
    Failed(String),
}

/// The `resources/list` entries: the bundled pages and the sessions this server controls.
#[must_use]
pub fn list(ctx: &Ctx) -> Vec<Value> {
    let sessions = ctx.registry.ids().into_iter().map(|id| {
        json!({
            "uri": format!("{SESSIONS_PREFIX}{id}"),
            "name": id,
            "title": "Session lease view",
            "description": "A session this server controls.",
            "mimeType": "application/json",
        })
    });
    DOCS.iter()
        .map(|doc| {
            json!({
                "uri": format!("{DOCS_PREFIX}{}", doc.name),
                "name": doc.name,
                "title": doc.title,
                "description": doc.description,
                "mimeType": "text/markdown",
                "size": doc.text.len(),
            })
        })
        .chain(sessions)
        .collect()
}

/// The `resources/templates/list` entries.
#[must_use]
pub fn templates() -> Vec<Value> {
    vec![json!({
        "uriTemplate": "browserx://sessions/{id}",
        "name": "session",
        "title": "Session lease view",
        "description": "The lease view of one session (never its token or CDP URL).",
        "mimeType": "application/json",
    })]
}

/// Reads a resource.
///
/// # Errors
/// [`ReadError::NotFound`] for an unknown URI, [`ReadError::Failed`] when the session cannot be
/// fetched.
pub async fn read(ctx: &Ctx, uri: &str) -> Result<Vec<Value>, ReadError> {
    if let Some(name) = uri.strip_prefix(DOCS_PREFIX) {
        let doc = DOCS
            .iter()
            .find(|d| d.name == name)
            .ok_or(ReadError::NotFound)?;
        return Ok(vec![
            json!({ "uri": uri, "mimeType": "text/markdown", "text": doc.text }),
        ]);
    }
    if let Some(raw) = uri.strip_prefix(SESSIONS_PREFIX) {
        let id = browserx_core::SessionId::parse(raw).map_err(|_| ReadError::NotFound)?;
        let mut view = ctx
            .backend
            .get_session(&id.prefixed())
            .await
            .map_err(|e| match e {
                crate::backend::BackendError::Api { status: 404, .. } => ReadError::NotFound,
                other => ReadError::Failed(other.to_string()),
            })?;
        view["controlled"] = json!(ctx.registry.get(&id.prefixed()).is_some());
        let redacted = ctx.redactor.redacted(&view);
        return Ok(vec![json!({
            "uri": uri,
            "mimeType": "application/json",
            "text": serde_json::to_string_pretty(&redacted).unwrap_or_default(),
        })]);
    }
    Err(ReadError::NotFound)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_documented_page_is_bundled_and_listed() {
        let (ctx, _dir) = crate::testing::ctx_from("");
        let listed = list(&ctx);
        assert_eq!(listed.len(), 7);
        for doc in &DOCS {
            assert!(!doc.text.trim().is_empty(), "{} is empty", doc.name);
        }
        let names: Vec<&str> = listed.iter().filter_map(|r| r["name"].as_str()).collect();
        assert_eq!(
            names,
            [
                "sessions",
                "persistence",
                "recovery",
                "handoff",
                "security",
                "egress",
                "mcp"
            ]
        );
        assert_eq!(templates()[0]["uriTemplate"], "browserx://sessions/{id}");
    }
}
