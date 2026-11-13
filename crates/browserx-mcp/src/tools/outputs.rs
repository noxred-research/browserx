//! Output schemas of the tools. Every successful result carries `structuredContent` that
//! validates against its tool's schema (the schemas list the stable members; others may be
//! present), and a serialized copy of it as text for clients that do not read structured content.

use serde_json::{Value, json};

fn object(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": true,
    })
}

fn page_meta(extra: Value) -> Value {
    let mut properties = json!({
        "session_id": { "type": "string" },
        "tab_id": { "type": "string" },
        "notice": { "type": ["string", "null"] },
    });
    if let (Some(base), Some(more)) = (properties.as_object_mut(), extra.as_object()) {
        base.extend(more.clone());
    }
    object(properties, &["session_id"])
}

/// The output schema of `tool`.
#[must_use]
pub fn output_schema(tool: &str) -> Value {
    match tool {
        "capabilities" => object(
            json!({
                "server": { "type": "string" },
                "version": { "type": "string" },
                "read_only": { "type": "boolean" },
                "capabilities": { "type": "array", "items": { "type": "string" } },
                "tools": { "type": "array", "items": { "type": "string" } },
                "engagement": { "type": "object" },
                "model_configured": { "type": "boolean" },
                "note": { "type": "string" },
            }),
            &["server", "version", "read_only", "capabilities", "tools"],
        ),
        "health" => object(
            json!({ "healthy": { "type": "boolean" }, "api": { "type": "object" }, "operations": { "type": "object" } }),
            &["healthy", "api", "operations"],
        ),
        "pool_status" => object(
            json!({ "verdict": { "type": "string" }, "reasons": { "type": "array" }, "pool": {} }),
            &["verdict", "reasons"],
        ),
        "assess" => object(
            json!({ "verdict": { "type": "string" }, "overall": { "type": "string" }, "reasons": { "type": "array" }, "checks": { "type": "array" } }),
            &["verdict", "overall", "checks"],
        ),
        "list_sessions" => object(
            json!({ "count": { "type": "integer" }, "sessions": { "type": "array", "items": { "type": "object" } } }),
            &["count", "sessions"],
        ),
        "get_session" | "create_session" | "renew_session" => {
            object(json!({ "session": { "type": "object" } }), &["session"])
        }
        "snapshot_session" => object(json!({ "snapshot": {} }), &["snapshot"]),
        "release_session" => object(
            json!({ "released": { "type": "boolean" }, "session": { "type": "object" } }),
            &["released"],
        ),
        "handoff_session" => object(json!({}), &[]),
        "explain_session" | "explain_error" => {
            object(json!({ "title": { "type": "string" } }), &[])
        }
        "list_launch_profiles" | "list_snapshots" => object(json!({}), &[]),
        "open_page" | "go_back" | "go_forward" => {
            page_meta(json!({ "settled": { "type": "boolean" } }))
        }
        "page_snapshot" => page_meta(json!({
            "refs": { "type": "integer" },
            "lines": { "type": "integer" },
            "truncated": { "type": "boolean" },
            "snapshot_id": { "type": "string" },
        })),
        "find_in_snapshot" => page_meta(json!({
            "matches": { "type": "integer" },
            "snapshot_id": { "type": "string" },
            "truncated": { "type": "boolean" },
        })),
        "page_text" => page_meta(json!({ "truncated": { "type": "boolean" } })),
        "screenshot" => page_meta(json!({
            "width": { "type": "integer" },
            "height": { "type": "integer" },
            "bytes": { "type": "integer" },
            "resource_uri": { "type": "string" },
        })),
        "list_tabs" => object(
            json!({ "session_id": { "type": "string" }, "count": { "type": "integer" } }),
            &["session_id", "count"],
        ),
        "switch_tab" => object(
            json!({ "session_id": { "type": "string" }, "current_tab": { "type": "string" } }),
            &["session_id", "current_tab"],
        ),
        "close_tab" => object(
            json!({ "session_id": { "type": "string" }, "closed": { "type": "string" } }),
            &["session_id", "closed"],
        ),
        "wait_for" => object(
            json!({ "session_id": { "type": "string" }, "satisfied": { "type": "boolean" }, "waited_ms": { "type": "integer" } }),
            &["session_id", "satisfied", "waited_ms"],
        ),
        "network_log" | "console_log" => page_meta(json!({ "count": { "type": "integer" } })),
        "click" | "hover" | "type_text" | "press_key" => page_meta(json!({
            "navigated": { "type": "boolean" },
            "settled": { "type": "boolean" },
        })),
        "select_option" => page_meta(json!({ "navigated": { "type": "boolean" } })),
        "scroll" => object(
            json!({ "session_id": { "type": "string" }, "scroll": {} }),
            &["session_id", "scroll"],
        ),
        "evaluate_js" => page_meta(json!({ "truncated": { "type": "boolean" } })),
        "summarize_page" | "extract_data" => {
            page_meta(json!({ "advisory": { "type": "boolean" } }))
        }
        "diagnose" => object(
            json!({ "verdict": { "type": "string" }, "narrative": { "type": "string" }, "checks": { "type": "array" } }),
            &["verdict", "narrative"],
        ),
        "engagement_status" => object(
            json!({
                "handle": { "type": "string" },
                "flags": { "type": "object", "properties": {
                    "A": { "type": "boolean" }, "B": { "type": "boolean" }, "C": { "type": "boolean" } },
                    "required": ["A", "B", "C"] },
                "policy": { "type": "object" },
                "all_three": { "type": "boolean" },
                "calls": { "type": "integer" },
            }),
            &["handle", "flags", "policy", "all_three"],
        ),
        "reset_context" => object(
            json!({ "handle": { "type": "string" }, "retired": { "type": "boolean" } }),
            &["handle", "retired"],
        ),
        "propose_scope_grant" => object(
            json!({
                "active": { "type": "boolean" },
                "narrows_the_ceiling": { "type": "boolean" },
                "digest": { "type": "string" },
            }),
            &["active", "narrows_the_ceiling", "digest"],
        ),
        _ => object(json!({}), &[]),
    }
}
