//! The MCP server against a real BrowserX server (scheduler, lease store, HTTP API, operations
//! listener) with a fake browser runtime: monitoring, session control, secrets and the audit log.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use browserx_egress::EgressPolicy;
use browserx_pool::testing::FakeRuntime;
use common::{KEY, McpClient, TestServer, all_text, pool_config, start_server};
use serde_json::json;

async fn server() -> TestServer {
    let fake = FakeRuntime::new();
    start_server(Arc::new(fake), pool_config(), EgressPolicy::default()).await
}

const SESSIONS: &str =
    "[mcp]\ncapabilities = [\"sessions\", \"handoff\"]\n[sessions]\nmax_tracked = 2\n";

#[tokio::test]
async fn monitoring_reflects_the_real_server() {
    let mut server = server().await;
    let mut mcp = McpClient::start(server.mcp_config(""));
    let init = mcp.initialize().await;
    assert_eq!(init["serverInfo"]["name"], "browserx-mcp");

    let health = mcp.ok("health", json!({})).await;
    assert_eq!(health["healthy"], true);
    assert_eq!(health["api"]["key_accepted"], true);
    assert_eq!(health["operations"]["ready"], true);

    let pool = mcp.ok("pool_status", json!({})).await;
    assert_eq!(pool["verdict"], "ok", "{pool}");
    assert_eq!(pool["pool"]["queue_depth"], 0);

    let assessed = mcp.ok("assess", json!({})).await;
    assert_eq!(assessed["overall"], "pass", "{assessed}");
    assert_eq!(assessed["checks"].as_array().unwrap().len(), 6);

    let profiles = mcp.ok("list_launch_profiles", json!({})).await;
    assert_eq!(profiles["default"], "default");

    // Read-only: no session tools exist at all.
    let reply = mcp
        .request(
            "tools/call",
            json!({"name": "create_session", "arguments": {}}),
        )
        .await;
    assert_eq!(reply["error"]["message"], "Unknown tool: create_session");
    mcp.finish().await;
    server.stop().await;
}

#[tokio::test]
async fn session_lifecycle_keeps_secrets_inside_the_server() {
    let mut server = server().await;
    let mut mcp = McpClient::start(server.mcp_config(SESSIONS));
    mcp.initialize().await;

    let created = mcp
        .tool(
            "create_session",
            json!({"persistence": "snapshot", "labels": {"purpose": "test"}, "ttl_secs": 600}),
        )
        .await;
    assert_eq!(created["isError"], false, "{created}");
    let id = created["structuredContent"]["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let everything = all_text(&created);
    assert!(
        !everything.contains("bxt_")
            && !everything.contains("/cdp/")
            && !everything.contains("ws://"),
        "{everything}"
    );
    assert_eq!(
        created["structuredContent"]["session"]["labels"]["mcp"],
        "true"
    );
    assert_eq!(
        created["structuredContent"]["session"]["persistence"],
        "snapshot"
    );

    let listed = mcp.ok("list_sessions", json!({})).await;
    assert_eq!(listed["count"], 1);
    assert_eq!(listed["sessions"][0]["controlled"], true);
    assert_eq!(listed["sessions"][0]["mcp"], true);

    let got = mcp.ok("get_session", json!({"session_id": id})).await;
    assert_eq!(got["session"]["status"], "idle");
    let explained = mcp.ok("explain_session", json!({"session_id": id})).await;
    assert!(
        explained["summary"]
            .as_str()
            .unwrap()
            .contains("Session is idle")
    );
    assert_eq!(explained["persistence"]["mode"], "snapshot");

    let renewed = mcp
        .ok("renew_session", json!({"session_id": id, "ttl_secs": 900}))
        .await;
    assert_eq!(renewed["session"]["session_id"], id);
    let snapshot = mcp.ok("snapshot_session", json!({"session_id": id})).await;
    assert_eq!(snapshot["snapshot"]["version"], 1);
    let snapshots = mcp
        .ok(
            "list_snapshots",
            json!({"profile_id": got["session"]["profile_id"]}),
        )
        .await;
    assert!(snapshots["count"].as_u64().unwrap() >= 1);

    // Handoff rotates the token the server holds; control continues.
    let before = mcp.ok("get_session", json!({"session_id": id})).await["session"]["generation"]
        .as_u64()
        .unwrap();
    let denied = mcp
        .fails(
            "handoff_session",
            json!({"session_id": id, "confirm": false}),
        )
        .await;
    assert!(denied.contains("confirm=true"));
    let handed = mcp
        .tool(
            "handoff_session",
            json!({"session_id": id, "confirm": true}),
        )
        .await;
    assert_eq!(handed["structuredContent"]["rotated"], true, "{handed}");
    assert!(!all_text(&handed).contains("bxt_"));
    let after = mcp.ok("get_session", json!({"session_id": id})).await["session"]["generation"]
        .as_u64()
        .unwrap();
    assert!(after > before);
    mcp.ok("renew_session", json!({"session_id": id})).await;

    // The server controls at most `max_tracked` sessions.
    mcp.ok("create_session", json!({})).await;
    let limit = mcp.fails("create_session", json!({})).await;
    assert!(limit.contains("already controls 2 sessions"), "{limit}");

    let released = mcp
        .ok(
            "release_session",
            json!({"session_id": id, "confirm": true}),
        )
        .await;
    assert_eq!(released["released"], true);
    let gone = mcp.ok("get_session", json!({"session_id": id})).await;
    assert!(matches!(
        gone["session"]["status"].as_str(),
        Some("closed" | "draining")
    ));
    let renew_after = mcp.fails("renew_session", json!({"session_id": id})).await;
    assert!(renew_after.contains("not controlled by this server"));

    // Every call is in the audit log, which verifies and holds no secret.
    let log_path = mcp.ctx.cfg.audit.path.clone();
    mcp.finish().await;
    let report = browserx_mcp::audit::verify(&log_path).unwrap();
    assert_eq!(report.broken, None);
    assert!(report.entries >= 20, "{} entries", report.entries);
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(!log.contains("bxt_") && !log.contains(KEY));
    assert!(log.contains("\"tool\":\"handoff_session\"") && log.contains("mcp-test"));
    server.stop().await;
}

#[tokio::test]
async fn endpoints_are_revealed_only_when_the_operator_allows_it() {
    let mut server = server().await;
    let mut hidden = McpClient::start(server.mcp_config(SESSIONS));
    hidden.initialize().await;
    let result = hidden.tool("create_session", json!({})).await;
    assert!(!all_text(&result).contains("bxt_"));
    hidden.finish().await;

    let revealing = SESSIONS.replace("[mcp]\n", "[mcp]\nreveal_endpoints = true\n");
    let mut shown = McpClient::start(server.mcp_config(&revealing));
    shown.initialize().await;
    let result = shown.tool("create_session", json!({})).await;
    let text = all_text(&result);
    assert!(
        text.contains("bxt_") && text.contains("/cdp/ses_"),
        "{text}"
    );
    // The structured part, which a client may store or log, still holds no secret.
    assert!(!result["structuredContent"].to_string().contains("bxt_"));
    shown.finish().await;
    server.stop().await;
}

#[tokio::test]
async fn a_session_the_server_did_not_create_is_not_released_here() {
    let mut server = server().await;
    let (lease, _token) = server
        .pool
        .create("mcp", browserx_core::SessionSpec::default())
        .await
        .unwrap();
    let id = lease.session_id.prefixed();
    let mut mcp = McpClient::start(server.mcp_config(SESSIONS));
    mcp.initialize().await;
    let listed = mcp.ok("list_sessions", json!({})).await;
    assert_eq!(listed["sessions"][0]["controlled"], false);
    let text = mcp
        .fails(
            "release_session",
            json!({"session_id": id, "confirm": true}),
        )
        .await;
    assert!(text.contains("was not created by an MCP server"), "{text}");
    let text = mcp.fails("renew_session", json!({"session_id": id})).await;
    assert!(text.contains("not controlled by this server"));
    mcp.finish().await;
    server.stop().await;
}

#[tokio::test]
async fn sessions_that_ended_on_their_own_free_their_slot() {
    let mut server = server().await;
    let mut mcp = McpClient::start(
        server.mcp_config(&SESSIONS.replace("max_tracked = 2", "max_tracked = 1")),
    );
    mcp.initialize().await;
    let first = mcp.ok("create_session", json!({})).await["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        mcp.fails("create_session", json!({}))
            .await
            .contains("already controls 1 sessions")
    );

    // The worker releases it behind this server's back (an expiry would look the same).
    server
        .pool
        .release(
            "mcp",
            browserx_core::SessionId::parse(&first).unwrap(),
            None,
            None,
        )
        .await
        .unwrap();
    let second = mcp.ok("create_session", json!({})).await["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(first, second);
    let controlled = mcp.ok("capabilities", json!({})).await["controlled_sessions"].clone();
    assert_eq!(controlled, json!([second]));
    mcp.finish().await;
    server.stop().await;
}
