//! The protocol conformance vector pack: JSON cases under `tests/vectors/protocol`, run over a
//! real HTTP socket for both protocol eras. The vectors are plain data so other implementations
//! can run the same pack.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use browserx_mcp::http::{HttpOptions, parse_digest, router, serve};
use browserx_mcp::{Config, Ctx, Server, schema};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const TOKEN: &str = "bxm_synthetic_conformance_token";

struct Fixture {
    base: String,
    cancel: CancellationToken,
    ctx: Arc<Ctx>,
    server: Arc<Server>,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("key"), "bxk_synthetic\n").unwrap();
    let text = "[server]\nurl = \"http://127.0.0.1:1\"\napi_key_file = \"key\"\n[audit]\npath = \"audit.jsonl\"\n\
                [mcp]\ncapabilities = [\"browse\", \"interact\", \"evaluate\"]\n[browse]\nrequire_scope = false\n";
    let ctx = Ctx::build(Config::parse(text, dir.path()).unwrap()).unwrap();
    let server = Arc::new(Server::new(Arc::clone(&ctx)));
    let digest = hex::encode(Sha256::digest(TOKEN.as_bytes()));
    let options = HttpOptions {
        path: "/mcp".into(),
        token_sha256: parse_digest(&digest).unwrap(),
        allowed_origins: vec![],
        loopback_bind: true,
        max_body_bytes: 64 * 1024,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let cancel = CancellationToken::new();
    tokio::spawn(serve(
        listener,
        router(Arc::clone(&server), options),
        cancel.clone(),
    ));
    Fixture {
        base,
        cancel,
        ctx,
        server,
        _dir: dir,
    }
}

async fn post(f: &Fixture, headers: &Value, body: &Value) -> (u16, Value) {
    let mut request = reqwest::Client::new()
        .post(format!("{}/mcp", f.base))
        .bearer_auth(TOKEN)
        .header("content-type", "application/json")
        .header("accept", "application/json");
    for (name, value) in headers.as_object().unwrap() {
        request = request.header(name.as_str(), value.as_str().unwrap());
    }
    let response = request.body(body.to_string()).send().await.unwrap();
    let status = response.status().as_u16();
    let value = response.json::<Value>().await.unwrap_or(Value::Null);
    (status, value)
}

/// Whether every member of `expected` is in `actual` (objects are subsets, everything else is
/// equal).
fn subset(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => e
            .iter()
            .all(|(k, v)| a.get(k).is_some_and(|got| subset(v, got))),
        _ => expected == actual,
    }
}

fn at<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(value, |v, key| v.get(key))
}

fn check(f: &Fixture, case: &Value, status: u16, reply: &Value, tools: Option<&Value>) {
    let id = case["id"].as_str().unwrap();
    let expect = &case["expect"];
    assert_eq!(
        status,
        u16::try_from(expect["status"].as_u64().unwrap()).unwrap(),
        "{id}: {reply}"
    );
    if let Some(code) = expect.get("error_code") {
        assert_eq!(&reply["error"]["code"], code, "{id}: {reply}");
    }
    if let Some(data) = expect.get("error_data") {
        assert!(subset(data, &reply["error"]["data"]), "{id}: {reply}");
    }
    if let Some(result) = expect.get("result") {
        assert!(subset(result, &reply["result"]), "{id}: {reply}");
    }
    for path in expect["absent"].as_array().into_iter().flatten() {
        assert!(
            at(reply, path.as_str().unwrap()).is_none(),
            "{id}: {path} present in {reply}"
        );
    }
    if let Some(tools) = tools {
        let listed = tools.as_array().unwrap();
        let names: Vec<&str> = listed.iter().map(|t| t["name"].as_str().unwrap()).collect();
        if expect["tools_sorted"] == json!(true) {
            let mut sorted = names.clone();
            sorted.sort_unstable();
            assert_eq!(names, sorted, "{id}: tools are listed in a stable order");
        }
        for key in expect["tools_have"].as_array().into_iter().flatten() {
            for tool in listed {
                assert!(
                    tool.get(key.as_str().unwrap()).is_some(),
                    "{id}: {} lacks {key}",
                    tool["name"]
                );
            }
        }
        if expect["no_header_mirrors"] == json!(true) {
            // No tool parameter is mirrored into a header, so a secret-typed one cannot be.
            for tool in listed {
                for (name, property) in tool["inputSchema"]["properties"].as_object().unwrap() {
                    assert!(
                        property.get("x-mcp-header").is_none(),
                        "{}: {name}",
                        tool["name"]
                    );
                }
            }
        }
    }
    if let Some(tool) = expect.get("structured_matches_output_schema") {
        let tool = tool.as_str().unwrap();
        let listed = f
            .ctx
            .tools
            .iter()
            .find(|t| t.name == tool)
            .unwrap()
            .descriptor();
        let structured = reply["result"]["structuredContent"].clone();
        schema::check(&listed["outputSchema"], structured.clone())
            .unwrap_or_else(|issues| panic!("{id}: {issues:?} in {structured}"));
        for key in listed["outputSchema"]["required"].as_array().unwrap() {
            assert!(
                structured.get(key.as_str().unwrap()).is_some(),
                "{id}: {key} missing"
            );
        }
    }
    if expect["text_copy"] == json!(true) {
        let text = reply["result"]["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            parsed, reply["result"]["structuredContent"],
            "{id}: the text copy matches"
        );
    }
}

fn load(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/tests/vectors/protocol/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let pack: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    pack["cases"].as_array().unwrap().clone()
}

async fn run_pack(name: &str) -> usize {
    let f = fixture().await;
    let cases = load(name);
    for case in &cases {
        let (status, reply) = post(&f, &case["headers"], &case["request"]).await;
        let tools = case["request"]["method"]
            .as_str()
            .filter(|m| *m == "tools/list")
            .map(|_| reply["result"]["tools"].clone());
        check(&f, case, status, &reply, tools.as_ref());
    }
    f.cancel.cancel();
    cases.len()
}

#[tokio::test]
async fn the_legacy_vectors_pass() {
    assert!(run_pack("legacy.json").await >= 8);
}

#[tokio::test]
async fn the_modern_vectors_pass() {
    assert!(run_pack("modern.json").await >= 14);
}

#[tokio::test]
async fn every_successful_offline_result_validates_against_its_output_schema() {
    let f = fixture().await;
    let headers = json!({"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call"});
    for (tool, arguments) in [
        ("capabilities", json!({})),
        ("explain_error", json!({"code": "stale_generation"})),
        ("engagement_status", json!({})),
        ("reset_context", json!({})),
    ] {
        let mut h = headers.clone();
        h["Mcp-Name"] = json!(tool);
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": tool, "arguments": arguments,
            "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}}});
        let (status, reply) = post(&f, &h, &body).await;
        assert_eq!(status, 200);
        assert_eq!(reply["result"]["isError"], false, "{tool}: {reply}");
        let descriptor = f
            .ctx
            .tools
            .iter()
            .find(|t| t.name == tool)
            .unwrap()
            .descriptor();
        schema::check(
            &descriptor["outputSchema"],
            reply["result"]["structuredContent"].clone(),
        )
        .unwrap_or_else(|issues| panic!("{tool}: {issues:?}"));
        for key in descriptor["outputSchema"]["required"].as_array().unwrap() {
            assert!(
                reply["result"]["structuredContent"]
                    .get(key.as_str().unwrap())
                    .is_some(),
                "{tool}: {key}"
            );
        }
    }
    f.cancel.cancel();
}

#[tokio::test]
async fn annotations_are_truthful_and_names_are_valid() {
    let f = fixture().await;
    let read_only = [
        "capabilities",
        "health",
        "pool_status",
        "assess",
        "list_sessions",
        "get_session",
        "page_snapshot",
        "find_in_snapshot",
        "page_text",
        "screenshot",
        "list_tabs",
        "wait_for",
        "network_log",
        "console_log",
        "engagement_status",
        "explain_error",
    ];
    let state_changing = [
        "click",
        "type_text",
        "press_key",
        "select_option",
        "evaluate_js",
    ];
    for tool in &f.ctx.tools {
        let d = tool.descriptor();
        let name = d["name"].as_str().unwrap();
        assert!(
            name.len() <= 128
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)),
            "{name}"
        );
        let a = &d["annotations"];
        if read_only.contains(&name) {
            assert_eq!(a["readOnlyHint"], true, "{name}");
            assert_eq!(a["idempotentHint"], true, "{name}");
        }
        if state_changing.contains(&name) {
            assert_eq!(a["readOnlyHint"], false, "{name}");
            assert_eq!(a["destructiveHint"], true, "{name}");
            assert_eq!(a["openWorldHint"], true, "{name}");
        }
        for key in [
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ] {
            assert!(a[key].is_boolean(), "{name}: {key}");
        }
    }
    // The server never decides anything from an annotation: a hostile client sending its own
    // hints changes nothing, because tools take no such arguments.
    let _ = &f.server;
    f.cancel.cancel();
}

#[tokio::test]
async fn a_trace_context_is_accepted_and_recorded() {
    let f = fixture().await;
    let headers = json!({"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "explain_error"});
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "explain_error", "arguments": {"code": "conflict"},
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {},
                  "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}}});
    let (status, _) = post(&f, &headers, &body).await;
    assert_eq!(status, 200);
    let log = std::fs::read_to_string(&f.ctx.cfg.audit.path).unwrap();
    assert!(log.contains("0af7651916cd43dd8448eb211c80319c"), "{log}");
    f.cancel.cancel();
}
