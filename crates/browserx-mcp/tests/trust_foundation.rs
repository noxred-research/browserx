//! The trust foundation end to end with a real Chromium: the signed engagement manifest, human
//! approvals (multi round-trip and out of band), the session ledger and the scope grant.
//! Skipped (with a printed note) when no Chromium is found.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::sync::Arc;

use browserx_egress::EgressPolicy;
use browserx_mcp::approvals;
use browserx_mcp::crypto::OperatorKeys;
use browserx_mcp::server::Transport;
use browserx_mcp::{Ctx, Server, grants, manifest};
use common::site::{Site, chromium_runtime, serve};
use common::{McpClient, TestServer, pool_config, start_server};
use serde_json::{Value, json};

const OP_KEY: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn write_keys(dir: &Path) -> OperatorKeys {
    std::fs::write(dir.join("operator.keys"), format!("op = {OP_KEY}\n")).unwrap();
    OperatorKeys::load(&dir.join("operator.keys")).unwrap()
}

struct Lab {
    server: TestServer,
    mcp: McpClient,
    keys: OperatorKeys,
    id: String,
}

/// Starts a BrowserX server and an MCP client; `config` builds the MCP configuration text from
/// the server's directory and the operator keys.
async fn lab(scratch: &Path, config: impl FnOnce(&Path, &OperatorKeys) -> String) -> Option<Lab> {
    let runtime = chromium_runtime(scratch)?;
    let server = start_server(
        Arc::new(runtime),
        pool_config(),
        EgressPolicy {
            block_private: true,
            allow_cidrs: vec!["127.0.0.0/8".into()],
        },
    )
    .await;
    let keys = write_keys(server.dir.path());
    let text = config(server.dir.path(), &keys);
    let mut mcp = McpClient::start(server.mcp_config(&text));
    mcp.initialize().await;
    let created = mcp
        .tool("create_session", json!({"launch_profile": "default"}))
        .await;
    assert_eq!(created["isError"], false, "{created}");
    let id = created["structuredContent"]["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    Some(Lab {
        server,
        mcp,
        keys,
        id,
    })
}

impl Lab {
    async fn open(&mut self, url: &str) -> Value {
        self.mcp
            .tool("open_page", json!({"session_id": self.id, "url": url}))
            .await
    }

    async fn snapshot(&mut self) -> String {
        let result = self
            .mcp
            .tool("page_snapshot", json!({"session_id": self.id}))
            .await;
        assert_eq!(result["isError"], false, "{result}");
        common::all_text(&result)
    }

    fn audit(&self) -> String {
        std::fs::read_to_string(&self.mcp.ctx.cfg.audit.path).unwrap()
    }

    async fn stop(mut self) {
        self.mcp.finish().await;
        self.server.stop().await;
    }
}

fn ref_of(snapshot: &str, needle: &str) -> String {
    let line = snapshot
        .lines()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no line with {needle:?} in\n{snapshot}"));
    let start = line.find("[e").unwrap() + 1;
    let end = line[start..].find(']').unwrap() + start;
    line[start..end].to_owned()
}

fn reason(result: &Value) -> Option<String> {
    result["structuredContent"]["error"]["detail"]["reason"]
        .as_str()
        .map(str::to_owned)
}

fn kind(result: &Value) -> Option<String> {
    result["structuredContent"]["error"]["kind"]
        .as_str()
        .map(str::to_owned)
}

fn modern(elicitation: bool) -> Value {
    let caps = if elicitation {
        json!({"elicitation": {}})
    } else {
        json!({})
    };
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": caps,
        "io.modelcontextprotocol/clientInfo": {"name": "trust-test", "version": "1"},
    })
}

async fn rpc_as(server: &Server, principal: Option<&str>, method: &str, params: Value) -> Value {
    server
        .handle(
            method,
            Some(params),
            &Transport {
                name: "stdio",
                remote: None,
                principal: principal.map(str::to_owned),
            },
        )
        .await
        .unwrap()
}

fn page(body: &str) -> String {
    body.to_owned()
}

#[tokio::test]
async fn the_signed_manifest_confines_hosts_and_protects_requests() {
    let scratch = tempfile::tempdir().unwrap();
    let attack = serve(vec![
        (
            "/",
            page(
                "<main><h1>App</h1><a href=\"/account/delete?id=1\">Remove me</a>\
                 <form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form></main>",
            ),
        ),
        ("/logout", String::new()),
        ("/account/delete", String::new()),
    ])
    .await;
    let visit = serve(vec![(
        "/",
        page(
            "<main><h1>Docs</h1><form method=\"post\" action=\"/save\">\
             <input type=\"text\" name=\"q\" aria-label=\"Note\"><button type=\"submit\">Save</button></form></main>",
        ),
    ), ("/save", String::new())])
    .await;
    let Some(mut lab) = lab(scratch.path(), |dir, keys| {
        let text = format!(
            "[engagement]\nid = \"eng-test\"\noperator = \"alice\"\nauthorization_note = \"ticket 42\"\n\
             not_after = \"2099-01-01T00:00:00Z\"\n\
             [[scope]]\nhost = \"127.0.0.1:{}\"\nmode = \"attack\"\n\
             [[scope]]\nhost = \"127.0.0.1:{}\"\nmode = \"visit\"\n\
             [[protected]]\npattern = \"POST */logout\"\nmode = \"blocked\"\n\
             [[protected]]\npattern = \"* /account/delete*\"\nmode = \"blocked\"\n\
             [impact]\nlevel = \"demonstrate\"\n",
            attack.port, visit.port
        );
        std::fs::write(dir.join("engagement.toml"), &text).unwrap();
        std::fs::write(
            dir.join("engagement.toml.sig"),
            manifest::sign(keys, "op", text.as_bytes()).unwrap(),
        )
        .unwrap();
        "[operator]\nkeys_file = \"operator.keys\"\n[manifest]\npath = \"engagement.toml\"\n\
         [mcp]\ncapabilities = [\"sessions\", \"browse\", \"interact\"]\n\
         [safety]\nprofile = \"authorized_security_test\"\n[safety.rule_of_two]\nmode = \"off\"\n"
            .to_owned()
    })
    .await
    else {
        return;
    };

    // A visit-only host loads and reads, but refuses form submission.
    let opened = lab.open(&format!("{}/", visit.base)).await;
    assert_eq!(opened["isError"], false, "{opened}");
    let snapshot = lab.snapshot().await;
    let save = ref_of(&snapshot, "button \"Save\"");
    let refused = lab
        .mcp
        .tool("click", json!({"session_id": lab.id, "ref": save}))
        .await;
    assert_eq!(refused["isError"], true, "{refused}");
    assert_eq!(reason(&refused).as_deref(), Some("visit_only"), "{refused}");
    assert_eq!(visit.count("POST"), 0);

    // A protected URL is refused with the shared reason code, before the browser is sent.
    let refused = lab
        .open(&format!("{}/account/delete?id=1", attack.base))
        .await;
    assert_eq!(
        reason(&refused).as_deref(),
        Some("blocked_protected"),
        "{refused}"
    );
    assert_eq!(attack.count("/account/delete"), 0);

    // A protected submission is refused whatever the class says.
    lab.open(&format!("{}/", attack.base)).await;
    let snapshot = lab.snapshot().await;
    let out = ref_of(&snapshot, "button \"Sign out\"");
    let refused = lab
        .mcp
        .tool("click", json!({"session_id": lab.id, "ref": out}))
        .await;
    assert_eq!(
        reason(&refused).as_deref(),
        Some("blocked_protected"),
        "{refused}"
    );
    assert_eq!(attack.count("POST"), 0);

    // The engagement id and the manifest digest are in every audit entry.
    let audit = lab.audit();
    assert!(audit.contains("\"engagement\":\"eng-test\""));
    assert!(audit.contains("\"manifest_digest\""));
    assert!(audit.contains("\"reason\":\"blocked_protected\""));
    assert!(audit.contains("\"reason\":\"visit_only\""));
    let report = browserx_mcp::audit::verify(&lab.mcp.ctx.cfg.audit.path).unwrap();
    assert_eq!(report.broken, None);
    lab.stop().await;
}

fn plain_ctx(dir: &Path, extra: &str) -> Arc<Ctx> {
    std::fs::write(dir.join("key"), "bxk_synthetic\n").unwrap();
    let text = format!(
        "[server]\nurl = \"http://127.0.0.1:1\"\napi_key_file = \"key\"\n[audit]\npath = \"audit.jsonl\"\n{extra}"
    );
    Ctx::build(browserx_mcp::Config::parse(&text, dir).unwrap()).unwrap()
}

async fn listed(server: &Server) -> Vec<String> {
    let result = rpc_as(server, None, "tools/list", json!({})).await;
    result["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn an_unsigned_or_expired_manifest_unlists_the_tools_that_change_pages() {
    let manifest_text = |not_after: &str| {
        format!(
            "[engagement]\nid = \"eng-1\"\noperator = \"alice\"\nauthorization_note = \"n\"\n\
             not_after = \"{not_after}\"\n[[scope]]\nhost = \"app.example.test\"\nmode = \"attack\"\n"
        )
    };
    let base = "[operator]\nkeys_file = \"operator.keys\"\n[manifest]\npath = \"engagement.toml\"\n\
                [mcp]\ncapabilities = [\"browse\", \"interact\", \"evaluate\"]\n";
    for (label, not_after, signed, expect_mutation) in [
        ("signed and in force", "2099-01-01T00:00:00Z", true, true),
        ("unsigned", "2099-01-01T00:00:00Z", false, false),
        ("signed but expired", "2000-01-02T00:00:00Z", true, false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let keys = write_keys(dir.path());
        let text = manifest_text(not_after);
        std::fs::write(dir.path().join("engagement.toml"), &text).unwrap();
        if signed {
            std::fs::write(
                dir.path().join("engagement.toml.sig"),
                manifest::sign(&keys, "op", text.as_bytes()).unwrap(),
            )
            .unwrap();
        }
        let ctx = plain_ctx(dir.path(), base);
        let server = Server::new(Arc::clone(&ctx));
        let names = listed(&server).await;
        for tool in ["click", "type_text", "evaluate_js"] {
            assert_eq!(
                names.iter().any(|n| n == tool),
                expect_mutation,
                "{label}: {tool}"
            );
        }
        assert!(names.iter().any(|n| n == "page_snapshot"), "{label}");
        let call = rpc_as(
            &server,
            None,
            "tools/call",
            json!({"name": "click", "arguments": {"session_id": "ses_00000000000000000000000000000001", "ref": "e1"}}),
        )
        .await;
        let _ = call;
        if !expect_mutation {
            // Calling a mutation tool anyway is refused with the shared reason code.
            let refused = rpc_as(
                &server,
                None,
                "tools/call",
                json!({"name": "open_page", "arguments": {"session_id": "ses_00000000000000000000000000000001", "url": "https://app.example.test/"}}),
            )
            .await;
            if not_after.starts_with("2000") {
                assert_eq!(
                    reason(&refused).as_deref(),
                    Some("window_closed"),
                    "{refused}"
                );
            }
        }
    }

    // A tampered not_after no longer verifies.
    let dir = tempfile::tempdir().unwrap();
    let keys = write_keys(dir.path());
    let text = manifest_text("2000-01-02T00:00:00Z");
    let signature = manifest::sign(&keys, "op", text.as_bytes()).unwrap();
    std::fs::write(
        dir.path().join("engagement.toml"),
        text.replace("2000", "2099"),
    )
    .unwrap();
    std::fs::write(dir.path().join("engagement.toml.sig"), signature).unwrap();
    let loaded = manifest::Loaded::load(
        &dir.path().join("engagement.toml"),
        &dir.path().join("engagement.toml.sig"),
        &keys,
    )
    .unwrap();
    assert!(!loaded.trusted());
}

struct Approval {
    site: Site,
}

fn approval_site_pages() -> Vec<(&'static str, String)> {
    vec![
        (
            "/",
            page(
                "<main><h1>Account</h1>\
                 <form method=\"post\" action=\"/delete\"><button type=\"submit\">Delete account</button></form>\
                 <input type=\"password\" aria-label=\"Password\"></main>",
            ),
        ),
        ("/delete", String::new()),
    ]
}

#[tokio::test]
async fn approvals_run_an_action_exactly_once_over_both_routes() {
    let scratch = tempfile::tempdir().unwrap();
    let Approval { site } = Approval {
        site: serve(approval_site_pages()).await,
    };
    let origin = site.base.clone();
    let Some(mut lab) = lab(scratch.path(), |_, _| {
        format!(
            "[operator]\nkeys_file = \"operator.keys\"\n[mcp]\ncapabilities = [\"sessions\", \"browse\", \"interact\"]\n\
             [browse]\nallowed_origins = [\"{origin}\"]\n\
             [engagement]\nid = \"E\"\noperator = \"alice\"\nauthorization_note = \"n\"\n\
             [safety]\nprofile = \"test_environment\"\n[safety.rule_of_two]\nmode = \"off\"\n"
        )
    })
    .await
    else {
        return;
    };
    let server = Server::new(Arc::clone(&lab.mcp.ctx));
    lab.open(&format!("{}/", site.base)).await;
    let snapshot = lab.snapshot().await;
    let password = ref_of(&snapshot, "textbox \"Password\"");
    let delete = ref_of(&snapshot, "button \"Delete account\"");

    // Multi round trip: a client that declared elicitation gets an elicitation form.
    let type_args =
        json!({"session_id": lab.id, "ref": password, "text": "synthetic-secret-not-real"});
    let call = |extra: Value| {
        let mut params = json!({
            "name": "type_text",
            "arguments": type_args.clone(),
            "_meta": modern(true),
        });
        for (k, v) in extra.as_object().unwrap() {
            params[k] = v.clone();
        }
        params
    };
    let first = rpc_as(&server, None, "tools/call", call(json!({}))).await;
    assert_eq!(first["resultType"], "input_required", "{first}");
    assert_eq!(
        first["inputRequests"]["approval"]["method"],
        "elicitation/create"
    );
    let state = first["requestState"].as_str().unwrap().to_owned();
    let accept = json!({"approval": {"action": "accept", "content": {"approve": true}}});
    let executed = |lab: &Lab| lab.audit().matches("\"tool\":\"type_text\"").count();
    let ok_results = |lab: &Lab| {
        lab.audit()
            .lines()
            .filter(|l| l.contains("\"tool\":\"type_text\"") && l.contains("\"outcome\":\"ok\""))
            .count()
    };
    assert_eq!(
        ok_results(&lab),
        0,
        "nothing ran yet ({} entries)",
        executed(&lab)
    );

    // Tampered state: refused.
    let mut bytes = state.clone().into_bytes();
    let at = bytes.len() / 2;
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();
    let refused = rpc_as(
        &server,
        None,
        "tools/call",
        call(json!({"requestState": tampered, "inputResponses": accept})),
    )
    .await;
    assert_eq!(
        reason(&refused).as_deref(),
        Some("approval_invalid"),
        "{refused}"
    );
    // Another principal: refused.
    let refused = rpc_as(
        &server,
        Some("http:someone-else"),
        "tools/call",
        call(json!({"requestState": state, "inputResponses": accept})),
    )
    .await;
    assert_eq!(
        reason(&refused).as_deref(),
        Some("approval_invalid"),
        "{refused}"
    );
    // A declined answer does not run the action.
    let declined = rpc_as(
        &server,
        None,
        "tools/call",
        call(json!({"requestState": state, "inputResponses": {"approval": {"action": "decline"}}})),
    )
    .await;
    assert_eq!(
        reason(&declined).as_deref(),
        Some("approval_declined"),
        "{declined}"
    );
    assert_eq!(ok_results(&lab), 0);

    // A fresh request, accepted: exactly one execution.
    let first = rpc_as(&server, None, "tools/call", call(json!({}))).await;
    let state = first["requestState"].as_str().unwrap().to_owned();
    let done = rpc_as(
        &server,
        None,
        "tools/call",
        call(json!({"requestState": state, "inputResponses": accept})),
    )
    .await;
    assert_eq!(done["isError"], false, "{done}");
    assert_eq!(done["resultType"], "complete");
    assert_eq!(ok_results(&lab), 1);
    // The consumed state gives a fresh request, not a second execution.
    let replay = rpc_as(
        &server,
        None,
        "tools/call",
        call(json!({"requestState": state, "inputResponses": accept})),
    )
    .await;
    assert_eq!(replay["resultType"], "input_required", "{replay}");
    assert_eq!(ok_results(&lab), 1);

    // A client without the elicitation capability never receives inputRequests.
    let mut params = call(json!({}));
    params["_meta"] = modern(false);
    let plain = rpc_as(&server, None, "tools/call", params).await;
    assert!(plain.get("inputRequests").is_none(), "{plain}");
    assert_eq!(
        kind(&plain).as_deref(),
        Some("approval_required"),
        "{plain}"
    );
    let id = plain["structuredContent"]["error"]["detail"]["approval_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Out of band: pending until the operator signs the record, then once.
    let mut with_id = type_args.clone();
    with_id["approval_id"] = json!(id);
    let pending = lab.mcp.tool("type_text", with_id.clone()).await;
    assert_eq!(
        pending["structuredContent"]["error"]["detail"]["status"], "pending",
        "{pending}"
    );
    let dir = lab.mcp.ctx.cfg.approvals_dir();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    approvals::approve(&dir, &id, &lab.keys, "op", now).unwrap();
    let before = ok_results(&lab);
    let done = lab.mcp.tool("type_text", with_id.clone()).await;
    assert_eq!(done["isError"], false, "{done}");
    assert_eq!(ok_results(&lab), before + 1);
    let again = lab.mcp.tool("type_text", with_id).await;
    assert_eq!(again["isError"], true);
    assert_eq!(ok_results(&lab), before + 1, "the approval is single use");

    // The destructive click: no POST until approved; then exactly one.
    let click_args = json!({"session_id": lab.id, "ref": delete});
    let asked = lab.mcp.tool("click", click_args.clone()).await;
    assert_eq!(
        kind(&asked).as_deref(),
        Some("approval_required"),
        "{asked}"
    );
    assert_eq!(site.count("POST"), 0);
    let id = asked["structuredContent"]["error"]["detail"]["approval_id"]
        .as_str()
        .unwrap()
        .to_owned();
    approvals::approve(&dir, &id, &lab.keys, "op", now).unwrap();
    let mut approved = click_args.clone();
    approved["approval_id"] = json!(id);
    let result = lab.mcp.tool("click", approved).await;
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(site.count("POST /delete"), 1);
    // `confirm: true` is an intent flag: it never stands in for an approval.
    let intent = lab
        .mcp
        .tool(
            "release_session",
            json!({"session_id": "ses_00000000000000000000000000000009", "confirm": true}),
        )
        .await;
    assert_eq!(intent["isError"], true);
    lab.stop().await;
}

#[tokio::test]
async fn the_ledger_turns_three_flags_into_an_approval_or_a_refusal() {
    let scratch = tempfile::tempdir().unwrap();
    let site = serve(vec![(
        "/",
        page("<main><h1>App</h1><button>Run</button></main>"),
    )])
    .await;
    for (mode, strict) in [("enforce", false), ("strict", true)] {
        let origin = site.base.clone();
        let Some(mut lab) = lab(scratch.path(), |_, _| {
            format!(
                "[operator]\nkeys_file = \"operator.keys\"\n[mcp]\ncapabilities = [\"sessions\", \"browse\", \"interact\"]\n\
                 [browse]\nallowed_origins = [\"{origin}\"]\n\
                 [engagement]\nid = \"E\"\noperator = \"alice\"\nauthorization_note = \"n\"\n\
                 [safety]\nprofile = \"authorized_security_test\"\n\
                 [safety.rule_of_two]\nmode = \"{mode}\"\nprivate_network_is_sensitive = false\n"
            )
        })
        .await
        else {
            return;
        };
        let server = Server::new(Arc::clone(&lab.mcp.ctx));
        let status = lab.mcp.ok("engagement_status", json!({})).await;
        assert_eq!(status["flags"], json!({"A": false, "B": false, "C": true}));
        let handle = status["handle"].as_str().unwrap().to_owned();

        lab.open(&format!("{}/", site.base)).await;
        let snapshot = lab.snapshot().await;
        let run = ref_of(&snapshot, "button \"Run\"");
        let status = lab.mcp.ok("engagement_status", json!({})).await;
        assert_eq!(status["flags"], json!({"A": true, "B": false, "C": true}));
        // A and C only: the button works.
        let clicked = lab
            .mcp
            .tool("click", json!({"session_id": lab.id, "ref": run}))
            .await;
        assert_eq!(clicked["isError"], false, "{clicked}");

        // A persistent session is sensitive context: now all three are set.
        let sensitive = lab
            .mcp
            .tool(
                "create_session",
                json!({"launch_profile": "default", "persistence": "snapshot"}),
            )
            .await;
        assert_eq!(sensitive["isError"], false, "{sensitive}");
        let status = lab.mcp.ok("engagement_status", json!({})).await;
        assert_eq!(status["flags"], json!({"A": true, "B": true, "C": true}));
        assert_eq!(status["all_three"], true);
        let snapshot = lab.snapshot().await;
        let run = ref_of(&snapshot, "button \"Run\"");
        let gated = lab
            .mcp
            .tool("click", json!({"session_id": lab.id, "ref": run}))
            .await;
        assert_eq!(gated["isError"], true, "{gated}");
        if strict {
            assert_eq!(reason(&gated).as_deref(), Some("rule_of_two"), "{gated}");
        } else {
            assert_eq!(
                kind(&gated).as_deref(),
                Some("approval_required"),
                "{gated}"
            );
            let reasons = gated["structuredContent"]["error"]["detail"]["reasons"].to_string();
            assert!(reasons.contains("rule_of_two"), "{reasons}");
        }
        assert!(
            lab.audit()
                .contains("\"abc\":{\"A\":true,\"B\":true,\"C\":true}")
        );

        // Another principal's handle is unknown; so is a retired or forged one.
        let other = rpc_as(
            &server,
            Some("http:other"),
            "tools/call",
            json!({"name": "engagement_status", "arguments": {"handle": handle}}),
        )
        .await;
        assert_eq!(reason(&other).as_deref(), Some("unknown_handle"), "{other}");
        assert!(other.to_string().contains("unknown handle"));
        let reset = lab.mcp.ok("reset_context", json!({})).await;
        assert_eq!(reset["retired"], true);
        let old = lab
            .mcp
            .tool("engagement_status", json!({"handle": handle}))
            .await;
        assert_eq!(reason(&old).as_deref(), Some("unknown_handle"));
        let fresh = lab.mcp.ok("engagement_status", json!({})).await;
        assert_eq!(fresh["flags"], json!({"A": false, "B": false, "C": true}));
        assert_ne!(fresh["handle"], json!(handle));

        // A restarted server does not know any old handle.
        let again = plain_ctx(
            lab.server.dir.path(),
            &format!(
                "[mcp]\ncapabilities = [\"browse\", \"interact\"]\n[browse]\nallowed_origins = [\"{}\"]\n\
                 [engagement]\noperator = \"a\"\nauthorization_note = \"n\"\n",
                site.base
            ),
        );
        let restarted = Server::new(again);
        let unknown = rpc_as(
            &restarted,
            None,
            "tools/call",
            json!({"name": "engagement_status", "arguments": {"handle": fresh["handle"]}}),
        )
        .await;
        assert_eq!(reason(&unknown).as_deref(), Some("unknown_handle"));
        lab.stop().await;
    }
}

#[tokio::test]
async fn a_signed_grant_limits_reading_actions_and_the_steps_that_may_run() {
    let scratch = tempfile::tempdir().unwrap();
    let evil = serve(vec![("/", page("<main><h1>Evil</h1></main>"))]).await;
    let framed = serve(vec![(
        "/frame",
        page("<main><h2>IFRAME-SECRET-TEXT</h2><button>Framed button</button></main>"),
    )])
    .await;
    let doc = serve(vec![("/", page("<main><h1>Reference</h1></main>"))]).await;
    let secret = "bxk_test_0123456789abcdef0123";
    let app = serve(vec![(
        "/",
        page(&format!(
            "<main><h1>App</h1><a href=\"{evil}/?q={secret}\">Injected</a>\
             <a href=\"{doc}/\">Reference</a>\
             <iframe src=\"{framed}/frame\" title=\"Embedded\"></iframe></main>",
            evil = evil.base,
            doc = doc.base,
            framed = framed.base,
        )),
    )])
    .await;
    let grant_text = format!(
        "[grant]\nengagement = \"E\"\nprincipal = \"*\"\nro_origins = [\"{doc}\"]\nrw_origins = [\"{app}\"]\n\
         not_after = \"2099-01-01T00:00:00Z\"\n[budgets]\ncalls = 100\n\
         [[plan]]\ntool = \"open_page\"\norigin = \"{app}\"\naction_class = \"navigate_in_scope\"\nmax_count = 3\n\
         [[plan]]\ntool = \"page_snapshot\"\nmax_count = 5\n\
         [[plan]]\ntool = \"click\"\nmax_count = 2\n",
        doc = doc.base,
        app = app.base
    );
    let origins = format!(
        "[\"{}\", \"{}\", \"{}\", \"{}\"]",
        app.base, evil.base, framed.base, doc.base
    );
    let Some(mut lab) = lab(scratch.path(), |dir, keys| {
        std::fs::write(dir.join("grant.toml"), &grant_text).unwrap();
        std::fs::write(
            dir.join("grant.toml.sig"),
            grants::sign(keys, "op", grant_text.as_bytes()).unwrap(),
        )
        .unwrap();
        format!(
            "[operator]\nkeys_file = \"operator.keys\"\n[grant]\npath = \"grant.toml\"\n\
             [mcp]\ncapabilities = [\"sessions\", \"browse\", \"interact\", \"evaluate\"]\n\
             [browse]\nallowed_origins = {origins}\n\
             [engagement]\nid = \"E\"\noperator = \"alice\"\nauthorization_note = \"n\"\n\
             [safety]\nprofile = \"authorized_security_test\"\n[safety.rule_of_two]\nmode = \"off\"\n"
        )
    })
    .await
    else {
        return;
    };

    // Model-built URL to an origin outside the grant: refused, nothing sent to it.
    let refused = lab.open(&format!("{}/?q={secret}", evil.base)).await;
    // The secret shape is redacted from the answer, the reason is the shared code.
    assert_eq!(
        reason(&refused).as_deref(),
        Some("origin_not_in_rw"),
        "{refused}"
    );
    // A URL that carries a known secret value is never sent anywhere.
    assert!(evil.hits().is_empty());

    let opened = lab.open(&format!("{}/", app.base)).await;
    assert_eq!(opened["isError"], false, "{opened}");
    // The exfiltration guard: a secret-looking value to a read-write origin needs an approval.
    let leak = lab
        .open(&format!("{}/?t=Zk3Hq9XpL2vB7nTr5WcYd8Ae", app.base))
        .await;
    assert_eq!(kind(&leak).as_deref(), Some("approval_required"), "{leak}");
    assert!(leak.to_string().contains("exfiltration_guard"));

    let snapshot = lab.snapshot().await;
    // Text of an iframe from an origin the grant does not cover never reaches the model.
    assert!(!snapshot.contains("IFRAME-SECRET-TEXT"), "{snapshot}");
    assert!(snapshot.contains("content withheld"), "{snapshot}");
    assert!(framed.count("/frame") <= 1);

    // The injected link to a non-grant origin: refused before any request leaves.
    let injected = ref_of(&snapshot, "link \"Injected\"");
    let blocked = lab
        .mcp
        .tool("click", json!({"session_id": lab.id, "ref": injected}))
        .await;
    assert_eq!(blocked["isError"], true, "{blocked}");
    assert!(evil.hits().is_empty(), "{:?}", evil.hits());

    // An injected script call is not a step of the plan.
    let script = lab
        .mcp
        .tool(
            "evaluate_js",
            json!({"session_id": lab.id, "expression": "document.title"}),
        )
        .await;
    assert_eq!(reason(&script).as_deref(), Some("outside_plan"), "{script}");

    // A proposal that widens is rejected; a narrowing one is only a file until signed.
    let widening = lab
        .mcp
        .tool(
            "propose_scope_grant",
            json!({"ro_origins": [evil.base], "rw_origins": [app.base]}),
        )
        .await;
    assert_eq!(
        reason(&widening).as_deref(),
        Some("proposal_widens_ceiling"),
        "{widening}"
    );
    let narrowing = lab
        .mcp
        .ok(
            "propose_scope_grant",
            json!({"ro_origins": [doc.base], "rw_origins": [], "allowed_tools": ["open_page"], "calls": 5,
                   "not_after": "2098-01-01T00:00:00Z"}),
        )
        .await;
    assert_eq!(narrowing["active"], false);
    assert_eq!(narrowing["narrows_the_ceiling"], true);
    assert!(Path::new(narrowing["file"].as_str().unwrap()).exists());
    lab.stop().await;

    // A forged grant stops the server from starting.
    let dir = tempfile::tempdir().unwrap();
    let keys = write_keys(dir.path());
    std::fs::write(dir.path().join("grant.toml"), &grant_text).unwrap();
    std::fs::write(
        dir.path().join("grant.toml.sig"),
        grants::sign(&keys, "op", grant_text.as_bytes()).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("grant.toml"),
        grant_text.replace("calls = 100", "calls = 900"),
    )
    .unwrap();
    std::fs::write(dir.path().join("key"), "bxk_synthetic\n").unwrap();
    let text = format!(
        "[server]\nurl = \"http://127.0.0.1:1\"\napi_key_file = \"key\"\n[audit]\npath = \"audit.jsonl\"\n\
         [operator]\nkeys_file = \"operator.keys\"\n[grant]\npath = \"grant.toml\"\n\
         [mcp]\ncapabilities = [\"browse\"]\n[browse]\nallowed_origins = {origins}\n\
         [engagement]\noperator = \"a\"\nauthorization_note = \"n\"\n"
    );
    let config = browserx_mcp::Config::parse(&text, dir.path()).unwrap();
    let error = Ctx::build(config).unwrap_err().to_string();
    assert!(error.contains("not signed"), "{error}");
}

#[tokio::test]
async fn screenshots_are_resource_links_for_modern_requests_and_images_for_legacy_ones() {
    use base64::Engine as _;
    let scratch = tempfile::tempdir().unwrap();
    let site = serve(vec![("/", page("<main><h1>Shot</h1></main>"))]).await;
    let origin = site.base.clone();
    let Some(mut lab) = lab(scratch.path(), |_, _| {
        format!(
            "[mcp]\ncapabilities = [\"sessions\", \"browse\"]\n[browse]\nallowed_origins = [\"{origin}\"]\n\
             [engagement]\nid = \"E\"\noperator = \"alice\"\nauthorization_note = \"n\"\n"
        )
    })
    .await
    else {
        return;
    };
    lab.open(&format!("{}/", site.base)).await;
    // Legacy: an inline image block.
    let legacy = lab
        .mcp
        .tool("screenshot", json!({"session_id": lab.id}))
        .await;
    assert!(
        legacy["content"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["type"] == "image"),
        "{legacy}"
    );
    // Modern: a resource link, readable as a PNG blob.
    let server = Server::new(Arc::clone(&lab.mcp.ctx));
    let modern_result = rpc_as(
        &server,
        None,
        "tools/call",
        json!({"name": "screenshot", "arguments": {"session_id": lab.id}, "_meta": modern(false)}),
    )
    .await;
    assert_eq!(modern_result["isError"], false, "{modern_result}");
    let link = modern_result["content"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["type"] == "resource_link")
        .unwrap_or_else(|| panic!("no resource_link in {modern_result}"));
    assert!(
        modern_result["content"]
            .as_array()
            .unwrap()
            .iter()
            .all(|b| b["type"] != "image")
    );
    let uri = link["uri"].as_str().unwrap();
    assert_eq!(modern_result["structuredContent"]["resource_uri"], uri);
    let read = rpc_as(
        &server,
        None,
        "resources/read",
        json!({"uri": uri, "_meta": modern(false)}),
    )
    .await;
    let blob = read["contents"][0]["blob"].as_str().unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .unwrap();
    assert_eq!(&bytes[..4], &[0x89, b'P', b'N', b'G']);
    lab.stop().await;
}
