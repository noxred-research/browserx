//! `browserx agent eval`: runs a versioned suite of scripted attacks against loopback fixtures
//! through the MCP server, with a real BrowserX server and a real Chromium, and reports per
//! enforcement layer how many attacks were attempted, blocked and how many got through.
//!
//! The runner is an operator command, not a tool a model can call. It serves only loopback
//! fixtures, holds only synthetic secrets and makes no external request: the BrowserX server
//! it starts refuses every destination outside `127.0.0.0/8`. A case passes only when every
//! expectation holds; a step that names a `layer` is an attack, and an attack whose defence did
//! not hold is a deterministic escape. The run exits `0` only with every case passing and no
//! escape, `1` otherwise, and `2` when the environment cannot run it (no Chromium, no server).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use browserx_mcp::crypto::{OperatorKeys, new_key_line};
use browserx_mcp::server::Transport;
use browserx_mcp::{Config as McpConfig, Ctx, Server, grants};
use clap::Args;
use rand::Rng as _;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The suite format version this runner reads.
const SUITE_VERSION: u64 = 1;

/// `browserx agent eval` arguments.
#[derive(Debug, Args)]
pub struct EvalArgs {
    /// The suite: a directory holding `suite.json` and its `pages/`, or the `suite.json` file.
    #[arg(long)]
    pub suite: PathBuf,
    /// Where to write the JSON report.
    #[arg(long)]
    pub report: PathBuf,
    /// Fixes the order cases run in (0 keeps the suite's order). Verdicts do not depend on it.
    #[arg(long, default_value_t = 0)]
    pub seed: u64,
    /// Self-test: switch one enforcement layer off and let the suite show it notices. One of
    /// scope, grant, ledger, classifier, stale_ref, redaction.
    #[cfg(feature = "fault-injection")]
    #[arg(long)]
    pub mutate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Suite {
    version: u64,
    name: String,
    origins: BTreeMap<String, OriginSpec>,
    configs: BTreeMap<String, ConfigSpec>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct OriginSpec {
    #[serde(default)]
    forbidden: bool,
    routes: BTreeMap<String, Route>,
}

#[derive(Debug, Clone, Deserialize)]
struct Route {
    file: Option<String>,
    status: Option<u16>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ConfigSpec {
    capabilities: Vec<String>,
    profile: String,
    rule_of_two: String,
    #[serde(default = "yes")]
    private_network_is_sensitive: bool,
    scope: Vec<String>,
    grant: Option<GrantSpec>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
struct GrantSpec {
    ro: Vec<String>,
    rw: Vec<String>,
    plan: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    layer: String,
    config: String,
    #[serde(default)]
    description: String,
    steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
struct Step {
    tool: String,
    #[serde(default)]
    args: Value,
    layer: Option<String>,
    #[serde(default)]
    expect: Value,
    #[serde(default)]
    modern: bool,
    #[serde(default, rename = "requestState")]
    request_state: Option<String>,
    #[serde(default, rename = "inputResponses")]
    input_responses: Option<Value>,
}

/// One fixture origin with its access log.
struct Fixture {
    base: String,
    forbidden: bool,
    log: Arc<Mutex<Vec<String>>>,
}

impl Fixture {
    fn hits(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// The synthetic API-key-shaped value pages carry to prove redaction. It is assembled here so
/// no secret-shaped literal sits in the repository.
fn canary_key() -> String {
    ["bxk", "test", "canary", "9f8e7d6c5b4a39281706"].join("_")
}

fn fill(text: &str, bases: &BTreeMap<String, String>, api_key: &str) -> String {
    let mut out = text
        .replace("@@api_key@@", api_key)
        .replace("@@canary_key@@", &canary_key());
    for (name, base) in bases {
        out = out.replace(&format!("@@{name}@@"), base);
    }
    out
}

async fn serve_origin(
    listener: TcpListener,
    spec: Arc<BTreeMap<String, Route>>,
    pages: Arc<PathBuf>,
    bases: Arc<BTreeMap<String, String>>,
    log: Arc<Mutex<Vec<String>>>,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let (spec, pages, bases, log) = (
            Arc::clone(&spec),
            Arc::clone(&pages),
            Arc::clone(&bases),
            Arc::clone(&log),
        );
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 16 * 1024];
            let n = stream.read(&mut buffer).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..n]).into_owned();
            let mut parts = request.split_whitespace();
            let method = parts.next().unwrap_or("GET").to_owned();
            let target = parts.next().unwrap_or("/").to_owned();
            if target != "/favicon.ico" {
                log.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(format!("{method} {target}"));
            }
            let path = target.split('?').next().unwrap_or("/");
            let (status, headers, body) = match spec.get(path) {
                Some(route) => {
                    let body = route
                        .file
                        .as_ref()
                        .and_then(|file| std::fs::read_to_string(pages.join(file)).ok())
                        .map(|text| fill(&text, &bases, ""))
                        .unwrap_or_default();
                    (route.status.unwrap_or(200), route.headers.clone(), body)
                }
                None => (
                    404,
                    BTreeMap::new(),
                    "<!doctype html><p>missing</p>".to_owned(),
                ),
            };
            let mut head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (name, value) in &headers {
                head.push_str(&format!("{name}: {}\r\n", fill(value, &bases, "")));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(body.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// The environment of a run: a BrowserX server and the keys that belong to it.
struct Rig {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    api: String,
    ops: String,
    api_key: String,
    keys: OperatorKeys,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<tokio::task::JoinHandle<browserx_core::Result<()>>>,
}

impl Rig {
    async fn start(chromium: &Path) -> Result<Self> {
        let tmp = tempfile::tempdir().context("cannot create a scratch directory")?;
        let dir = tmp.path().to_path_buf();
        let (api_port, ops_port) = (free_port()?, free_port()?);
        let mut key_bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut key_bytes);
        let api_key = format!("bxk_{}", hex::encode(key_bytes));
        crate::keys::new_snapshot_key(&dir.join("keys").join("snapshot.key"))?;
        let args: Vec<String> = std::env::var("BROWSERX_TEST_BROWSER_ARGS")
            .unwrap_or_else(|_| "--no-sandbox --disable-gpu".into())
            .split_whitespace()
            .map(|a| format!("{a:?}"))
            .collect();
        let text = format!(
            "[server]\nlisten = \"127.0.0.1:{api_port}\"\nops_listen = \"127.0.0.1:{ops_port}\"\n\
             public_base_url = \"http://127.0.0.1:{api_port}\"\n\
             [[auth.api_keys]]\nname = \"eval\"\nsha256 = \"{}\"\nmax_sessions = 16\n\
             [pool]\nmax_browsers = 4\nqueue_timeout_secs = 20\n\
             [session]\ndefault_ttl_secs = 600\ndefault_idle_timeout_secs = 600\n\
             [storage]\nstate_dir = \"{}\"\nsnapshot_key_file = \"{}\"\n\
             [egress]\nblock_private = true\nallow_cidrs = [\"127.0.0.0/8\"]\n\
             [runtime]\ndefault_launch_profile = \"default\"\nstartup_timeout_secs = 60\n\
             [runtime.launch_profiles.default]\nheadless = true\nexecutable = \"{}\"\nargs = [{}]\n",
            browserx_server::key_digest(&api_key),
            dir.join("state").display(),
            dir.join("keys").join("snapshot.key").display(),
            chromium.display(),
            args.join(", ")
        );
        let config_path = dir.join("server.toml");
        std::fs::write(&config_path, text)?;
        let config = browserx_server::Config::load(&config_path)
            .context("the generated server configuration is invalid")?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(browserx_server::run(config, async move {
            let _ = stopped.await;
        }));
        let ops = format!("http://127.0.0.1:{ops_port}");
        let client = reqwest::Client::new();
        let started = Instant::now();
        loop {
            if client
                .get(format!("{ops}/readyz"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            if started.elapsed() > Duration::from_secs(60) || server.is_finished() {
                bail!("the BrowserX server did not become ready");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let line = new_key_line("eval");
        std::fs::write(dir.join("operator.keys"), format!("{line}\n"))?;
        let keys = OperatorKeys::load(&dir.join("operator.keys"))?;
        std::fs::write(dir.join("mcp-api-key"), format!("{api_key}\n"))?;
        Ok(Self {
            dir,
            _dir: tmp,
            api: format!("http://127.0.0.1:{api_port}"),
            ops,
            api_key,
            keys,
            stop: Some(stop),
            server: Some(server),
        })
    }

    async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(server) = self.server.take() {
            let _ = tokio::time::timeout(Duration::from_secs(30), server).await;
        }
    }
}

/// What a mutation (a deliberately removed layer) changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mutation {
    None,
    Scope,
    Grant,
    Ledger,
    #[cfg(feature = "fault-injection")]
    Fault,
}

fn mcp_config(
    suite_name: &str,
    name: &str,
    spec: &ConfigSpec,
    bases: &BTreeMap<String, String>,
    rig: &Rig,
    mutation: Mutation,
) -> Result<McpConfig> {
    let origins = |names: &[String]| -> Vec<String> {
        names.iter().filter_map(|n| bases.get(n).cloned()).collect()
    };
    let quoted = |items: Vec<String>| {
        format!(
            "[{}]",
            items
                .iter()
                .map(|i| format!("{i:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let scope = if mutation == Mutation::Scope {
        "[browse]\nrequire_scope = false\n".to_owned()
    } else {
        format!(
            "[browse]\nallowed_origins = {}\n",
            quoted(origins(&spec.scope))
        )
    };
    let mode = if mutation == Mutation::Ledger {
        "off"
    } else {
        spec.rule_of_two.as_str()
    };
    let engagement = format!("eval-{suite_name}");
    let mut grant_section = String::new();
    if let Some(grant) = spec.grant.as_ref().filter(|_| mutation != Mutation::Grant) {
        let mut text = format!(
            "[grant]\nengagement = {engagement:?}\nprincipal = \"*\"\nro_origins = {}\nrw_origins = {}\n\
             not_after = \"2099-01-01T00:00:00Z\"\n[budgets]\ncalls = 500\n",
            quoted(origins(&grant.ro)),
            quoted(origins(&grant.rw)),
        );
        for step in &grant.plan {
            text.push_str("[[plan]]\n");
            for key in ["tool", "origin", "action_class"] {
                if let Some(value) = step.get(key).and_then(Value::as_str) {
                    let value = if key == "origin" && value != "*" {
                        bases
                            .get(value)
                            .cloned()
                            .unwrap_or_else(|| value.to_owned())
                    } else {
                        value.to_owned()
                    };
                    text.push_str(&format!("{key} = {value:?}\n"));
                }
            }
            if let Some(n) = step.get("max_count").and_then(Value::as_u64) {
                text.push_str(&format!("max_count = {n}\n"));
            }
        }
        let path = rig.dir.join(format!("grant-{name}.toml"));
        std::fs::write(&path, &text)?;
        let signature =
            grants::sign(&rig.keys, "eval", text.as_bytes()).map_err(|e| anyhow::anyhow!("{e}"))?;
        std::fs::write(rig.dir.join(format!("grant-{name}.toml.sig")), signature)?;
        grant_section = format!("[grant]\npath = {:?}\n", path.display().to_string());
    }
    let text = format!(
        "[server]\nurl = {:?}\nops_url = {:?}\napi_key_file = {:?}\n\
         [audit]\npath = {:?}\n\
         [operator]\nkeys_file = {:?}\n{grant_section}\
         [approvals]\ndir = {:?}\n\
         [mcp]\ncapabilities = {}\nrelease_on_exit = true\n{scope}\
         [engagement]\nid = {engagement:?}\noperator = \"agent-eval\"\nauthorization_note = \"loopback fixtures only\"\n\
         [safety]\nprofile = {:?}\n[safety.rule_of_two]\nmode = {mode:?}\nprivate_network_is_sensitive = {}\n",
        rig.api,
        rig.ops,
        rig.dir.join("mcp-api-key").display().to_string(),
        rig.dir
            .join(format!("audit-{name}.jsonl"))
            .display()
            .to_string(),
        rig.dir.join("operator.keys").display().to_string(),
        rig.dir
            .join(format!("approvals-{name}"))
            .display()
            .to_string(),
        quoted(spec.capabilities.clone()),
        spec.profile,
        spec.private_network_is_sensitive,
    );
    McpConfig::parse(&text, &rig.dir).map_err(|e| anyhow::anyhow!("{e}"))
}

fn walk_strings(value: &mut Value, f: &dyn Fn(&str) -> String) {
    match value {
        Value::String(text) => *text = f(text),
        Value::Array(items) => items.iter_mut().for_each(|v| walk_strings(v, f)),
        Value::Object(map) => map.values_mut().for_each(|v| walk_strings(v, f)),
        _ => {}
    }
}

fn find_ref(snapshot: &str, needle: &str) -> Option<String> {
    let line = snapshot
        .lines()
        .find(|l| l.contains(needle) && l.contains("[e"))?;
    let start = line.find("[e")? + 1;
    let end = line[start..].find(']')? + start;
    Some(line[start..end].to_owned())
}

fn tamper(state: &str) -> String {
    let mut bytes = state.as_bytes().to_vec();
    if let Some(byte) = bytes.get_mut(state.len() / 2) {
        *byte = if *byte == b'A' { b'B' } else { b'A' };
    }
    String::from_utf8(bytes).unwrap_or_default()
}

fn texts(result: &Value) -> String {
    result["content"]
        .as_array()
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| b["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Whether every untrusted block ends with its own closing tag exactly once and marks every line.
fn envelope_intact(result: &Value) -> Result<(), String> {
    let mut checked = 0;
    for block in result["content"].as_array().into_iter().flatten() {
        let Some(text) = block["text"].as_str() else {
            continue;
        };
        if !text.starts_with("<untrusted_page_content ") {
            continue;
        }
        checked += 1;
        let first = text.lines().next().unwrap_or("");
        let nonce = first
            .split("nonce=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .ok_or("the opening tag has no nonce")?;
        let closing = format!("</untrusted_page_content nonce=\"{nonce}\">");
        if text.matches("</untrusted_page_content").count() != 1 || !text.ends_with(&closing) {
            return Err("the envelope has a second or a foreign closing tag".into());
        }
        let marker = format!("{}|", &nonce[..8.min(nonce.len())]);
        let lines: Vec<&str> = text.lines().collect();
        for line in &lines[1..lines.len().saturating_sub(1)] {
            if !line.starts_with(&marker) {
                return Err(format!("a body line lacks the datamark: {line:?}"));
            }
        }
    }
    if checked == 0 {
        return Err("no untrusted block in the result".into());
    }
    Ok(())
}

fn subset(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => e
            .iter()
            .all(|(k, v)| a.get(k).is_some_and(|got| subset(v, got))),
        _ => expected == actual,
    }
}

/// The failures of `expect` against a tool result.
fn evaluate(
    expect: &Value,
    result: &Value,
    fixtures: &BTreeMap<String, Fixture>,
    since: &BTreeMap<String, usize>,
) -> Vec<String> {
    let mut failures = Vec::new();
    let error = &result["structuredContent"]["error"];
    let is_error = result["isError"].as_bool().unwrap_or(false);
    let approval_asked =
        result["resultType"] == "input_required" || error["kind"] == "approval_required";
    let text = texts(result);
    if let Some(ok) = expect["ok"].as_bool()
        && (ok == is_error || (ok && approval_asked))
    {
        failures.push(format!("expected ok={ok}, got {}", brief(result)));
    }
    if let Some(code) = expect["refused"].as_str()
        && !(is_error && error["detail"]["reason"] == code)
    {
        failures.push(format!(
            "expected a refusal with reason {code}, got {}",
            brief(result)
        ));
    }
    if expect["approval_required"] == json!(true) && !approval_asked {
        failures.push(format!(
            "expected an approval request, got {}",
            brief(result)
        ));
    }
    if expect["input_required"] == json!(true) && result["resultType"] != "input_required" {
        failures.push(format!("expected input_required, got {}", brief(result)));
    }
    if let Some(detail) = expect.get("error_detail")
        && !subset(detail, &error["detail"])
    {
        failures.push(format!(
            "expected error detail {detail}, got {}",
            brief(result)
        ));
    }
    for needle in expect["text_contains"].as_array().into_iter().flatten() {
        if !text.contains(needle.as_str().unwrap_or("\u{0}")) {
            failures.push(format!("the result lacks {needle}"));
        }
    }
    for needle in expect["text_excludes"].as_array().into_iter().flatten() {
        if text.contains(needle.as_str().unwrap_or("\u{0}")) {
            failures.push(format!("the result contains {needle}"));
        }
    }
    if expect["envelope_intact"] == json!(true)
        && let Err(why) = envelope_intact(result)
    {
        failures.push(why);
    }
    if let Some(Value::Object(excludes)) = expect.get("log_excludes") {
        for (origin, needle) in excludes {
            if let (Some(fixture), Some(needle)) = (fixtures.get(origin), needle.as_str()) {
                let from = since.get(origin).copied().unwrap_or(0);
                if let Some(hit) = fixture
                    .hits()
                    .iter()
                    .skip(from)
                    .find(|h| h.contains(needle))
                {
                    failures.push(format!("{origin} received {hit:?}"));
                }
            }
        }
    }
    failures
}

fn brief(result: &Value) -> String {
    let text = texts(result);
    let shown: String = text.chars().take(240).collect();
    format!(
        "{shown}{}",
        if result["resultType"] == "input_required" {
            " (input_required)"
        } else {
            ""
        }
    )
}

#[derive(Default, Clone, Copy)]
struct Tally {
    attempted: u64,
    blocked: u64,
    escaped: u64,
}

struct CaseOutcome {
    json: Value,
    passed: bool,
}

#[allow(clippy::too_many_arguments)]
async fn run_case(
    case: &Case,
    server: &Server,
    fixtures: &BTreeMap<String, Fixture>,
    bases: &BTreeMap<String, String>,
    api_key: &str,
    tallies: &mut BTreeMap<String, Tally>,
) -> CaseOutcome {
    let started = Instant::now();
    let since: BTreeMap<String, usize> = fixtures
        .iter()
        .map(|(name, f)| (name.clone(), f.hits().len()))
        .collect();
    // Every case is its own principal: ledger flags, call budgets and plan progress belong to
    // the principal, so a case starts with a clean context whatever ran before it.
    let transport = Transport {
        name: "stdio",
        remote: None,
        principal: Some(format!("eval:{}", case.id)),
    };
    let call = |name: &str, args: Value, extra: Value| {
        let mut params = json!({ "name": name, "arguments": args });
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                params[k] = v.clone();
            }
        }
        let transport = transport.clone();
        async move {
            match server.handle("tools/call", Some(params), &transport).await {
                Ok(result) => result,
                Err(error) => {
                    json!({ "isError": true, "content": [{"type": "text", "text": error.message}],
                                       "structuredContent": {"error": {"kind": "protocol", "message": error.message}}})
                }
            }
        }
    };
    let created = call(
        "create_session",
        json!({"launch_profile": "default"}),
        json!({}),
    )
    .await;
    let mut sessions: Vec<String> = Vec::new();
    let session = created["structuredContent"]["session"]["session_id"]
        .as_str()
        .map(str::to_owned);
    let mut failures: Vec<String> = Vec::new();
    let mut step_reports: Vec<Value> = Vec::new();
    let Some(session) = session else {
        failures.push(format!("cannot create a session: {}", brief(&created)));
        return CaseOutcome {
            json: json!({ "id": case.id, "layer": case.layer, "config": case.config, "passed": false, "failures": failures }),
            passed: false,
        };
    };
    sessions.push(session.clone());
    let (mut first_snapshot, mut last_snapshot, mut state) =
        (String::new(), String::new(), String::new());

    for step in &case.steps {
        let mut args = step.args.clone();
        walk_strings(&mut args, &|s| {
            fill(s, bases, api_key).replace("$session", &session)
        });
        // `{"$ref": text}` objects become element refs.
        let mut ref_failure = None;
        if let Some(map) = args.as_object_mut() {
            for (key, value) in map.clone() {
                if let Some(object) = value.as_object() {
                    let (needle, source) =
                        if let Some(n) = object.get("$ref").and_then(Value::as_str) {
                            (n, &last_snapshot)
                        } else if let Some(n) = object.get("$ref_old").and_then(Value::as_str) {
                            (n, &first_snapshot)
                        } else {
                            continue;
                        };
                    match find_ref(source, needle) {
                        Some(found) => {
                            map.insert(key, json!(found));
                        }
                        None => {
                            ref_failure = Some(format!("no ref for {needle:?} in the snapshot"))
                        }
                    }
                }
            }
        }
        let mut extra = Map::new();
        if step.modern {
            extra.insert(
                "_meta".into(),
                json!({
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
                }),
            );
        }
        if let Some(requested) = &step.request_state {
            let value = match requested.as_str() {
                "$state" => state.clone(),
                "$state_tampered" => tamper(&state),
                other => other.to_owned(),
            };
            extra.insert("requestState".into(), json!(value));
        }
        if let Some(responses) = &step.input_responses {
            extra.insert("inputResponses".into(), responses.clone());
        }
        let step_started = Instant::now();
        let result = if let Some(why) = ref_failure {
            json!({ "isError": true, "content": [{"type": "text", "text": why}] })
        } else {
            call(&step.tool, args, Value::Object(extra)).await
        };
        if step.tool == "page_snapshot" && result["isError"] == false {
            let text = texts(&result);
            if first_snapshot.is_empty() {
                first_snapshot.clone_from(&text);
            }
            last_snapshot = text;
        }
        if step.tool == "create_session"
            && let Some(id) = result["structuredContent"]["session"]["session_id"].as_str()
        {
            sessions.push(id.to_owned());
        }
        if let Some(next) = result["requestState"].as_str() {
            state = next.to_owned();
        }
        let mut step_failures = evaluate(&step.expect, &result, fixtures, &since);
        if result["content"][0]["text"] == Value::Null && result.get("resultType").is_none() {
            step_failures.push("the call returned no content".into());
        }
        for (name, fixture) in fixtures {
            if fixture.forbidden {
                let from = since.get(name).copied().unwrap_or(0);
                if let Some(hit) = fixture.hits().into_iter().nth(from) {
                    step_failures.push(format!(
                        "the out-of-scope origin {name} received a request: {hit:?}"
                    ));
                }
            }
        }
        let passed = step_failures.is_empty();
        if let Some(layer) = &step.layer {
            let tally = tallies.entry(layer.clone()).or_default();
            tally.attempted += 1;
            if passed {
                tally.blocked += 1;
            } else {
                tally.escaped += 1;
            }
        }
        step_reports.push(json!({
            "tool": step.tool,
            "layer": step.layer,
            "passed": passed,
            "ms": u64::try_from(step_started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "failures": step_failures,
        }));
        failures.extend(
            step_failures
                .into_iter()
                .map(|f| format!("{}: {f}", step.tool)),
        );
    }
    for id in &sessions {
        let _ = call(
            "release_session",
            json!({"session_id": id, "confirm": true}),
            json!({}),
        )
        .await;
    }
    let passed = failures.is_empty();
    CaseOutcome {
        json: json!({
            "id": case.id,
            "layer": case.layer,
            "config": case.config,
            "description": case.description,
            "passed": passed,
            "ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "steps": step_reports,
            "failures": failures,
        }),
        passed,
    }
}

fn shuffled(count: usize, seed: u64) -> Vec<usize> {
    let mut order: Vec<usize> = (0..count).collect();
    if seed == 0 {
        return order;
    }
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    for i in (1..count).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let j = usize::try_from(state % (i as u64 + 1)).unwrap_or(0);
        order.swap(i, j);
    }
    order
}

/// Runs the suite. Returns the process exit status.
///
/// # Errors
/// Only for failures of the runner itself that are not an environment problem.
pub async fn run(args: EvalArgs) -> Result<i32> {
    let suite_path = if args.suite.is_dir() {
        args.suite.join("suite.json")
    } else {
        args.suite.clone()
    };
    let text = std::fs::read_to_string(&suite_path)
        .with_context(|| format!("cannot read the suite {}", suite_path.display()))?;
    let suite: Suite = serde_json::from_str(&text).context("the suite is not valid")?;
    if suite.version != SUITE_VERSION {
        bail!(
            "suite version {} is not supported (this runner reads {SUITE_VERSION})",
            suite.version
        );
    }
    let pages = Arc::new(
        suite_path
            .parent()
            .map_or_else(|| PathBuf::from("pages"), |p| p.join("pages")),
    );

    #[cfg(feature = "fault-injection")]
    let (mutation, mutation_name) = match args.mutate.as_deref() {
        None => (Mutation::None, None),
        Some("scope") => (Mutation::Scope, Some("scope")),
        Some("grant") => (Mutation::Grant, Some("grant")),
        Some("ledger") => (Mutation::Ledger, Some("ledger")),
        Some(name @ ("classifier" | "stale_ref" | "redaction")) => {
            use browserx_mcp::faults::{Fault, enable};
            enable(match name {
                "classifier" => Fault::Classifier,
                "stale_ref" => Fault::StaleRef,
                _ => Fault::Redaction,
            });
            (Mutation::Fault, Some(name))
        }
        Some(other) => bail!("unknown layer {other:?} for --mutate"),
    };
    #[cfg(not(feature = "fault-injection"))]
    let (mutation, mutation_name): (Mutation, Option<&str>) = (Mutation::None, None);

    let Some(chromium) = browserx_runtime::discover_chromium() else {
        eprintln!(
            "error: no Chromium was found (set BROWSERX_CHROMIUM_PATH). The agent evaluation needs a real browser: a lane without one must fail, not pass."
        );
        return Ok(2);
    };

    // Fixture origins: bind first so every origin knows the others' addresses.
    let mut listeners = BTreeMap::new();
    let mut bases = BTreeMap::new();
    for name in suite.origins.keys() {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        bases.insert(name.clone(), format!("http://{}", listener.local_addr()?));
        listeners.insert(name.clone(), listener);
    }
    let bases_shared = Arc::new(bases.clone());
    let mut fixtures = BTreeMap::new();
    for (name, listener) in listeners {
        let spec = &suite.origins[&name];
        let log: Arc<Mutex<Vec<String>>> = Arc::default();
        tokio::spawn(serve_origin(
            listener,
            Arc::new(spec.routes.clone()),
            Arc::clone(&pages),
            Arc::clone(&bases_shared),
            Arc::clone(&log),
        ));
        fixtures.insert(
            name.clone(),
            Fixture {
                base: bases[&name].clone(),
                forbidden: spec.forbidden,
                log,
            },
        );
    }

    let mut rig = match Rig::start(&chromium).await {
        Ok(rig) => rig,
        Err(error) => {
            eprintln!("error: cannot start the BrowserX server for the evaluation: {error:#}");
            return Ok(2);
        }
    };
    let mut servers: BTreeMap<String, Arc<Server>> = BTreeMap::new();
    let mut ctxs: Vec<Arc<Ctx>> = Vec::new();
    for (name, spec) in &suite.configs {
        let config = mcp_config(&suite.name, name, spec, &bases, &rig, mutation)?;
        let ctx = Ctx::build(config).map_err(|e| anyhow::anyhow!("{e}"))?;
        ctx.start();
        ctxs.push(Arc::clone(&ctx));
        servers.insert(name.clone(), Arc::new(Server::new(ctx)));
    }

    let started = Instant::now();
    let mut tallies: BTreeMap<String, Tally> = BTreeMap::new();
    let mut reports = Vec::new();
    let mut passed_cases = 0_usize;
    for index in shuffled(suite.cases.len(), args.seed) {
        let case = &suite.cases[index];
        let Some(server) = servers.get(&case.config) else {
            bail!("case {} names the unknown config {}", case.id, case.config);
        };
        let outcome = run_case(case, server, &fixtures, &bases, &rig.api_key, &mut tallies).await;
        println!(
            "{} {} ({})",
            if outcome.passed { "pass" } else { "FAIL" },
            case.id,
            case.layer
        );
        if !outcome.passed {
            for failure in outcome.json["failures"].as_array().into_iter().flatten() {
                println!("     {}", failure.as_str().unwrap_or(""));
            }
        }
        passed_cases += usize::from(outcome.passed);
        reports.push(outcome.json);
    }
    for ctx in &ctxs {
        ctx.shutdown().await;
    }
    rig.stop().await;

    let escapes: u64 = tallies.values().map(|t| t.escaped).sum();
    let attempted: u64 = tallies.values().map(|t| t.attempted).sum();
    let blocked: u64 = tallies.values().map(|t| t.blocked).sum();
    let failed = suite.cases.len() - passed_cases;
    let layers: Map<String, Value> = tallies
        .iter()
        .map(|(layer, t)| {
            (
                layer.clone(),
                json!({ "attempted": t.attempted, "blocked": t.blocked, "escaped": t.escaped }),
            )
        })
        .collect();
    let fixture_report: Map<String, Value> = fixtures
        .iter()
        .map(|(name, f)| {
            let hits = f.hits();
            (
                name.clone(),
                json!({
                    "origin": f.base,
                    "forbidden": f.forbidden,
                    "requests": hits.len(),
                    "first_requests": hits.iter().take(20).collect::<Vec<_>>(),
                }),
            )
        })
        .collect();
    let report = json!({
        "suite": suite.name,
        "suite_version": suite.version,
        "seed": args.seed,
        "mutation": mutation_name,
        "chromium": chromium.display().to_string(),
        "summary": {
            "cases": suite.cases.len(),
            "passed": passed_cases,
            "failed": failed,
            "attacks_attempted": attempted,
            "attacks_blocked": blocked,
            "deterministic_escapes": escapes,
            "measured_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        },
        "layers": layers,
        "fixtures": fixture_report,
        "cases": reports,
    });
    if let Some(parent) = args.report.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.report, serde_json::to_string_pretty(&report)? + "\n")
        .with_context(|| format!("cannot write the report {}", args.report.display()))?;
    println!(
        "\n{} cases, {passed_cases} passed, {failed} failed; {attempted} attacks, {blocked} blocked, {escapes} escaped",
        suite.cases.len()
    );
    println!("layer            attempted  blocked  escaped");
    for (layer, t) in &tallies {
        println!(
            "{layer:<16} {:>9}  {:>7}  {:>7}",
            t.attempted, t.blocked, t.escaped
        );
    }
    println!("report: {}", args.report.display());
    Ok(i32::from(failed > 0 || escapes > 0))
}
