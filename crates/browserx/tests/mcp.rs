//! Drives the real `browserx` binary: `browserx mcp` over stdio (utilities, protocol, audit) and,
//! when a Chromium is available, a full browsing session against a running `browserx serve`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_browserx"))
}

fn run(args: &[&str]) -> (bool, String, String) {
    let output = std::process::Command::new(binary())
        .args(args)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn write_private(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A running `browserx mcp` speaking JSON-RPC on its stdio.
struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next: u64,
}

impl Mcp {
    fn spawn(config: &Path) -> Self {
        let mut child = Command::new(binary())
            .args(["mcp", "--config"])
            .arg(config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            next: 0,
        }
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        let line =
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(line.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();
        stdin.flush().await.unwrap();
        loop {
            let mut reply = String::new();
            let n =
                tokio::time::timeout(Duration::from_secs(120), self.stdout.read_line(&mut reply))
                    .await
                    .expect("timed out waiting for the MCP server")
                    .unwrap();
            assert!(n > 0, "the MCP server closed its stdout");
            let value: Value =
                serde_json::from_str(reply.trim()).expect("stdout carries only JSON-RPC frames");
            if value["id"] == json!(id) {
                return value;
            }
        }
    }

    async fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let reply = self
            .request("tools/call", json!({"name": name, "arguments": arguments}))
            .await;
        assert!(reply.get("error").is_none(), "{name}: {reply}");
        reply["result"].clone()
    }

    /// Closes stdin and waits for a clean exit.
    async fn finish(mut self) {
        drop(self.stdin.take());
        let status = tokio::time::timeout(Duration::from_secs(30), self.child.wait())
            .await
            .expect("browserx mcp exits when stdin closes")
            .unwrap();
        assert!(status.success(), "{status}");
    }
}

fn text_blocks(result: &Value) -> Vec<String> {
    result["content"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|b| b["text"].as_str().map(str::to_owned))
        .collect()
}

fn untrusted(result: &Value) -> String {
    text_blocks(result)
        .into_iter()
        .find(|t| t.starts_with("<untrusted_page_content"))
        .unwrap_or_else(|| panic!("no untrusted block in {result}"))
}

const READ_ONLY: &str = "[server]\nurl = \"http://127.0.0.1:1\"\napi_key_file = \"api-key\"\n[audit]\npath = \"audit.jsonl\"\n";

#[tokio::test]
async fn mcp_serves_the_protocol_on_stdio_and_keeps_a_verifiable_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    write_private(
        &dir.path().join("api-key"),
        "bxk_synthetic_key_for_the_cli_test\n",
    );
    let config = dir.path().join("mcp.toml");
    std::fs::write(&config, READ_ONLY).unwrap();

    let (ok, out, _) = run(&["mcp", "check", config.to_str().unwrap()]);
    assert!(
        ok && out.contains("configuration is valid") && out.contains("read-only"),
        "{out}"
    );
    let (ok, _, err) = run(&[
        "mcp",
        "check",
        dir.path().join("missing.toml").to_str().unwrap(),
    ]);
    assert!(!ok && err.contains("cannot read"), "{err}");

    let (ok, out, _) = run(&["mcp", "token", "new"]);
    let digest_line = out
        .lines()
        .find(|l| l.starts_with("token_sha256"))
        .expect("config line");
    assert!(
        ok && out.contains("bxm_") && digest_line.len() > 64,
        "{out}"
    );

    let mut mcp = Mcp::spawn(&config);
    let init = mcp
        .request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "cli-test", "version": "1"}}))
        .await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    let tools = mcp.request("tools/list", json!({})).await;
    assert!(
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "capabilities")
    );
    assert!(
        !tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "open_page")
    );
    let caps = mcp.tool("capabilities", json!({})).await;
    assert_eq!(caps["structuredContent"]["read_only"], true);
    let error = mcp.request("nope/nope", json!({})).await;
    assert_eq!(error["error"]["code"], -32601);
    mcp.finish().await;

    let audit = dir.path().join("audit.jsonl");
    let (ok, out, _) = run(&["mcp", "audit", "verify", audit.to_str().unwrap()]);
    assert!(
        ok && out.contains("audit log is intact: 1 entries"),
        "{out}"
    );
    assert!(
        std::fs::read_to_string(&audit)
            .unwrap()
            .contains("cli-test")
    );

    // Editing an entry breaks the chain, and the command says where.
    let edited = std::fs::read_to_string(&audit).unwrap().replacen(
        "\"outcome\":\"ok\"",
        "\"outcome\":\"error\"",
        1,
    );
    std::fs::write(&audit, edited).unwrap();
    let (ok, _, err) = run(&["mcp", "audit", "verify", audit.to_str().unwrap()]);
    assert!(!ok && err.contains("chain breaks at line 1"), "{err}");
}

#[tokio::test]
async fn mcp_stops_on_sigterm_even_while_stdin_stays_open() {
    let dir = tempfile::tempdir().unwrap();
    write_private(
        &dir.path().join("api-key"),
        "bxk_synthetic_key_for_the_cli_test\n",
    );
    let config = dir.path().join("mcp.toml");
    std::fs::write(&config, READ_ONLY).unwrap();
    let mut mcp = Mcp::spawn(&config);
    mcp.request("ping", json!({})).await;
    let pid = mcp.child.id().unwrap();
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let status = tokio::time::timeout(Duration::from_secs(10), mcp.child.wait())
        .await
        .expect("browserx mcp stops on SIGTERM although its stdin is still open")
        .unwrap();
    assert!(status.success(), "{status}");
    drop(mcp.stdin.take());
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Serves two small pages and counts nothing: just enough to click through.
async fn site() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let n = stream.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..n]).into_owned();
                let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let body = if path == "/next" {
                    "<!doctype html><title>Second</title><main><h1>Second</h1><p>You arrived on the second page of the binary test site.</p></main>"
                } else {
                    "<!doctype html><title>First</title><main><h1>First</h1><p>The first page of the binary test site has a link.</p><a href=\"/next\">Continue</a></main>"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn mcp_binary_drives_a_session_on_a_running_server() {
    let Some(chromium) = browserx_runtime::discover_chromium() else {
        eprintln!(
            "SKIP: no Chromium found (set BROWSERX_CHROMIUM_PATH to run the binary end-to-end test)"
        );
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // A key for the MCP server and a snapshot key for the BrowserX server.
    let (ok, out, _) = run(&["keys", "new", "mcp"]);
    assert!(ok);
    let key = out
        .lines()
        .find(|l| l.starts_with("bxk_"))
        .unwrap()
        .to_owned();
    let sha = out
        .lines()
        .find(|l| l.starts_with("sha256"))
        .unwrap()
        .to_owned();
    write_private(&root.join("api-key"), &format!("{key}\n"));
    let snapshot_key = root.join("keys/snapshot.key");
    let (ok, _, err) = run(&["snapshot-key", "new", snapshot_key.to_str().unwrap()]);
    assert!(ok, "{err}");

    let (api, ops) = (free_port().await, free_port().await);
    let server_config = root.join("server.toml");
    std::fs::write(
        &server_config,
        format!(
            "[server]\nlisten = \"127.0.0.1:{api}\"\nops_listen = \"127.0.0.1:{ops}\"\npublic_base_url = \"http://127.0.0.1:{api}\"\n\
             [[auth.api_keys]]\nname = \"mcp\"\n{sha}\nmax_sessions = 4\n\
             [storage]\nstate_dir = \"{state}\"\nsnapshot_key_file = \"{key_file}\"\n\
             [egress]\nallow_cidrs = [\"127.0.0.0/8\"]\n\
             [runtime]\nstartup_timeout_secs = 60\n[runtime.launch_profiles.default]\nexecutable = \"{exe}\"\nargs = [\"--no-sandbox\", \"--disable-gpu\"]\n",
            state = root.join("state").display(),
            key_file = snapshot_key.display(),
            exe = chromium.display(),
        ),
    )
    .unwrap();
    let mut server = Command::new(binary())
        .args(["serve", "--config"])
        .arg(&server_config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let http = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..150 {
        if let Ok(resp) = http
            .get(format!("http://127.0.0.1:{ops}/readyz"))
            .send()
            .await
            && resp.status().is_success()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ready, "browserx serve did not become ready");

    let allowed = site().await;
    let mcp_config = root.join("mcp.toml");
    std::fs::write(
        &mcp_config,
        format!(
            "[server]\nurl = \"http://127.0.0.1:{api}\"\nops_url = \"http://127.0.0.1:{ops}\"\napi_key_file = \"api-key\"\n\
             [mcp]\ncapabilities = [\"sessions\", \"browse\", \"interact\"]\n\
             [browse]\nallowed_origins = [\"{allowed}\"]\n\
             [engagement]\noperator = \"binary test\"\nauthorization_note = \"synthetic test engagement\"\n\
             [audit]\npath = \"audit.jsonl\"\n"
        ),
    )
    .unwrap();
    let mut mcp = Mcp::spawn(&mcp_config);
    mcp.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "binary-test", "version": "1"}})).await;

    let health = mcp.tool("health", json!({})).await;
    assert_eq!(health["structuredContent"]["healthy"], true, "{health}");
    let created = mcp.tool("create_session", json!({})).await;
    assert_eq!(created["isError"], false, "{created}");
    let id = created["structuredContent"]["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let opened = mcp
        .tool(
            "open_page",
            json!({"session_id": id, "url": format!("{allowed}/")}),
        )
        .await;
    assert_eq!(opened["isError"], false, "{opened}");
    assert!(untrusted(&opened).contains("title: First"));
    let snapshot = untrusted(&mcp.tool("page_snapshot", json!({"session_id": id})).await);
    let line = snapshot
        .lines()
        .find(|l| l.contains("link \"Continue\""))
        .unwrap_or_else(|| panic!("{snapshot}"));
    let reference = &line[line.find("[e").unwrap() + 1..line.find(']').unwrap()];
    let clicked = mcp
        .tool("click", json!({"session_id": id, "ref": reference}))
        .await;
    assert_eq!(clicked["structuredContent"]["navigated"], true, "{clicked}");
    let text = untrusted(&mcp.tool("page_text", json!({"session_id": id})).await);
    assert!(
        text.contains("second page of the binary test site"),
        "{text}"
    );

    let shot = mcp.tool("screenshot", json!({"session_id": id})).await;
    let image = shot["content"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["type"] == "image")
        .unwrap();
    assert_eq!(image["mimeType"], "image/png");
    assert!(
        image["data"].as_str().unwrap().starts_with("iVBOR"),
        "PNG magic in base64"
    );
    let net = untrusted(&mcp.tool("network_log", json!({"session_id": id})).await);
    assert!(net.contains(&format!("{allowed}/next")), "{net}");

    let refused = mcp
        .tool(
            "open_page",
            json!({"session_id": id, "url": "https://elsewhere.example.test/"}),
        )
        .await;
    assert_eq!(refused["isError"], true);
    assert!(text_blocks(&refused)[0].contains("outside the authorized scope"));

    let released = mcp
        .tool(
            "release_session",
            json!({"session_id": id, "confirm": true}),
        )
        .await;
    assert_eq!(
        released["structuredContent"]["released"], true,
        "{released}"
    );
    mcp.finish().await;

    let audit = root.join("audit.jsonl");
    let (ok, out, _) = run(&["mcp", "audit", "verify", audit.to_str().unwrap()]);
    assert!(ok && out.contains("audit log is intact"), "{out}");
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(!log.contains("bxt_") && !log.contains(&key) && log.contains("binary test"));

    // Stop the server the way an operator does, so it shuts its browsers down.
    let pid = server.id().unwrap();
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let _ = tokio::time::timeout(Duration::from_secs(30), server.wait()).await;
}
