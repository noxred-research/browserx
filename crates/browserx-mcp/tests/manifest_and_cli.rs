//! Offline signature vectors for the manifest and the grant, and the operator commands
//! (`manifest sign|verify`, `grant sign|verify`, `approvals`, `operator-key`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use browserx_mcp::crypto::OperatorKeys;
use browserx_mcp::{McpArgs, grants, manifest};
use clap::Parser;
use serde_json::Value;

#[derive(Parser)]
struct Wrapper {
    #[command(flatten)]
    mcp: McpArgs,
}

async fn run(args: &[&str]) -> Result<(), browserx_mcp::McpError> {
    let mut argv = vec!["browserx-mcp"];
    argv.extend_from_slice(args);
    let wrapper = Wrapper::try_parse_from(argv).unwrap();
    browserx_mcp::run(wrapper.mcp, std::future::pending()).await
}

#[test]
fn the_shared_signature_vectors_verify_exactly_as_expected() {
    let path = format!(
        "{}/tests/vectors/manifest/signatures.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let pack: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut keys = OperatorKeys::new();
    keys.insert(
        pack["key_id"].as_str().unwrap(),
        hex::decode(pack["key_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    for case in pack["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let domain = match case["kind"].as_str().unwrap() {
            "manifest" => manifest::DOMAIN,
            _ => grants::DOMAIN,
        };
        let verified = keys
            .verify(
                case["signature"].as_str().unwrap(),
                domain,
                case["content"].as_str().unwrap().as_bytes(),
            )
            .is_ok();
        assert_eq!(verified, case["valid"].as_bool().unwrap(), "{id}");
    }
}

fn write(dir: &Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path.display().to_string()
}

#[tokio::test]
async fn the_operator_signs_and_verifies_offline_and_a_tampered_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let keys = write(
        dir.path(),
        "operator.keys",
        &format!("op = {}\n", "0a".repeat(32)),
    );
    let manifest_text = "[engagement]\nid = \"e\"\noperator = \"a\"\nauthorization_note = \"n\"\n\
                         not_after = \"2099-01-01T00:00:00Z\"\n[[scope]]\nhost = \"app.example.test\"\nmode = \"attack\"\n";
    let path = write(dir.path(), "engagement.toml", manifest_text);
    // Unsigned: verify fails with a message that says why.
    let error = run(&["manifest", "verify", &path, "--keys", &keys])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no signature"), "{error}");
    run(&["manifest", "sign", &path, "--keys", &keys])
        .await
        .unwrap();
    run(&["manifest", "verify", &path, "--keys", &keys])
        .await
        .unwrap();
    // One byte of the content changes: invalid.
    std::fs::write(&path, manifest_text.replace("2099", "2098")).unwrap();
    let error = run(&["manifest", "verify", &path, "--keys", &keys])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("invalid"), "{error}");
    // A manifest that does not parse is refused before it is signed.
    let bad = write(dir.path(), "bad.toml", "[engagement]\nid = \"\"\n");
    assert!(
        run(&["manifest", "sign", &bad, "--keys", &keys])
            .await
            .is_err()
    );

    let grant_text = "[grant]\nengagement = \"e\"\nrw_origins = [\"https://app.example.test\"]\n";
    let grant = write(dir.path(), "grant.toml", grant_text);
    run(&["grant", "sign", &grant, "--keys", &keys])
        .await
        .unwrap();
    run(&["grant", "verify", &grant, "--keys", &keys])
        .await
        .unwrap();
    std::fs::write(&grant, grant_text.replace("app.example", "evil.example")).unwrap();
    assert!(
        run(&["grant", "verify", &grant, "--keys", &keys])
            .await
            .is_err()
    );
    run(&["operator-key", "new", "second"]).await.unwrap();
}

#[tokio::test]
async fn approvals_are_listed_and_signed_from_the_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let keys = format!("op = {}\n", "0b".repeat(32));
    std::fs::write(dir.path().join("operator.keys"), &keys).unwrap();
    std::fs::write(dir.path().join("key"), "bxk_synthetic\n").unwrap();
    let config = write(
        dir.path(),
        "mcp.toml",
        "[server]\nurl = \"http://127.0.0.1:1\"\napi_key_file = \"key\"\n[audit]\npath = \"audit.jsonl\"\n\
         [operator]\nkeys_file = \"operator.keys\"\n[approvals]\ndir = \"approvals\"\n",
    );
    run(&["approvals", "list", "--config", &config])
        .await
        .unwrap();
    let error = run(&[
        "approvals",
        "approve",
        "apr_000000000000000000000000",
        "--config",
        &config,
    ])
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("no such pending approval"),
        "{error}"
    );
    let cfg = browserx_mcp::Config::load(Path::new(&config)).unwrap();
    assert_eq!(cfg.approvals_dir(), dir.path().join("approvals"));
}
