//! `browserx doctor --config` reports the lease registry. No Chromium is needed: the launch
//! profile points at a missing executable, so the command ends right after the registry check.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

fn doctor(config: &Path) -> (bool, String) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_browserx"))
        .args(["doctor", "--config"])
        .arg(config)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

fn config(dir: &Path, extra: &str) -> std::path::PathBuf {
    let path = dir.join("browserx.toml");
    std::fs::write(
        &path,
        format!(
            "[[auth.api_keys]]\nname = \"dev\"\nsha256 = \"{zero}\"\n\n\
             [storage]\nstate_dir = {state:?}\nsnapshot_key_file = {key:?}\n\n\
             [runtime.launch_profiles.default]\nexecutable = \"/nonexistent/chromium\"\n\n{extra}",
            zero = "0".repeat(64),
            state = dir.join("state").display().to_string(),
            key = dir.join("keys").join("snapshot.key").display().to_string(),
        ),
    )
    .unwrap();
    path
}

#[test]
fn an_unreachable_registry_fails_the_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = config(
        dir.path(),
        "[database]\nurl = \"postgres://app@127.0.0.1:1/browserx\"\nnode = \"doctor-test\"\n",
    );
    let (ok, out) = doctor(&path);
    assert!(!ok, "{out}");
    let line = out
        .lines()
        .find(|l| l.contains("lease registry"))
        .unwrap_or_else(|| panic!("no registry line in:\n{out}"));
    assert!(line.contains("[FAIL]"), "{line}");
}

#[test]
fn a_sqlite_registry_is_reported_before_and_after_its_creation() {
    let dir = tempfile::tempdir().unwrap();
    let path = config(dir.path(), "");
    let (_, out) = doctor(&path);
    let line = out.lines().find(|l| l.contains("lease registry")).unwrap();
    assert!(
        line.contains("[ ok ]") && line.contains("created at the first start"),
        "{line}"
    );

    // With a database file present the check opens it and reads once.
    let db = dir.path().join("state").join("browserx.db");
    std::fs::write(&db, "").unwrap();
    let (_, out) = doctor(&path);
    let line = out.lines().find(|l| l.contains("lease registry")).unwrap();
    assert!(
        line.contains("[ ok ]") && line.contains("reachable"),
        "{line}"
    );
}
