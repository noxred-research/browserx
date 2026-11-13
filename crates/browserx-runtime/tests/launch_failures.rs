//! Launch failure paths, exercised with throw-away shell scripts that stand in for
//! a browser. Kept in one test function: writing and executing script files from
//! concurrently running tests can race on `ETXTBSY`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use browserx_core::{BrowserId, BrowserRuntime, Error, LaunchRequest};
use browserx_runtime::{ChromiumRuntime, LaunchProfile, RuntimeConfig};

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn runtime(executable: PathBuf, temp_root: &Path, startup: Duration) -> ChromiumRuntime {
    let mut cfg = RuntimeConfig {
        temp_root: temp_root.to_path_buf(),
        startup_timeout: startup,
        ..RuntimeConfig::default()
    };
    cfg.launch_profiles.insert(
        "default".into(),
        LaunchProfile {
            executable: Some(executable),
            ..LaunchProfile::default()
        },
    );
    ChromiumRuntime::new(cfg).unwrap()
}

fn request() -> LaunchRequest {
    LaunchRequest {
        browser_id: BrowserId::new(),
        launch_profile: None,
        user_data_dir: None,
        proxy_server: None,
        persona_seed: "12345".to_owned(),
    }
}

fn temp_is_empty(root: &Path) -> bool {
    std::fs::read_dir(root).map_or(true, |mut e| e.next().is_none())
}

#[tokio::test]
async fn failed_launches_report_causes_and_leave_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let temp_root = dir.path().join("tmp");

    // Missing executable.
    let rt = runtime(
        dir.path().join("does-not-exist"),
        &temp_root,
        Duration::from_secs(5),
    );
    let err = rt.launch(request()).await.err().unwrap();
    assert!(matches!(err, Error::Browser(_)), "{err:?}");
    assert!(temp_is_empty(&temp_root));

    // Exits immediately and says why on stderr.
    let exe = script(
        dir.path(),
        "crash.sh",
        "echo 'fatal: no display' >&2\nexit 3",
    );
    let rt = runtime(exe, &temp_root, Duration::from_secs(5));
    let err = rt.launch(request()).await.err().unwrap();
    match &err {
        Error::Browser(msg) => assert!(msg.contains("no display"), "{msg}"),
        other => panic!("unexpected {other:?}"),
    }
    assert!(temp_is_empty(&temp_root));

    // Stays alive but never opens a DevTools endpoint: startup timeout, group killed.
    let marker = dir.path().join("pid");
    let exe = script(
        dir.path(),
        "hang.sh",
        &format!("echo $$ > {}\nsleep 600 &\nwait", marker.display()),
    );
    let rt = runtime(exe, &temp_root, Duration::from_millis(800));
    let err = rt.launch(request()).await.err().unwrap();
    assert!(matches!(err, Error::Timeout(_)), "{err:?}");
    let pid = std::fs::read_to_string(&marker).unwrap().trim().to_owned();
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "hung browser must be killed"
    );
    assert!(temp_is_empty(&temp_root));

    // Opens a "DevTools" line pointing at a closed port: connect fails, process killed.
    let exe = script(
        dir.path(),
        "badport.sh",
        "echo 'DevTools listening on ws://127.0.0.1:1/devtools/browser/x' >&2\nsleep 600",
    );
    let rt = runtime(exe, &temp_root, Duration::from_secs(5));
    let err = rt.launch(request()).await.err().unwrap();
    assert!(matches!(err, Error::Browser(_)), "{err:?}");
    assert!(temp_is_empty(&temp_root));

    // Unknown launch profile.
    let rt = runtime(dir.path().join("x"), &temp_root, Duration::from_secs(5));
    let mut req = request();
    req.launch_profile = Some("nope".into());
    assert!(matches!(
        rt.launch(req).await.err().unwrap(),
        Error::InvalidRequest(_)
    ));
}

#[test]
fn profiles_with_managed_flags_are_rejected_at_construction() {
    let mut cfg = RuntimeConfig::default();
    cfg.launch_profiles.insert(
        "default".into(),
        LaunchProfile {
            args: vec!["--remote-debugging-port=9222".into()],
            ..LaunchProfile::default()
        },
    );
    assert!(matches!(
        ChromiumRuntime::new(cfg),
        Err(Error::InvalidRequest(_))
    ));
}
