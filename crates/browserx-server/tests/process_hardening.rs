//! The worker is non-dumpable after init: other processes of the same user cannot
//! read its environment, and children it starts are ordinary dumpable processes.
//! Own test binary, because the flag is process-wide.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn is_root_or_ptracer() -> bool {
    // Root (or CAP_SYS_PTRACE) reads any /proc/<pid>/environ.
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        .is_some_and(|caps| caps & (1 << 19) != 0)
}

#[test]
fn the_worker_is_non_dumpable_and_its_children_are_not() {
    // A same-user observer can read the environment before the hardening.
    // (Skipped as an assertion when the test runs with CAP_SYS_PTRACE, which
    // reads everything.)
    let me = std::process::id();
    let observer = |pid: u32| {
        Command::new("cat")
            .arg(format!("/proc/{pid}/environ"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    let privileged = is_root_or_ptracer();
    if !privileged {
        assert!(
            observer(me),
            "a same-user process reads the worker's environ before init"
        );
    }

    browserx_server::hardening::harden_process().unwrap();
    assert!(
        !nix::sys::prctl::get_dumpable().unwrap(),
        "still dumpable after init"
    );
    if !privileged {
        assert!(
            !observer(me),
            "a same-user process still reads the worker's environ"
        );
    }
    // What the worker's own bookkeeping reads (the orphan sweep identifies
    // processes through `stat` and `cmdline`) stays world-readable.
    let pid = std::process::id();
    assert!(std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok());
    assert!(std::fs::read(format!("/proc/{pid}/cmdline")).is_ok());

    // `execve` resets the flag: a child (a browser) is dumpable again, so its
    // /proc entries and crash handling behave normally.
    let mut child = Command::new("sleep")
        .arg("30")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        // Wait until the fork has exec'd `sleep`.
        if std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|c| c.trim() == "sleep") {
            break;
        }
        assert!(Instant::now() < deadline, "child did not exec");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        std::fs::read(format!("/proc/{pid}/environ")).is_ok(),
        "a child must be dumpable after exec"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}
