//! Records of launched browsers and cleanup after a crashed worker.
//!
//! Every browser the runtime starts gets a small JSON record,
//! `<temp_root>/<browser_id>.json`, holding the owning worker's identity, the
//! browser's pid / process group / start time and its user-data directory. The
//! record exists before the browser does and is removed once the browser is
//! confirmed gone. If the worker dies without cleaning up, the browsers it
//! launched keep running (they sit in their own process groups); the next
//! worker calls [`sweep`], which kills every leftover that it can *verify* is
//! the recorded browser and removes the temporary directories nobody owns.
//!
//! Verification never trusts a pid alone, because pids are recycled. A process
//! counts as a leftover only if it is in the recorded process group, its
//! command line carries the exact `--user-data-dir=<dir>` argument the browser
//! was started with and, for the group leader, its start time matches the one
//! recorded at launch.

use std::collections::HashSet;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use browserx_core::{BrowserId, Error, Result};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};

/// Largest record file read; real records are a few hundred bytes.
const MAX_RECORD_BYTES: u64 = 16 * 1024;
/// Largest `/proc/<pid>/cmdline` read per process.
const MAX_CMDLINE_BYTES: u64 = 64 * 1024;
/// Prefix of the temporary user-data directories the runtime creates.
pub(crate) const TEMP_DIR_PREFIX: &str = "browserx-";
/// A directory with this prefix and no record is only removed when it is this old,
/// so a launch that is just being set up is never touched.
const STRAY_DIR_MIN_AGE: Duration = Duration::from_secs(10 * 60);
/// How long leftovers get between SIGTERM and SIGKILL.
const SWEEP_GRACE: Duration = Duration::from_secs(3);
const SWEEP_POLL: Duration = Duration::from_millis(50);
const RECORD_VERSION: u32 = 1;

/// What one sweep did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Leftover browser process groups that were killed.
    pub killed: usize,
    /// Stale temporary user-data directories that were removed.
    pub removed_dirs: usize,
}

/// Identity of a running process: its id and its start time in clock ticks since
/// boot (stable for the life of the process, different for a recycled pid).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProcIdentity {
    pub(crate) pid: u32,
    pub(crate) start: u64,
}

impl ProcIdentity {
    /// The identity of `pid` now, or `None` when it does not exist or `/proc` is
    /// unavailable.
    pub(crate) fn of(pid: u32) -> Option<Self> {
        let stat = read_stat(pid)?;
        Some(Self {
            pid,
            start: stat.start,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    version: u32,
    browser_id: String,
    /// The worker process that launched the browser.
    owner: Option<ProcIdentity>,
    /// The browser's process group leader once it is running.
    browser: Option<ProcIdentity>,
    user_data_dir: PathBuf,
    /// Set when the runtime created `user_data_dir` itself and may delete it.
    temp_dir: Option<PathBuf>,
}

/// The on-disk record of one launched browser; removed on drop.
#[derive(Debug)]
pub(crate) struct RecordGuard {
    path: PathBuf,
    record: Record,
}

impl RecordGuard {
    /// Writes the initial record (no browser pid yet) for a launch about to start.
    pub(crate) fn create(
        temp_root: &Path,
        browser_id: BrowserId,
        user_data_dir: &Path,
        temp_dir: Option<&Path>,
    ) -> Result<Self> {
        ensure_private_dir(temp_root)?;
        let guard = Self {
            path: temp_root.join(format!("{browser_id}.json")),
            record: Record {
                version: RECORD_VERSION,
                browser_id: browser_id.to_string(),
                owner: ProcIdentity::of(std::process::id()),
                browser: None,
                user_data_dir: user_data_dir.to_path_buf(),
                temp_dir: temp_dir.map(Path::to_path_buf),
            },
        };
        guard.write()?;
        Ok(guard)
    }

    /// Records the running browser's process.
    pub(crate) fn set_browser(&mut self, pid: u32) -> Result<()> {
        self.record.browser = ProcIdentity::of(pid);
        self.write()
    }

    /// Writes the record atomically (temp file in the same directory, then rename).
    fn write(&self) -> Result<()> {
        let body = serde_json::to_vec(&self.record)
            .map_err(|e| Error::Internal(format!("encode browser record: {e}")))?;
        let tmp = self.path.with_extension("json.tmp");
        let result = (|| -> std::io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(&body)?;
            file.sync_all()?;
            fs::rename(&tmp, &self.path)
        })();
        result.map_err(|e| {
            let _ = fs::remove_file(&tmp);
            Error::Storage(format!("cannot write the browser record: {e}"))
        })
    }

    /// Deletes the record file. Idempotent.
    pub(crate) fn remove(&self) {
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(error = %e, "could not remove a browser record"),
        }
    }
}

impl Drop for RecordGuard {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Creates `dir` (and missing parents) with mode `0700`. An existing directory
/// keeps its mode.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| Error::Storage(format!("cannot create temp root: {e}")))
}

// ---------------------------------------------------------------- /proc

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stat {
    pgrp: u32,
    zombie: bool,
    start: u64,
}

/// Parses `/proc/<pid>/stat`. The command name (field 2) may contain spaces and
/// parentheses, so fields are counted from the last `)`.
fn parse_stat(text: &str) -> Option<Stat> {
    let rest = &text[text.rfind(')')? + 1..];
    let mut fields = rest.split_ascii_whitespace();
    let state = fields.next()?; // field 3
    let _ppid = fields.next()?; // field 4
    let pgrp = fields.next()?.parse().ok()?; // field 5
    // fields 6..=21 sit between pgrp and starttime (field 22)
    let start = fields.nth(16)?.parse().ok()?;
    Some(Stat {
        pgrp,
        zombie: state == "Z" || state == "X",
        start,
    })
}

fn read_stat(pid: u32) -> Option<Stat> {
    parse_stat(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn read_args(pid: u32) -> Vec<Vec<u8>> {
    let Ok(file) = fs::File::open(format!("/proc/{pid}/cmdline")) else {
        return Vec::new();
    };
    let mut raw = Vec::new();
    if file.take(MAX_CMDLINE_BYTES).read_to_end(&mut raw).is_err() {
        return Vec::new();
    }
    raw.split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

#[derive(Clone, Debug)]
struct ProcInfo {
    pid: u32,
    stat: Stat,
    args: Vec<Vec<u8>>,
}

/// A snapshot of the live (non-zombie) process table.
struct ProcTable(Vec<ProcInfo>);

impl ProcTable {
    /// `None` when `/proc` cannot be listed (not Linux, or hidden): sweeping is
    /// then impossible, and nothing may be deleted on the strength of an empty table.
    fn scan() -> Option<Self> {
        let entries = fs::read_dir("/proc").ok()?;
        let mut all = Vec::new();
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            let Some(stat) = read_stat(pid) else { continue };
            if stat.zombie {
                continue;
            }
            all.push(ProcInfo {
                pid,
                stat,
                args: read_args(pid),
            });
        }
        Some(Self(all))
    }

    fn alive(&self, who: ProcIdentity) -> bool {
        self.0
            .iter()
            .any(|p| p.pid == who.pid && p.stat.start == who.start)
    }

    /// Process groups holding a process started with exactly
    /// `--user-data-dir=<dir>`. When the recorded `browser` identity is given, a
    /// process with that pid must also have the recorded start time (a recycled
    /// pid fails this), and only the recorded group counts.
    fn groups_using_dir(&self, dir: &Path, browser: Option<ProcIdentity>) -> HashSet<u32> {
        let mut wanted = b"--user-data-dir=".to_vec();
        wanted.extend_from_slice(dir.as_os_str().as_encoded_bytes());
        self.0
            .iter()
            .filter(|p| p.args.iter().any(|a| carries_arg(a, &wanted)))
            .filter(|p| match browser {
                Some(b) => p.stat.pgrp == b.pid && (p.pid != b.pid || p.stat.start == b.start),
                None => true,
            })
            .map(|p| p.stat.pgrp)
            .collect()
    }
}

/// Whether one `/proc/<pid>/cmdline` entry is, or contains as a whole word, `wanted`.
///
/// Chromium's main process rewrites its own argument area into a single
/// space-separated string, so the exact argument can appear inside a longer
/// entry. The match must sit between spaces (or the ends) of that entry.
fn carries_arg(entry: &[u8], wanted: &[u8]) -> bool {
    if entry == wanted {
        return true;
    }
    entry
        .windows(wanted.len())
        .enumerate()
        .filter(|(_, window)| *window == wanted)
        .any(|(at, _)| {
            let before = at == 0 || entry[at - 1] == b' ';
            let after = entry.get(at + wanted.len()).is_none_or(|b| *b == b' ');
            before && after
        })
}

// ---------------------------------------------------------------- sweep

fn is_safe_temp_dir(root: &Path, dir: &Path) -> bool {
    let named_ours = dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with(TEMP_DIR_PREFIX));
    named_ours
        && dir.parent() == Some(root)
        && fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
}

fn remove_dir_best_effort(dir: &Path) -> bool {
    match fs::remove_dir_all(dir) {
        Ok(()) => true,
        Err(e) if e.kind() == ErrorKind::NotFound => false,
        Err(e) => {
            tracing::warn!(error = %e, "could not remove a stale browser directory");
            false
        }
    }
}

/// SIGTERMs then SIGKILLs the process groups in `groups`; returns how many were
/// signalled successfully. `dir` and `browser` re-verify the processes before
/// the escalation to SIGKILL.
fn kill_groups(
    groups: &HashSet<u32>,
    own_pgrp: u32,
    dir: &Path,
    browser: Option<ProcIdentity>,
) -> usize {
    let mut signalled = 0;
    let targets: Vec<u32> = groups
        .iter()
        .copied()
        .filter(|g| *g > 1 && *g != own_pgrp)
        .collect();
    for group in &targets {
        if send(*group, Signal::SIGTERM) {
            signalled += 1;
        }
    }
    let deadline = std::time::Instant::now() + SWEEP_GRACE;
    loop {
        let still: HashSet<u32> = ProcTable::scan()
            .map(|t| t.groups_using_dir(dir, browser))
            .unwrap_or_default();
        let remaining: Vec<u32> = targets
            .iter()
            .copied()
            .filter(|g| still.contains(g))
            .collect();
        if remaining.is_empty() {
            return signalled;
        }
        if std::time::Instant::now() >= deadline {
            for group in remaining {
                send(group, Signal::SIGKILL);
            }
            // Give the kernel a moment to deliver before the caller deletes files.
            std::thread::sleep(SWEEP_POLL * 4);
            return signalled;
        }
        std::thread::sleep(SWEEP_POLL);
    }
}

fn send(group: u32, signal: Signal) -> bool {
    i32::try_from(group)
        .ok()
        .is_some_and(|raw| killpg(Pid::from_raw(raw), Some(signal)).is_ok())
}

fn read_record(path: &Path) -> Option<Record> {
    let file = fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    // A record we wrote is ours and private; refuse anything else.
    if meta.uid() != nix::unistd::geteuid().as_raw() || meta.mode() & 0o022 != 0 {
        tracing::warn!("ignoring a browser record that is not private to this user");
        return None;
    }
    let mut raw = Vec::new();
    file.take(MAX_RECORD_BYTES).read_to_end(&mut raw).ok()?;
    let record: Record = serde_json::from_slice(&raw).ok()?;
    (record.version == RECORD_VERSION).then_some(record)
}

fn older_than(path: &Path, age: Duration) -> bool {
    fs::symlink_metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|d| d >= age)
}

/// Kills verified leftover browsers and removes stale temporary directories under
/// `temp_root`. Blocking; call from a blocking context.
pub(crate) fn sweep(temp_root: &Path) -> SweepReport {
    sweep_with_age(temp_root, STRAY_DIR_MIN_AGE)
}

fn sweep_with_age(temp_root: &Path, stray_age: Duration) -> SweepReport {
    let mut report = SweepReport::default();
    let Some(table) = ProcTable::scan() else {
        tracing::warn!("cannot read /proc; leftover browsers are not swept");
        return report;
    };
    let entries = match fs::read_dir(temp_root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return report,
        Err(e) => {
            tracing::warn!(error = %e, "cannot list the temp root; leftover browsers are not swept");
            return report;
        }
    };
    let own_pgrp = read_stat(std::process::id()).map_or(0, |s| s.pgrp);

    let mut referenced: HashSet<PathBuf> = HashSet::new();
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let Some(record) = read_record(&path) else {
                continue;
            };
            if record.owner.is_some_and(|owner| table.alive(owner)) {
                // The launching worker still runs (possibly this very process).
                if let Some(dir) = &record.temp_dir {
                    referenced.insert(dir.clone());
                }
                continue;
            }
            if let Some(dir) = &record.temp_dir {
                referenced.insert(dir.clone());
            }
            let groups = table.groups_using_dir(&record.user_data_dir, record.browser);
            report.killed += kill_groups(&groups, own_pgrp, &record.user_data_dir, record.browser);
            if let Some(dir) = &record.temp_dir
                && is_safe_temp_dir(temp_root, dir)
                && remove_dir_best_effort(dir)
            {
                report.removed_dirs += 1;
            }
            if let Err(e) = fs::remove_file(&path) {
                tracing::warn!(error = %e, "could not remove a browser record");
            }
            tracing::info!(browser = %record.browser_id, "swept a leftover browser record");
        } else if path.extension().is_some_and(|e| e == "tmp") && older_than(&path, stray_age) {
            let _ = fs::remove_file(&path);
        } else {
            paths.push(path);
        }
    }

    // Directories no record accounts for: leftovers from builds that wrote none,
    // or from a crash between creating the directory and writing its record.
    for dir in paths {
        if referenced.contains(&dir)
            || !is_safe_temp_dir(temp_root, &dir)
            || !older_than(&dir, stray_age)
        {
            continue;
        }
        let groups = table.groups_using_dir(&dir, None);
        report.killed += kill_groups(&groups, own_pgrp, &dir, None);
        if remove_dir_best_effort(&dir) {
            report.removed_dirs += 1;
        }
    }
    report
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    use super::*;

    /// A stand-in browser: a shell that sleeps, started in its own process group
    /// with the exact argument a real launch carries.
    fn fake_browser(script_dir: &Path, user_data_dir: &Path) -> Child {
        let script = script_dir.join("fake-browser.sh");
        if !script.exists() {
            fs::write(&script, "#!/bin/sh\nsleep 300 &\nwait\n").unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }
        // Retry: writing then executing a script can race with ETXTBSY.
        for _ in 0..20 {
            match Command::new(&script)
                .arg(format!("--user-data-dir={}", user_data_dir.display()))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
            {
                Ok(child) => return child,
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => panic!("spawn: {e}"),
            }
        }
        panic!("script stayed busy");
    }

    fn wait_for_args(pid: u32, dir: &Path) {
        let wanted = format!("--user-data-dir={}", dir.display());
        for _ in 0..100 {
            if read_args(pid)
                .iter()
                .any(|a| a.as_slice() == wanted.as_bytes())
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("process {pid} never showed its arguments");
    }

    fn dead_owner() -> ProcIdentity {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        let identity = ProcIdentity { pid, start: 1 };
        child.wait().unwrap();
        identity
    }

    fn write_record(root: &Path, id: &str, record: &Record) -> PathBuf {
        fs::create_dir_all(root).unwrap();
        let path = root.join(format!("{id}.json"));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&serde_json::to_vec(record).unwrap())
            .unwrap();
        path
    }

    fn record(
        dir: &Path,
        temp: bool,
        browser: Option<ProcIdentity>,
        owner: ProcIdentity,
    ) -> Record {
        Record {
            version: RECORD_VERSION,
            browser_id: "test".into(),
            owner: Some(owner),
            browser,
            user_data_dir: dir.to_path_buf(),
            temp_dir: temp.then(|| dir.to_path_buf()),
        }
    }

    fn gone(pid: u32) -> bool {
        for _ in 0..100 {
            if read_stat(pid).is_none_or(|s| s.zombie) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    #[test]
    fn stat_parsing_survives_hostile_command_names() {
        let line = "123 (a) b (c) S 1 456 456 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 9876543 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        let stat = parse_stat(line).unwrap();
        assert_eq!(stat.pgrp, 456);
        assert_eq!(stat.start, 9_876_543);
        assert!(!stat.zombie);
        assert!(parse_stat(&line.replace(" S ", " Z ")).unwrap().zombie);
        assert!(parse_stat("garbage").is_none());
    }

    #[test]
    fn user_data_dir_argument_is_matched_as_a_whole_word() {
        let wanted = b"--user-data-dir=/tmp/browserx-abc";
        // separate argument, as most processes show it
        assert!(carries_arg(wanted, wanted));
        // Chromium's main process joins its arguments with spaces
        assert!(carries_arg(
            b"/usr/bin/chrome --headless=new --user-data-dir=/tmp/browserx-abc --no-sandbox",
            wanted
        ));
        assert!(carries_arg(
            b"chrome --user-data-dir=/tmp/browserx-abc",
            wanted
        ));
        // a longer directory name or a different flag is not a match
        assert!(!carries_arg(
            b"chrome --user-data-dir=/tmp/browserx-abcd",
            wanted
        ));
        assert!(!carries_arg(
            b"chrome x--user-data-dir=/tmp/browserx-abc",
            wanted
        ));
        assert!(!carries_arg(
            b"chrome --user-data-dir=/tmp/browserx-ab",
            wanted
        ));
    }

    #[test]
    fn own_process_has_an_identity() {
        let me = ProcIdentity::of(std::process::id()).unwrap();
        assert_eq!(me.pid, std::process::id());
        assert!(ProcTable::scan().unwrap().alive(me));
    }

    #[test]
    fn leftover_browser_is_killed_and_its_directory_and_record_removed() {
        let root = tempfile::tempdir().unwrap();
        let tmp = root.path().join("tmp");
        let dir = tmp.join("browserx-orphan1");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("Cookies"), b"x").unwrap();
        let mut child = fake_browser(root.path(), &dir);
        wait_for_args(child.id(), &dir);
        let identity = ProcIdentity::of(child.id()).unwrap();
        let rec = write_record(&tmp, "a", &record(&dir, true, Some(identity), dead_owner()));

        let report = sweep(&tmp);
        assert_eq!(
            report,
            SweepReport {
                killed: 1,
                removed_dirs: 1
            }
        );
        child.wait().unwrap();
        assert!(gone(child.id()));
        assert!(!dir.exists());
        assert!(!rec.exists());
    }

    #[test]
    fn a_recycled_pid_with_a_foreign_command_line_is_left_alone() {
        let root = tempfile::tempdir().unwrap();
        let tmp = root.path().join("tmp");
        let dir = tmp.join("browserx-orphan2");
        fs::create_dir_all(&dir).unwrap();
        // An unrelated process that happens to hold the recorded pid.
        let other = root.path().join("some-other-dir");
        let mut innocent = fake_browser(root.path(), &other);
        wait_for_args(innocent.id(), &other);
        let identity = ProcIdentity::of(innocent.id()).unwrap();
        let rec = write_record(&tmp, "b", &record(&dir, true, Some(identity), dead_owner()));

        let report = sweep(&tmp);
        assert_eq!(
            report,
            SweepReport {
                killed: 0,
                removed_dirs: 1
            }
        );
        assert!(
            read_stat(innocent.id()).is_some_and(|s| !s.zombie),
            "innocent process was killed"
        );
        assert!(!rec.exists());
        innocent.kill().unwrap();
        innocent.wait().unwrap();
    }

    #[test]
    fn a_leader_with_a_different_start_time_is_not_the_recorded_browser() {
        let root = tempfile::tempdir().unwrap();
        let tmp = root.path().join("tmp");
        let dir = tmp.join("browserx-orphan3");
        fs::create_dir_all(&dir).unwrap();
        let mut other = fake_browser(root.path(), &dir);
        wait_for_args(other.id(), &dir);
        let real = ProcIdentity::of(other.id()).unwrap();
        let stale = ProcIdentity {
            start: real.start + 1,
            ..real
        };
        write_record(&tmp, "c", &record(&dir, true, Some(stale), dead_owner()));

        let report = sweep(&tmp);
        assert_eq!(report.killed, 0);
        assert!(read_stat(other.id()).is_some_and(|s| !s.zombie));
        other.kill().unwrap();
        other.wait().unwrap();
    }

    #[test]
    fn records_of_a_live_worker_are_untouched() {
        let root = tempfile::tempdir().unwrap();
        let tmp = root.path().join("tmp");
        let dir = tmp.join("browserx-live");
        fs::create_dir_all(&dir).unwrap();
        let mut child = fake_browser(root.path(), &dir);
        wait_for_args(child.id(), &dir);
        let identity = ProcIdentity::of(child.id()).unwrap();
        let me = ProcIdentity::of(std::process::id()).unwrap();
        let rec = write_record(&tmp, "d", &record(&dir, true, Some(identity), me));

        let report = sweep(&tmp);
        assert_eq!(report, SweepReport::default());
        assert!(rec.exists() && dir.exists());
        assert!(read_stat(child.id()).is_some_and(|s| !s.zombie));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn profile_directories_are_never_deleted() {
        let root = tempfile::tempdir().unwrap();
        let tmp = root.path().join("tmp");
        let profile = root.path().join("profiles").join("p1");
        fs::create_dir_all(&profile).unwrap();
        let mut child = fake_browser(root.path(), &profile);
        wait_for_args(child.id(), &profile);
        let identity = ProcIdentity::of(child.id()).unwrap();
        write_record(
            &tmp,
            "e",
            &record(&profile, false, Some(identity), dead_owner()),
        );

        let report = sweep(&tmp);
        assert_eq!(
            report,
            SweepReport {
                killed: 1,
                removed_dirs: 0
            }
        );
        child.wait().unwrap();
        assert!(profile.exists());
    }

    #[test]
    fn strays_without_a_record_are_removed_only_when_old_and_only_when_ours() {
        let root = tempfile::tempdir().unwrap();
        let tmp = root.path().join("tmp");
        fs::create_dir_all(&tmp).unwrap();
        let stray = tmp.join("browserx-stray");
        let foreign = tmp.join("other-tool");
        for d in [&stray, &foreign] {
            fs::create_dir_all(d).unwrap();
        }
        // fresh: kept
        assert_eq!(sweep(&tmp).removed_dirs, 0);
        assert!(stray.exists());
        // old enough: removed; names without our prefix are never touched
        let report = sweep_with_age(&tmp, Duration::ZERO);
        assert_eq!(report.removed_dirs, 1);
        assert!(!stray.exists());
        assert!(foreign.exists());
    }

    #[test]
    fn a_record_cannot_delete_a_directory_outside_the_temp_root() {
        let root = tempfile::tempdir().unwrap();
        let tmp = root.path().join("tmp");
        let outside = root.path().join("browserx-precious");
        fs::create_dir_all(&outside).unwrap();
        write_record(&tmp, "f", &record(&outside, true, None, dead_owner()));
        let report = sweep(&tmp);
        assert_eq!(report.removed_dirs, 0);
        assert!(outside.exists());
    }

    #[test]
    fn record_guard_writes_private_record_and_removes_it() {
        let root = tempfile::tempdir().unwrap();
        let tmp = root.path().join("tmp");
        let dir = tmp.join("browserx-x");
        let id = BrowserId::new();
        let mut guard = RecordGuard::create(&tmp, id, &dir, Some(&dir)).unwrap();
        guard.set_browser(std::process::id()).unwrap();
        let path = tmp.join(format!("{id}.json"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&tmp).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let parsed = read_record(&path).unwrap();
        assert_eq!(parsed.browser.unwrap().pid, std::process::id());
        assert_eq!(parsed.user_data_dir, dir);
        drop(guard);
        assert!(!path.exists());
    }
}
