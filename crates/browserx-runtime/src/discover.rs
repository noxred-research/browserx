//! Finding a Chromium executable.

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Environment variable that names the browser executable explicitly.
const ENV_VAR: &str = "BROWSERX_CHROMIUM_PATH";
/// Executable names searched on `PATH`, in order.
const CANDIDATES: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
];

/// Finds a Chromium-family executable.
///
/// `BROWSERX_CHROMIUM_PATH` wins when it points at an executable file; otherwise
/// the well-known names are searched on `PATH`. Returns `None` when nothing is found.
#[must_use]
pub fn discover_chromium() -> Option<PathBuf> {
    let explicit = std::env::var_os(ENV_VAR);
    let path = std::env::var_os("PATH");
    discover_in(explicit.as_deref(), path.as_deref())
}

pub(crate) fn discover_in(explicit: Option<&OsStr>, path_var: Option<&OsStr>) -> Option<PathBuf> {
    if let Some(explicit) = explicit.filter(|v| !v.is_empty()) {
        let candidate = PathBuf::from(explicit);
        if is_executable(&candidate) {
            return Some(candidate);
        }
        tracing::warn!("{ENV_VAR} does not point at an executable file; searching PATH instead");
    }
    let path_var = path_var?;
    for dir in std::env::split_paths(path_var) {
        for name in CANDIDATES {
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::ffi::OsString;

    use super::*;

    fn make_exec(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn explicit_path_wins() {
        let dir = tempfile::tempdir().unwrap();
        let chosen = make_exec(dir.path(), "my-browser", 0o755);
        make_exec(dir.path(), "chromium", 0o755);
        let found = discover_in(Some(chosen.as_os_str()), Some(dir.path().as_os_str()));
        assert_eq!(found, Some(chosen));
    }

    #[test]
    fn path_search_follows_candidate_order_and_needs_exec_bit() {
        let dir = tempfile::tempdir().unwrap();
        make_exec(dir.path(), "chromium", 0o644);
        let chrome = make_exec(dir.path(), "google-chrome", 0o755);
        make_exec(dir.path(), "chrome", 0o755);
        assert_eq!(
            discover_in(None, Some(dir.path().as_os_str())),
            Some(chrome)
        );
    }

    #[test]
    fn invalid_explicit_path_falls_back_to_path() {
        let dir = tempfile::tempdir().unwrap();
        let chromium = make_exec(dir.path(), "chromium-browser", 0o755);
        let bogus = OsString::from("/nonexistent/browser");
        assert_eq!(
            discover_in(Some(bogus.as_os_str()), Some(dir.path().as_os_str())),
            Some(chromium)
        );
    }

    #[test]
    fn nothing_found_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(discover_in(None, Some(dir.path().as_os_str())), None);
        assert_eq!(discover_in(None, None), None);
    }
}
