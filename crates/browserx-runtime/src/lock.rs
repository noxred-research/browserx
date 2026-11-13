//! Exclusive ownership of a browser profile directory.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use browserx_core::{Error, Result};
use fs4::fs_std::FileExt;

/// File inside the profile directory that carries the lock.
const LOCK_FILE: &str = ".browserx.lock";

/// An exclusive advisory lock on a profile directory, held for as long as the
/// value lives. A profile directory belongs to exactly one browser process; the
/// lock is released on drop (or when the owning process dies).
#[derive(Debug)]
pub struct ProfileLock {
    file: File,
    dir: PathBuf,
}

impl ProfileLock {
    /// Creates `dir` (mode 0700) if needed and takes a non-blocking exclusive
    /// lock on `<dir>/.browserx.lock`. Fails with [`Error::ProfileLocked`] when
    /// another holder has it.
    pub fn acquire(dir: &Path) -> Result<Self> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| Error::Storage(format!("cannot create profile directory: {e}")))?;
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(dir.join(LOCK_FILE))
            .map_err(|e| Error::Storage(format!("cannot open profile lock file: {e}")))?;
        match FileExt::try_lock_exclusive(&file) {
            Ok(true) => Ok(Self {
                file,
                dir: dir.to_path_buf(),
            }),
            Ok(false) => Err(Error::ProfileLocked(dir.display().to_string())),
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                Err(Error::ProfileLocked(dir.display().to_string()))
            }
            Err(err) => Err(Error::Storage(format!(
                "cannot lock profile directory: {err}"
            ))),
        }
    }

    /// The locked directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Drop for ProfileLock {
    fn drop(&mut self) {
        // Closing the descriptor releases the lock regardless; unlocking first
        // just makes the release explicit.
        let _ = FileExt::unlock(&self.file);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn second_acquire_fails_until_the_first_is_dropped() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("profile");
        let first = ProfileLock::acquire(&dir).unwrap();
        assert_eq!(first.dir(), dir);
        assert!(matches!(
            ProfileLock::acquire(&dir),
            Err(Error::ProfileLocked(_))
        ));
        drop(first);
        assert!(ProfileLock::acquire(&dir).is_ok());
    }

    #[test]
    fn directory_is_private() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("nested").join("profile");
        let _lock = ProfileLock::acquire(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn different_directories_do_not_conflict() {
        let root = tempfile::tempdir().unwrap();
        let _a = ProfileLock::acquire(&root.path().join("a")).unwrap();
        let _b = ProfileLock::acquire(&root.path().join("b")).unwrap();
    }
}
