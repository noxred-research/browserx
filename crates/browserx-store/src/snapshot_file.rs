//! Snapshot storage on the local filesystem.
//!
//! Layout under the root directory:
//!
//! ```text
//! <root>/<profile id>/<version:020>.snap       sealed bytes
//! <root>/<profile id>/<version:020>.meta.json  SnapshotMeta
//! ```
//!
//! Every file is written to a temporary name in the same directory, fsynced,
//! then renamed; the directory is fsynced afterwards. The `.snap` file is
//! renamed before the `.meta.json`, which acts as the commit marker: a version
//! without metadata does not exist. Files are created with mode `0600` and
//! directories with `0700`.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use browserx_core::{Error, ProfileId, Result, Snapshot, SnapshotMeta, SnapshotStore};
use rand::Rng;

use crate::MAX_SEALED_BYTES;
use crate::common::check_put;

const META_SUFFIX: &str = ".meta.json";
const SNAP_SUFFIX: &str = ".snap";
const META_MAX_BYTES: u64 = 64 * 1024;

fn io_err(what: &str, e: &io::Error) -> Error {
    Error::Storage(format!("{what}: {e}"))
}

/// A [`SnapshotStore`] writing sealed snapshots under a directory.
///
/// Mutating and reading operations are serialized within the process. The
/// directory must be owned by one worker process at a time.
#[derive(Clone)]
pub struct FileSnapshotStore {
    root: Arc<PathBuf>,
    lock: Arc<Mutex<()>>,
}

impl FileSnapshotStore {
    /// Opens (creating with mode `0700` if needed) the snapshot root directory.
    pub fn new(dir: PathBuf) -> Result<Self> {
        create_private_dir(&dir).map_err(|e| io_err("create snapshot directory", &e))?;
        Ok(Self {
            root: Arc::new(dir),
            lock: Arc::new(Mutex::new(())),
        })
    }

    async fn run<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Path) -> Result<T> + Send + 'static,
    {
        let root = Arc::clone(&self.root);
        let lock = Arc::clone(&self.lock);
        tokio::task::spawn_blocking(move || {
            let _guard = lock
                .lock()
                .map_err(|_| Error::Internal("snapshot store lock poisoned".into()))?;
            f(&root)
        })
        .await
        .map_err(|e| Error::Internal(format!("storage task failed: {e}")))?
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

fn file_stem(version: u64) -> String {
    format!("{version:020}")
}

/// Writes `bytes` to `path` atomically with mode `0600`.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("snapshot");
    let tmp = path.with_file_name(format!(".{name}.tmp-{:016x}", rand::rng().next_u64()));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|e| io_err("open snapshot file", &e))?;
    let mut buf = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| io_err("read snapshot file", &e))?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max {
        return Err(Error::Storage(
            "snapshot file exceeds its size limit".into(),
        ));
    }
    Ok(buf)
}

/// Committed versions of a profile, ascending. A missing directory is empty.
fn versions(dir: &Path) -> Result<Vec<u64>> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err("list snapshot directory", &e)),
    };
    let mut out = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|e| io_err("list snapshot directory", &e))?;
        let name = entry.file_name();
        if let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(META_SUFFIX))
            && let Ok(v) = stem.parse::<u64>()
        {
            out.insert(v);
        }
    }
    Ok(out.into_iter().collect())
}

fn read_meta(dir: &Path, profile: ProfileId, version: u64) -> Result<SnapshotMeta> {
    let bytes = read_bounded(
        &dir.join(format!("{}{META_SUFFIX}", file_stem(version))),
        META_MAX_BYTES,
    )?;
    let meta: SnapshotMeta = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Storage(format!("corrupt snapshot metadata v{version}: {e}")))?;
    if meta.version != version || meta.profile_id != profile {
        return Err(Error::Storage(format!(
            "snapshot metadata v{version} does not match its location"
        )));
    }
    Ok(meta)
}

fn read_snapshot(dir: &Path, profile: ProfileId, version: u64) -> Result<Snapshot> {
    let meta = read_meta(dir, profile, version)?;
    let max = u64::try_from(MAX_SEALED_BYTES).unwrap_or(u64::MAX);
    let sealed = read_bounded(
        &dir.join(format!("{}{SNAP_SUFFIX}", file_stem(version))),
        max,
    )?;
    if u64::try_from(sealed.len()).ok() != Some(meta.size) {
        return Err(Error::Storage(format!(
            "snapshot v{version} length does not match its metadata"
        )));
    }
    Ok(Snapshot { meta, sealed })
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err("remove snapshot file", &e)),
    }
}

#[async_trait]
impl SnapshotStore for FileSnapshotStore {
    async fn put(&self, snapshot: &Snapshot) -> Result<()> {
        check_put(snapshot)?;
        let snapshot = snapshot.clone();
        self.run(move |root| {
            let profile = snapshot.meta.profile_id;
            let version = snapshot.meta.version;
            let dir = root.join(profile.prefixed());
            if let Some(&newest) = versions(&dir)?.last()
                && version <= newest
            {
                return Err(Error::Conflict(format!(
                    "snapshot version {version} is not newer than stored version {newest}"
                )));
            }
            let fresh = !dir.exists();
            create_private_dir(&dir).map_err(|e| io_err("create profile directory", &e))?;
            let meta = serde_json::to_vec(&snapshot.meta)
                .map_err(|e| Error::Internal(format!("encode snapshot metadata: {e}")))?;
            let stem = file_stem(version);
            write_atomic(&dir.join(format!("{stem}{SNAP_SUFFIX}")), &snapshot.sealed)
                .map_err(|e| io_err("write snapshot", &e))?;
            write_atomic(&dir.join(format!("{stem}{META_SUFFIX}")), &meta)
                .map_err(|e| io_err("write snapshot metadata", &e))?;
            sync_dir(&dir).map_err(|e| io_err("sync profile directory", &e))?;
            if fresh {
                sync_dir(root).map_err(|e| io_err("sync snapshot root", &e))?;
            }
            Ok(())
        })
        .await
    }

    async fn latest(&self, profile: ProfileId) -> Result<Option<Snapshot>> {
        self.run(move |root| {
            let dir = root.join(profile.prefixed());
            match versions(&dir)?.last() {
                Some(&v) => read_snapshot(&dir, profile, v).map(Some),
                None => Ok(None),
            }
        })
        .await
    }

    async fn list(&self, profile: ProfileId) -> Result<Vec<SnapshotMeta>> {
        self.run(move |root| {
            let dir = root.join(profile.prefixed());
            versions(&dir)?
                .into_iter()
                .rev()
                .map(|v| read_meta(&dir, profile, v))
                .collect()
        })
        .await
    }

    async fn prune(&self, profile: ProfileId, keep: usize) -> Result<u64> {
        self.run(move |root| {
            let dir = root.join(profile.prefixed());
            let all = versions(&dir)?;
            let excess = all.len().saturating_sub(keep);
            for v in all.iter().take(excess) {
                // Metadata first: without it the version no longer exists.
                remove_if_present(&dir.join(format!("{}{META_SUFFIX}", file_stem(*v))))?;
                remove_if_present(&dir.join(format!("{}{SNAP_SUFFIX}", file_stem(*v))))?;
            }
            sweep_leftovers(&dir, &all[excess..])?;
            if excess > 0 {
                sync_dir(&dir).map_err(|e| io_err("sync profile directory", &e))?;
            }
            Ok(u64::try_from(excess).unwrap_or(u64::MAX))
        })
        .await
    }

    async fn delete_profile(&self, profile: ProfileId) -> Result<u64> {
        self.run(move |root| {
            let dir = root.join(profile.prefixed());
            let count = versions(&dir)?.len();
            match fs::remove_dir_all(&dir) {
                Ok(()) => sync_dir(root).map_err(|e| io_err("sync snapshot root", &e))?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_err("delete profile snapshots", &e)),
            }
            Ok(u64::try_from(count).unwrap_or(u64::MAX))
        })
        .await
    }
}

/// Removes temporary files and payloads whose metadata commit never happened.
fn sweep_leftovers(dir: &Path, retained: &[u64]) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_err("list snapshot directory", &e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| io_err("list snapshot directory", &e))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let orphan_payload = name
            .strip_suffix(SNAP_SUFFIX)
            .and_then(|stem| stem.parse::<u64>().ok())
            .is_some_and(|v| !retained.contains(&v));
        if orphan_payload || name.contains(".tmp-") {
            remove_if_present(&entry.path())?;
        }
    }
    Ok(())
}
