//! Wiring: build the pool from a [`Config`], bind listeners, serve, shut down.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use browserx_core::{Error, Result, SessionId, SystemClock};
use browserx_core::{LeaseStore, SnapshotStore};
use browserx_pool::Pool;
use browserx_runtime::{ChromiumRuntime, discover_chromium};
use browserx_store::{
    Engine, FileSnapshotStore, MariaDbLeaseStore, PostgresLeaseStore, S3SnapshotStore, Sealer,
    SqliteLeaseStore,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::api::{AppState, ReadyProbe, api_router};
use crate::auth::Authenticator;
use crate::config::Config;
use crate::listener::serve_http;
use crate::ops::ops_router;

/// How long open requests get to finish after a shutdown signal.
const GRACEFUL_WINDOW: Duration = Duration::from_secs(15);

fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| Error::Storage(format!("create {}: {e}", path.display())))
}

/// Download directories belong to sessions of a previous run; start empty.
fn reset_downloads_dir(path: &Path) -> Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::Storage(format!("clear {}: {e}", path.display()))),
    }
    create_private_dir(path)
}

fn load_sealer(cfg: &Config) -> Result<Sealer> {
    let key = &cfg.storage.snapshot_key_file;
    if !key.exists() {
        return Err(Error::Crypto(format!(
            "snapshot key file {} does not exist; create it with `browserx snapshot-key new {}`",
            key.display(),
            key.display()
        )));
    }
    let mut sealer = Sealer::from_key_file(key)?;
    for retired in &cfg.storage.retired_snapshot_key_files {
        sealer.add_retired_key_file(retired)?;
    }
    Ok(sealer)
}

/// Opens the configured lease registry and reads from it once: the check `browserx doctor`
/// runs, and what `/readyz` repeats while serving.
pub async fn ping_lease_registry(cfg: &Config) -> Result<()> {
    let leases = open_lease_store(cfg).await?;
    leases.get(SessionId::new()).await.map(|_| ())
}

/// Opens the lease registry the configuration names: SQLite in `state_dir` by default.
async fn open_lease_store(cfg: &Config) -> Result<Arc<dyn LeaseStore>> {
    let Some(database) = &cfg.database else {
        return Ok(Arc::new(SqliteLeaseStore::open(&cfg.storage.db_path())?));
    };
    let clock = Arc::new(SystemClock);
    match database.engine()? {
        Engine::Sqlite => {
            let path = database
                .sqlite_path()
                .unwrap_or_else(|| cfg.storage.db_path());
            Ok(Arc::new(SqliteLeaseStore::open(&path)?))
        }
        Engine::Postgres => {
            let store = PostgresLeaseStore::connect(database, clock).await?;
            tracing::info!(engine = "postgresql", "lease registry connected");
            Ok(Arc::new(store))
        }
        Engine::MariaDb => {
            let store = MariaDbLeaseStore::connect(database, clock).await?;
            tracing::info!(engine = "mariadb", "lease registry connected");
            Ok(Arc::new(store))
        }
    }
}

/// Opens the snapshot store the configuration names: files in `state_dir` by default.
async fn open_snapshot_store(cfg: &Config) -> Result<Arc<dyn SnapshotStore>> {
    let Some(object_store) = &cfg.object_store else {
        return Ok(Arc::new(FileSnapshotStore::new(
            cfg.storage.snapshots_dir(),
        )?));
    };
    let store = S3SnapshotStore::connect(object_store)?;
    store.ping().await?;
    tracing::info!(store = %store.profile_summary(), "snapshot store connected");
    Ok(Arc::new(store))
}

/// Builds the scheduler and the HTTP state from a validated configuration.
///
/// Leftovers of a previous worker (browsers, scratch directories, session
/// download directories) are swept before anything launches.
pub async fn build(cfg: &Config) -> Result<(Pool, AppState)> {
    let storage = &cfg.storage;
    let mut dirs = vec![
        storage.state_dir.clone(),
        storage.profiles_dir(),
        storage.temp_dir(),
    ];
    if cfg.object_store.is_none() {
        dirs.push(storage.snapshots_dir());
    }
    for dir in &dirs {
        create_private_dir(dir)?;
    }
    reset_downloads_dir(&storage.downloads_dir())?;
    let mut runtime_cfg = cfg.runtime.clone();
    runtime_cfg.temp_root = storage.temp_dir();
    let runtime = ChromiumRuntime::new(runtime_cfg.clone())?;
    let report = runtime.sweep_orphans().await?;
    tracing::info!(
        killed = report.killed,
        removed_dirs = report.removed_dirs,
        "swept leftover browsers"
    );
    let leases = open_lease_store(cfg).await?;
    let snapshots = open_snapshot_store(cfg).await?;
    let sealer = load_sealer(cfg)?;
    let pool = Pool::new(
        cfg.pool_config()?,
        Arc::new(runtime),
        leases,
        snapshots,
        Arc::new(sealer),
        Arc::new(SystemClock),
        cfg.egress.clone(),
        storage.profiles_dir(),
    )?;
    let default_profile = runtime_cfg.default_launch_profile.clone();
    let executable = runtime_cfg
        .launch_profiles
        .get(&default_profile)
        .and_then(|p| p.executable.clone());
    let ready: ReadyProbe = Arc::new(move || match &executable {
        Some(path) if !path.is_file() => {
            Err(format!("browser executable {} not found", path.display()))
        }
        Some(_) => Ok(()),
        None if discover_chromium().is_none() => Err(
            "no Chromium found (set BROWSERX_CHROMIUM_PATH or the launch profile executable)"
                .into(),
        ),
        None => Ok(()),
    });
    let state = AppState::new(
        pool.clone(),
        Authenticator::new(&cfg.auth.api_keys)?,
        &cfg.server.public_base_url,
        default_profile,
        ready,
    )?;
    state.set_limits(cfg.server_limits()?);
    Ok((pool, state))
}

/// Serves the API and operations listeners until `shutdown` resolves, then
/// drains: stops admission, closes relays, finishes open requests, and stops
/// every browser with confirmation.
pub async fn serve(
    state: AppState,
    api: TcpListener,
    ops: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let api_stop = CancellationToken::new();
    let ops_stop = CancellationToken::new();
    let limits = state.limits();
    let mut api_task = tokio::spawn(serve_http(
        api,
        api_router(state.clone()),
        limits.header_read_timeout,
        limits.max_connections,
        api_stop.clone(),
    ));
    let mut ops_task = tokio::spawn(serve_http(
        ops,
        ops_router(state.clone()),
        limits.header_read_timeout,
        limits.ops_max_connections,
        ops_stop.clone(),
    ));

    let mut failure: Option<Error> = None;
    tokio::select! {
        () = shutdown => {}
        r = &mut api_task => failure = Some(task_error("api listener", r)),
        r = &mut ops_task => failure = Some(task_error("operations listener", r)),
    }

    tracing::info!("shutting down: stopping admission and closing relays");
    state.pool().stop_admission();
    state.close_relays();
    api_stop.cancel();
    if tokio::time::timeout(GRACEFUL_WINDOW, &mut api_task)
        .await
        .is_err()
    {
        tracing::warn!("open requests did not finish in time; dropping them");
        api_task.abort();
    }
    state.pool().shutdown().await;
    ops_stop.cancel();
    if tokio::time::timeout(Duration::from_secs(5), &mut ops_task)
        .await
        .is_err()
    {
        ops_task.abort();
    }
    tracing::info!("shutdown complete");
    failure.map_or(Ok(()), Err)
}

fn task_error(
    what: &str,
    result: std::result::Result<std::io::Result<()>, tokio::task::JoinError>,
) -> Error {
    match result {
        Ok(Ok(())) => Error::Internal(format!("{what} stopped unexpectedly")),
        Ok(Err(e)) => Error::Internal(format!("{what} failed: {e}")),
        Err(e) => Error::Internal(format!("{what} task failed: {e}")),
    }
}

/// Runs a server from configuration until `shutdown` resolves.
pub async fn run(cfg: Config, shutdown: impl Future<Output = ()> + Send + 'static) -> Result<()> {
    crate::hardening::harden_process()?;
    let (pool, state) = build(&cfg).await?;
    let bind = |what: &'static str, addr: std::net::SocketAddr| async move {
        TcpListener::bind(addr)
            .await
            .map_err(|e| Error::Internal(format!("cannot bind {what} {addr}: {e}")))
    };
    let api = bind("listen", cfg.listen_addr()?).await?;
    let ops = bind("ops_listen", cfg.ops_addr()?).await?;
    for (what, addr) in [("api", api.local_addr()), ("ops", ops.local_addr())] {
        if let Ok(addr) = addr
            && !addr.ip().is_loopback()
        {
            tracing::warn!(
                listener = what,
                %addr,
                "listening on a non-loopback address: terminate TLS and restrict access in front of BrowserX"
            );
        }
    }
    pool.start().await?;
    tracing::info!(
        api = %cfg.server.listen,
        ops = %cfg.server.ops_listen,
        worker = %pool.worker_id(),
        "browserx is serving"
    );
    serve(state, api, ops, shutdown).await
}

/// Resolves on SIGINT or SIGTERM.
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let term = signal(SignalKind::terminate());
    let int = signal(SignalKind::interrupt());
    match (term, int) {
        (Ok(mut term), Ok(mut int)) => {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
        }
        _ => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use browserx_core::{Generation, ProfileId, SessionId, SnapshotMeta, StateSnapshot};
    use time::OffsetDateTime;

    use super::*;

    const AUTH: &str = "[[auth.api_keys]]\nname = \"dev\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n";

    fn snapshot_with(sealer: &Sealer) -> browserx_core::Snapshot {
        let meta = SnapshotMeta {
            profile_id: ProfileId::new(),
            version: 1,
            session_id: SessionId::new(),
            generation: Generation(1),
            created_at: OffsetDateTime::UNIX_EPOCH,
            size: 0,
            key_id: String::new(),
        };
        sealer.seal(meta, &StateSnapshot::default()).unwrap()
    }

    /// `[storage] retired_snapshot_key_files` reaches the sealer the worker opens snapshots with.
    #[test]
    fn configured_retired_key_files_open_old_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let keys = dir.path().join("keys");
        let (old_key, new_key) = (keys.join("old.key"), keys.join("new.key"));
        Sealer::generate_key_file(&old_key).unwrap();
        Sealer::generate_key_file(&new_key).unwrap();
        let old = Sealer::from_key_file(&old_key).unwrap();
        let old_id = old.key_id().to_owned();
        let sealed_before_rotation = snapshot_with(&old);

        let config = |retired: &str| {
            Config::from_toml(&format!(
                "{AUTH}[storage]\nstate_dir = {state:?}\nsnapshot_key_file = {new_key:?}\nretired_snapshot_key_files = [{retired}]\n",
                state = state.display().to_string(),
                new_key = new_key.display().to_string(),
            ))
            .unwrap()
        };

        let sealer = load_sealer(&config(&format!("{:?}", old_key.display().to_string()))).unwrap();
        assert!(sealer.open(&sealed_before_rotation).is_ok());
        let fresh = snapshot_with(&sealer);
        assert_ne!(fresh.meta.key_id, old_id, "a retired key never seals");

        // Retired key left out of the configuration: refused, and the error names its key id.
        let err = load_sealer(&config(""))
            .unwrap()
            .open(&sealed_before_rotation)
            .unwrap_err();
        assert!(matches!(&err, Error::Crypto(m) if *m == format!("unknown key_id {old_id}")));

        // A retired key file that does not exist stops startup instead of being skipped.
        let missing = keys.join("missing.key");
        assert!(load_sealer(&config(&format!("{:?}", missing.display().to_string()))).is_err());
        // The active key listed as retired is a duplicate key id.
        assert!(load_sealer(&config(&format!("{:?}", new_key.display().to_string()))).is_err());
    }
}
