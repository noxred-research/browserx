//! Wiring: build the pool from a [`Config`], bind listeners, serve, shut down.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use browserx_core::{Error, Result, SystemClock};
use browserx_pool::Pool;
use browserx_runtime::{ChromiumRuntime, discover_chromium};
use browserx_store::{FileSnapshotStore, Sealer, SqliteLeaseStore};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::api::{AppState, ReadyProbe, api_router};
use crate::auth::Authenticator;
use crate::config::Config;
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

/// Builds the scheduler and the HTTP state from a validated configuration.
pub fn build(cfg: &Config) -> Result<(Pool, AppState)> {
    let storage = &cfg.storage;
    for dir in [
        &storage.state_dir,
        &storage.snapshots_dir(),
        &storage.profiles_dir(),
        &storage.temp_dir(),
    ] {
        create_private_dir(dir)?;
    }
    let mut runtime_cfg = cfg.runtime.clone();
    runtime_cfg.temp_root = storage.temp_dir();
    let runtime = ChromiumRuntime::new(runtime_cfg.clone())?;
    let leases = SqliteLeaseStore::open(&storage.db_path())?;
    let snapshots = FileSnapshotStore::new(storage.snapshots_dir())?;
    let sealer = load_sealer(cfg)?;
    let pool = Pool::new(
        cfg.pool_config()?,
        Arc::new(runtime),
        Arc::new(leases),
        Arc::new(snapshots),
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
    let api_server = axum::serve(api, api_router(state.clone()))
        .with_graceful_shutdown(api_stop.clone().cancelled_owned());
    let ops_server = axum::serve(ops, ops_router(state.clone()))
        .with_graceful_shutdown(ops_stop.clone().cancelled_owned());
    let mut api_task = tokio::spawn(async move { api_server.await });
    let mut ops_task = tokio::spawn(async move { ops_server.await });

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
    let (pool, state) = build(&cfg)?;
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
