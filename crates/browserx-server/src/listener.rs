//! A plain-HTTP/1 listener with a request-head read timeout and a connection cap.
//!
//! `axum::serve` has neither, so a client that opens connections and sends
//! nothing (or one byte a second) would hold them forever. Here a connection
//! that does not deliver a complete request head within `header_read_timeout`
//! is closed, and once `max_connections` are open further connections are
//! closed immediately. WebSocket upgrades keep working: the timeout only
//! covers the request head, and an upgraded connection counts until it closes.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Serves `app` on `listener` until `stop` is cancelled, then finishes the
/// requests in flight. Dropping the returned future aborts every connection.
pub(crate) async fn serve_http(
    listener: TcpListener,
    app: Router,
    header_read_timeout: Duration,
    max_connections: usize,
    stop: CancellationToken,
) -> std::io::Result<()> {
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut connections = JoinSet::new();
    loop {
        let (stream, peer) = tokio::select! {
            () = stop.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    // Typically file-descriptor exhaustion: back off instead of spinning.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        while connections.try_join_next().is_some() {}
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            tracing::debug!(%peer, "connection limit reached; closing the new connection");
            continue;
        };
        if let Err(e) = stream.set_nodelay(true) {
            tracing::debug!(%peer, error = %e, "could not set TCP_NODELAY");
        }
        let service = TowerToHyperService::new(app.clone());
        let stop = stop.clone();
        connections.spawn(async move {
            let _permit = permit;
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout)
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            tokio::pin!(connection);
            let outcome = tokio::select! {
                r = connection.as_mut() => r,
                () = stop.cancelled() => {
                    connection.as_mut().graceful_shutdown();
                    connection.await
                }
            };
            if let Err(e) = outcome {
                tracing::debug!(%peer, error = %e, "connection ended with an error");
            }
        });
    }
    while connections.join_next().await.is_some() {}
    Ok(())
}
