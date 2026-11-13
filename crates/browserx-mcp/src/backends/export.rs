//! Audit export: the fan-out from the hash-chained local log to the enabled sinks.
//!
//! The local file stays authoritative. After a successful append [`Audit::record`] hands the
//! record to [`Exporter::offer`], which never blocks and never fails: every sink has its own
//! bounded queue and a background task that batches, sends with bounded timeouts and retries a
//! failed batch up to [`MAX_RETRIES`] times with exponential back-off before dropping it.
//! Records that do not fit into a full queue, and batches that could not be delivered, are
//! counted per sink ([`SinkStats::dropped`]). Delivery is at-least-once; every exported record
//! carries its `seq` and `hash`, so a receiver can verify the chain and discard duplicates.
//!
//! [`Audit::record`]: crate::audit::Audit::record

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use browserx_core::Secret;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::amqp::{Amqp, AmqpSection};
use super::clickhouse::ClickHouse;
use super::kafka::{Kafka, KafkaSection};
use super::search::Search;
use crate::config::{Config, read_secret};
use crate::error::McpError;

/// How many times a failed batch is sent again before it is dropped.
pub const MAX_RETRIES: u32 = 3;
const BACKOFF_BASE: Duration = Duration::from_millis(200);
const BACKOFF_CAP: Duration = Duration::from_secs(2);
/// The longest error text kept in the statistics.
const MAX_ERROR_CHARS: usize = 300;
/// The largest request body any sink builds.
pub(crate) const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// `[events]`: the event stream the audit log is exported to.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum EventsSection {
    /// Apache Kafka.
    Kafka(KafkaSection),
    /// RabbitMQ (AMQP 0-9-1).
    Amqp(AmqpSection),
    /// No event stream (explicitly off).
    None(NoSink),
}

/// The body of `[events] kind = "none"`: no other key is accepted.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoSink {}

/// Batching and timeout settings shared by every sink.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Tuning {
    pub batch_size: usize,
    pub flush_interval: Duration,
    pub buffer: usize,
    pub request_timeout: Duration,
}

impl Tuning {
    /// Checks the four shared settings of a section.
    pub(crate) fn check(
        section: &str,
        batch_size: usize,
        max_batch: usize,
        flush_interval_ms: u64,
        buffer: usize,
        request_timeout_ms: u64,
    ) -> Result<Self, McpError> {
        if !(1..=max_batch).contains(&batch_size) {
            return Err(bad(format!("{section}.batch_size must be 1..={max_batch}")));
        }
        if !(10..=60_000).contains(&flush_interval_ms) {
            return Err(bad(format!(
                "{section}.flush_interval_ms must be 10..=60000"
            )));
        }
        if !(16..=1_000_000).contains(&buffer) || buffer < batch_size {
            return Err(bad(format!(
                "{section}.buffer must be 16..=1000000 and at least batch_size"
            )));
        }
        if !(100..=120_000).contains(&request_timeout_ms) {
            return Err(bad(format!(
                "{section}.request_timeout_ms must be 100..=120000"
            )));
        }
        Ok(Self {
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            buffer,
            request_timeout: Duration::from_millis(request_timeout_ms),
        })
    }
}

pub(crate) fn bad(message: impl Into<String>) -> McpError {
    McpError::Config(message.into())
}

/// Whether `host` (as `Url::host_str` gives it) is a loopback address or `localhost`.
pub(crate) fn is_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Parses an `http(s)` URL of a section: no credentials, no query, no fragment. Plain `http` to
/// a host that is not loopback needs `allow_plaintext`; `allow_plaintext` is refused where it
/// would change nothing.
pub(crate) fn http_url(
    key: &str,
    raw: &str,
    allow_plaintext: bool,
    tls_ca_file: Option<&Path>,
) -> Result<url::Url, McpError> {
    let parsed = url::Url::parse(raw).map_err(|e| bad(format!("{key}: {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(bad(format!("{key} must be an http(s) URL")));
    }
    let Some(host) = parsed.host_str() else {
        return Err(bad(format!("{key} needs a host")));
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(bad(format!(
            "{key} must not carry credentials: use the section's password_file or the documented environment variable"
        )));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(bad(format!("{key} must not carry a query or a fragment")));
    }
    let plaintext_remote = parsed.scheme() == "http" && !is_loopback(host);
    if plaintext_remote && !allow_plaintext {
        return Err(bad(format!(
            "{key} is plain http to a host that is not loopback: use https or set allow_plaintext = true"
        )));
    }
    if allow_plaintext && !plaintext_remote {
        return Err(bad(format!(
            "allow_plaintext only applies to a plain http URL to a host that is not loopback ({key} is not)"
        )));
    }
    if tls_ca_file.is_some() && parsed.scheme() != "https" {
        return Err(bad(format!(
            "tls_ca_file needs an https URL ({key} is plain http)"
        )));
    }
    Ok(parsed)
}

/// The base URL without a trailing slash.
pub(crate) fn base_of(url: &url::Url) -> String {
    url.as_str().trim_end_matches('/').to_owned()
}

/// A secret from `file`, else from the environment variable `env`; `None` when neither is set.
pub(crate) fn secret_from(file: Option<&Path>, env: &str) -> Result<Option<Secret>, McpError> {
    if let Some(path) = file {
        return read_secret(path).map(Some);
    }
    match std::env::var(env) {
        Ok(value) if !value.trim().is_empty() => Ok(Some(Secret::new(value.trim()))),
        _ => Ok(None),
    }
}

/// The HTTP client of a sink: bounded timeouts, no redirects, a small idle pool, the optional
/// extra root certificates.
pub(crate) fn http_client(
    ca_file: Option<&Path>,
    timeout: Duration,
) -> Result<reqwest::Client, McpError> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(30));
    if let Some(path) = ca_file {
        let pem = std::fs::read(path)
            .map_err(|e| McpError::io(format!("cannot read tls_ca_file {}", path.display()), e))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|e| bad(format!("tls_ca_file {}: {e}", path.display())))?;
        if certs.is_empty() {
            return Err(bad(format!(
                "tls_ca_file {} holds no certificate",
                path.display()
            )));
        }
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder
        .build()
        .map_err(|e| bad(format!("cannot build the HTTP client: {e}")))
}

/// The record fields every sink extracts next to the full record.
pub(crate) struct Extracted {
    pub engagement: String,
    pub operator: String,
    pub reason: String,
    pub action_class: String,
    pub trace_id: String,
}

impl Extracted {
    pub(crate) fn of(record: &Value) -> Self {
        let pick = |key: &str| match record.get("context").and_then(|c| c.get(key)) {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        };
        Self {
            engagement: pick("engagement"),
            operator: pick("operator"),
            reason: pick("reason"),
            action_class: pick("action_class"),
            trace_id: pick("trace_id"),
        }
    }
}

/// Why a send failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SinkError {
    /// Worth trying again: the service is unreachable, slow or overloaded.
    #[error("{0}")]
    Transient(String),
    /// The service refused this batch; trying again changes nothing.
    #[error("{0}")]
    Rejected(String),
    /// The sink must not be used: wrong engine, version or schema.
    #[error("{0}")]
    Fatal(String),
}

/// What a send did, besides failing as a whole.
#[derive(Debug, Default)]
pub(crate) struct Report {
    /// Indices into the batch that failed in a way worth retrying.
    pub retry: Vec<usize>,
    /// How many records the service refused for good.
    pub rejected: usize,
    /// The reason of the retries or rejections.
    pub error: Option<String>,
}

/// One destination.
pub(crate) enum Sink {
    ClickHouse(Box<ClickHouse>),
    Kafka(Box<Kafka>),
    Amqp(Box<Amqp>),
    Search(Box<Search>),
}

impl Sink {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::ClickHouse(_) => "clickhouse",
            Self::Kafka(_) => "kafka",
            Self::Amqp(_) => "amqp",
            Self::Search(s) => s.kind_name(),
        }
    }

    pub(crate) async fn ensure_ready(&mut self) -> Result<(), SinkError> {
        match self {
            Self::ClickHouse(s) => s.ensure_ready().await,
            Self::Kafka(s) => s.ensure_ready().await,
            Self::Amqp(s) => s.ensure_ready().await,
            Self::Search(s) => s.ensure_ready().await,
        }
    }

    pub(crate) async fn send(&mut self, batch: &[Arc<Value>]) -> Result<Report, SinkError> {
        match self {
            Self::ClickHouse(s) => s.send(batch).await,
            Self::Kafka(s) => s.send(batch).await,
            Self::Amqp(s) => s.send(batch).await,
            Self::Search(s) => s.send(batch).await,
        }
    }

    /// Drops connections so that the next attempt starts clean.
    pub(crate) fn reset(&mut self) {
        match self {
            Self::ClickHouse(_) | Self::Search(_) => {}
            Self::Kafka(s) => s.reset(),
            Self::Amqp(s) => s.reset(),
        }
    }
}

const STARTING: u8 = 0;
const READY: u8 = 1;
const UNREACHABLE: u8 = 2;
const FATAL: u8 = 3;

/// Counters of one sink.
#[derive(Default)]
struct Stats {
    sent: AtomicU64,
    dropped: AtomicU64,
    inflight: AtomicU64,
    state: AtomicU8,
    last_error: Mutex<Option<String>>,
}

impl Stats {
    fn set_error(&self, message: &str) {
        let mut text: String = message.chars().take(MAX_ERROR_CHARS).collect();
        text.retain(|c| !c.is_control());
        *self
            .last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(text);
    }

    fn clear_error(&self) {
        *self
            .last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    fn drop_records(&self, count: usize) {
        self.dropped.fetch_add(count as u64, Ordering::Relaxed);
    }
}

/// A snapshot of one sink's counters, as reported by the `capabilities` tool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SinkStats {
    /// `clickhouse`, `kafka`, `amqp`, `opensearch` or `elasticsearch`.
    pub sink: &'static str,
    /// Records the service acknowledged.
    pub sent: u64,
    /// Records dropped: the queue was full, the service refused them or retries ran out.
    pub dropped: u64,
    /// Records waiting in the queue or in the batch being sent.
    pub queued: u64,
    /// The last failure, without secrets; `None` after a successful send.
    pub last_error: Option<String>,
    /// `starting`, `ready`, `unreachable` or `refused`.
    pub state: &'static str,
}

struct Handle {
    name: &'static str,
    tx: mpsc::Sender<Arc<Value>>,
    stats: Arc<Stats>,
}

struct Worker {
    sink: Sink,
    rx: mpsc::Receiver<Arc<Value>>,
    stats: Arc<Stats>,
    tuning: Tuning,
}

/// Fans audit records out to the configured sinks. See the module documentation.
pub struct Exporter {
    handles: Vec<Handle>,
    workers: Mutex<Vec<Worker>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    stop: CancellationToken,
}

impl std::fmt::Debug for Exporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exporter")
            .field(
                "sinks",
                &self.handles.iter().map(|h| h.name).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Exporter {
    /// Builds the sinks the configuration enables, reading their secrets. `None` when no sink
    /// is configured. No connection is made and no runtime is needed until [`Exporter::start`].
    ///
    /// # Errors
    /// When a secret file is unreadable or a client cannot be built.
    pub fn from_config(cfg: &Config) -> Result<Option<Arc<Self>>, McpError> {
        let mut sinks: Vec<(Sink, Tuning)> = Vec::new();
        if let Some(section) = &cfg.analytics {
            let (sink, tuning) = ClickHouse::build(section)?;
            sinks.push((Sink::ClickHouse(Box::new(sink)), tuning));
        }
        match &cfg.events {
            Some(EventsSection::Kafka(section)) => {
                let (sink, tuning) = Kafka::build(section)?;
                sinks.push((Sink::Kafka(Box::new(sink)), tuning));
            }
            Some(EventsSection::Amqp(section)) => {
                let (sink, tuning) = Amqp::build(section)?;
                sinks.push((Sink::Amqp(Box::new(sink)), tuning));
            }
            Some(EventsSection::None(_)) | None => {}
        }
        if let Some(section) = &cfg.search {
            let (sink, tuning) = Search::build(section)?;
            sinks.push((Sink::Search(Box::new(sink)), tuning));
        }
        if sinks.is_empty() {
            return Ok(None);
        }
        let mut handles = Vec::new();
        let mut workers = Vec::new();
        for (sink, tuning) in sinks {
            let (tx, rx) = mpsc::channel(tuning.buffer);
            let stats = Arc::new(Stats::default());
            handles.push(Handle {
                name: sink.name(),
                tx,
                stats: Arc::clone(&stats),
            });
            workers.push(Worker {
                sink,
                rx,
                stats,
                tuning,
            });
        }
        Ok(Some(Arc::new(Self {
            handles,
            workers: Mutex::new(workers),
            tasks: Mutex::new(Vec::new()),
            stop: CancellationToken::new(),
        })))
    }

    /// Hands one audit record (the JSON line as written, with `seq` and `hash`) to every sink.
    /// Never blocks and never fails: a full queue drops the record and counts it.
    pub fn offer(&self, record: &Value) {
        let record = Arc::new(record.clone());
        for handle in &self.handles {
            if handle.tx.try_send(Arc::clone(&record)).is_err() {
                handle.stats.drop_records(1);
            }
        }
    }

    /// Spawns the sender tasks. Needs a running tokio runtime; calling it again does nothing.
    pub fn start(&self) {
        let workers =
            std::mem::take(&mut *self.workers.lock().unwrap_or_else(PoisonError::into_inner));
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        for worker in workers {
            tasks.push(tokio::spawn(run(worker, self.stop.clone())));
        }
    }

    /// The counters of every sink.
    #[must_use]
    pub fn stats(&self) -> Vec<SinkStats> {
        self.handles
            .iter()
            .map(|handle| {
                let stats = &handle.stats;
                let queued = (handle.tx.max_capacity() - handle.tx.capacity()) as u64
                    + stats.inflight.load(Ordering::Relaxed);
                SinkStats {
                    sink: handle.name,
                    sent: stats.sent.load(Ordering::Relaxed),
                    dropped: stats.dropped.load(Ordering::Relaxed),
                    queued,
                    last_error: stats
                        .last_error
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .clone(),
                    state: match stats.state.load(Ordering::Relaxed) {
                        STARTING => "starting",
                        READY => "ready",
                        UNREACHABLE => "unreachable",
                        _ => "refused",
                    },
                }
            })
            .collect()
    }

    /// Waits until every sink has tried to reach its service once (at most `timeout`). A sink
    /// that cannot be used (wrong engine or version, a schema newer than this build) is an
    /// error; a sink that is only unreachable is logged and keeps retrying in the background.
    ///
    /// # Errors
    /// When a sink refuses to run.
    pub async fn preflight(&self, timeout: Duration) -> Result<(), McpError> {
        let deadline = Instant::now() + timeout;
        loop {
            let stats = self.stats();
            if let Some(refused) = stats.iter().find(|s| s.state == "refused") {
                return Err(bad(format!(
                    "export sink {}: {}",
                    refused.sink,
                    refused.last_error.as_deref().unwrap_or("refused")
                )));
            }
            if stats.iter().all(|s| s.state != "starting") || Instant::now() >= deadline {
                for sink in stats.iter().filter(|s| s.state != "ready") {
                    tracing::warn!(
                        sink = sink.sink,
                        error = sink.last_error.as_deref().unwrap_or("not reached yet"),
                        "audit export sink is not reachable; records are buffered and dropped when the buffer is full"
                    );
                }
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Flushes what is queued (one attempt per batch, no retries) and stops the tasks; waits
    /// at most `timeout`.
    pub async fn shutdown(&self, timeout: Duration) {
        self.stop.cancel();
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap_or_else(PoisonError::into_inner));
        let aborts: Vec<_> = tasks.iter().map(JoinHandle::abort_handle).collect();
        let joined = async {
            for task in tasks {
                let _ = task.await;
            }
        };
        if tokio::time::timeout(timeout, joined).await.is_err() {
            for abort in aborts {
                abort.abort();
            }
            tracing::warn!("audit export did not finish flushing before the shutdown deadline");
        }
    }
}

/// The attempt guard: one send may issue several bounded requests.
fn attempt_guard(tuning: &Tuning) -> Duration {
    tuning.request_timeout.saturating_mul(8)
}

async fn prepare(sink: &mut Sink, stats: &Stats, tuning: &Tuning) -> bool {
    let outcome = tokio::time::timeout(attempt_guard(tuning), sink.ensure_ready()).await;
    match outcome {
        Ok(Ok(())) => {
            stats.state.store(READY, Ordering::Relaxed);
            true
        }
        Ok(Err(SinkError::Fatal(message))) => {
            tracing::error!(sink = sink.name(), error = %message, "audit export sink refused to start");
            stats.set_error(&message);
            stats.state.store(FATAL, Ordering::Relaxed);
            false
        }
        Ok(Err(other)) => {
            stats.set_error(&other.to_string());
            stats.state.store(UNREACHABLE, Ordering::Relaxed);
            sink.reset();
            true
        }
        Err(_) => {
            stats.set_error("timed out");
            stats.state.store(UNREACHABLE, Ordering::Relaxed);
            sink.reset();
            true
        }
    }
}

async fn run(mut worker: Worker, stop: CancellationToken) {
    let tuning = worker.tuning;
    if !prepare(&mut worker.sink, &worker.stats, &tuning).await {
        drain_dropped(&mut worker);
        return;
    }
    let mut batch: Vec<Arc<Value>> = Vec::with_capacity(tuning.batch_size);
    loop {
        batch.clear();
        tokio::select! {
            biased;
            () = stop.cancelled() => break,
            first = worker.rx.recv() => match first {
                Some(item) => batch.push(item),
                None => break,
            },
        }
        let deadline = Instant::now() + tuning.flush_interval;
        while batch.len() < tuning.batch_size {
            tokio::select! {
                biased;
                () = stop.cancelled() => break,
                next = tokio::time::timeout_at(deadline, worker.rx.recv()) => match next {
                    Ok(Some(item)) => batch.push(item),
                    Ok(None) | Err(_) => break,
                },
            }
        }
        if !deliver(&mut worker, &batch, &stop, true).await {
            drain_dropped(&mut worker);
            return;
        }
    }
    // Shutdown: send what is left once, without retries.
    worker.rx.close();
    let stop_now = CancellationToken::new();
    stop_now.cancel();
    loop {
        let mut rest: Vec<Arc<Value>> = std::mem::take(&mut batch);
        while rest.len() < tuning.batch_size {
            match worker.rx.try_recv() {
                Ok(item) => rest.push(item),
                Err(_) => break,
            }
        }
        if rest.is_empty() {
            break;
        }
        if !deliver(&mut worker, &rest, &stop_now, false).await {
            drain_dropped(&mut worker);
            break;
        }
    }
}

/// After a refusal: count what is still queued as dropped and close the queue, so that later
/// records are counted as dropped as well.
fn drain_dropped(worker: &mut Worker) {
    worker.rx.close();
    while worker.rx.try_recv().is_ok() {
        worker.stats.drop_records(1);
    }
}

/// Sends `items`; returns `false` when the sink must stop (it was refused).
async fn deliver(
    worker: &mut Worker,
    items: &[Arc<Value>],
    stop: &CancellationToken,
    retry: bool,
) -> bool {
    let Worker {
        sink,
        stats,
        tuning,
        ..
    } = worker;
    let mut pending: Vec<Arc<Value>> = items.to_vec();
    stats
        .inflight
        .store(pending.len() as u64, Ordering::Relaxed);
    let mut attempt = 0_u32;
    let keep_going = loop {
        let guarded = tokio::time::timeout(attempt_guard(tuning), async {
            sink.ensure_ready().await?;
            sink.send(&pending).await
        })
        .await;
        let failure = match guarded {
            Ok(Ok(report)) => {
                let retried = report.retry.len();
                let done = pending.len().saturating_sub(retried + report.rejected);
                stats.sent.fetch_add(done as u64, Ordering::Relaxed);
                stats.drop_records(report.rejected);
                if retried == 0 {
                    stats.state.store(READY, Ordering::Relaxed);
                    if report.rejected == 0 {
                        stats.clear_error();
                    } else if let Some(error) = &report.error {
                        stats.set_error(error);
                    }
                    break true;
                }
                let message = report.error.unwrap_or_else(|| "partial failure".into());
                pending = report
                    .retry
                    .iter()
                    .filter_map(|index| pending.get(*index).cloned())
                    .collect();
                message
            }
            Ok(Err(SinkError::Fatal(message))) => {
                tracing::error!(sink = sink.name(), error = %message, "audit export sink refused");
                stats.set_error(&message);
                stats.state.store(FATAL, Ordering::Relaxed);
                stats.drop_records(pending.len());
                break false;
            }
            Ok(Err(SinkError::Rejected(message))) => {
                stats.set_error(&message);
                stats.drop_records(pending.len());
                break true;
            }
            Ok(Err(SinkError::Transient(message))) => {
                sink.reset();
                message
            }
            Err(_) => {
                sink.reset();
                "timed out".to_owned()
            }
        };
        stats.set_error(&failure);
        stats.state.store(UNREACHABLE, Ordering::Relaxed);
        if !retry || attempt >= MAX_RETRIES {
            stats.drop_records(pending.len());
            break true;
        }
        let backoff = BACKOFF_BASE.saturating_mul(1 << attempt).min(BACKOFF_CAP);
        attempt += 1;
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            () = stop.cancelled() => {
                stats.drop_records(pending.len());
                break true;
            }
        }
    };
    stats.inflight.store(0, Ordering::Relaxed);
    keep_going
}

/// Splits `batch` into runs of indices whose serialized size stays under `limit`. A record that
/// is larger than `limit` on its own is reported in the second list.
pub(crate) fn chunk_indices(sizes: &[usize], limit: usize) -> (Vec<Vec<usize>>, Vec<usize>) {
    let mut chunks: Vec<Vec<usize>> = Vec::new();
    let mut oversize = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    let mut bytes = 0_usize;
    for (index, size) in sizes.iter().enumerate() {
        if *size > limit {
            oversize.push(index);
            continue;
        }
        if bytes + size > limit && !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
            bytes = 0;
        }
        current.push(index);
        bytes += size;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    (chunks, oversize)
}

/// The text of an HTTP error body, trimmed to one short line.
pub(crate) fn short(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .chars()
        .take(MAX_ERROR_CHARS)
        .collect()
}

/// The path of a section's file, made absolute against `base`.
pub(crate) fn resolve(path: &mut PathBuf, base: &Path) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}

impl Config {
    /// Makes the export sections' file paths absolute.
    pub(crate) fn resolve_export(&mut self, base: &Path) {
        if let Some(section) = &mut self.analytics {
            section.resolve(base);
        }
        match &mut self.events {
            Some(EventsSection::Kafka(section)) => section.resolve(base),
            Some(EventsSection::Amqp(section)) => section.resolve(base),
            Some(EventsSection::None(_)) | None => {}
        }
        if let Some(section) = &mut self.search {
            section.resolve(base);
        }
    }

    /// Checks the export sections: shapes, ranges and combinations that cannot work.
    pub(crate) fn validate_export(&self) -> Result<(), McpError> {
        if let Some(section) = &self.analytics {
            section.validate()?;
        }
        match &self.events {
            Some(EventsSection::Kafka(section)) => section.validate()?,
            Some(EventsSection::Amqp(section)) => section.validate()?,
            Some(EventsSection::None(_)) | None => {}
        }
        if let Some(section) = &self.search {
            section.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn chunks_respect_the_limit_and_report_oversize_records() {
        let (chunks, oversize) = chunk_indices(&[40, 40, 40, 500, 10], 100);
        assert_eq!(chunks, vec![vec![0, 1], vec![2, 4]]);
        assert_eq!(oversize, vec![3]);
        assert_eq!(chunk_indices(&[], 10), (Vec::new(), Vec::new()));
    }

    #[test]
    fn extracted_fields_come_from_the_context() {
        let record = serde_json::json!({"context": {"engagement": "E1", "operator": "a",
            "reason": "out_of_scope", "action_class": "read", "trace_id": 7}});
        let e = Extracted::of(&record);
        assert_eq!(
            (
                e.engagement.as_str(),
                e.operator.as_str(),
                e.reason.as_str()
            ),
            ("E1", "a", "out_of_scope")
        );
        assert_eq!(
            (e.action_class.as_str(), e.trace_id.as_str()),
            ("read", "7")
        );
        assert_eq!(Extracted::of(&serde_json::json!({})).engagement, "");
    }

    #[test]
    fn urls_are_checked() {
        let loopback = http_url("k", "http://127.0.0.1:8123", false, None).unwrap();
        assert_eq!(base_of(&loopback), "http://127.0.0.1:8123");
        assert!(http_url("k", "http://clickhouse:8123", false, None).is_err());
        assert!(http_url("k", "http://clickhouse:8123", true, None).is_ok());
        assert!(http_url("k", "https://clickhouse:8443", true, None).is_err());
        assert!(http_url("k", "http://127.0.0.1:8123", true, None).is_err());
        assert!(http_url("k", "https://user:pw@host", false, None).is_err());
        assert!(http_url("k", "https://host/?a=1", false, None).is_err());
        assert!(http_url("k", "ftp://host", false, None).is_err());
        assert!(http_url("k", "http://localhost:1", false, Some(Path::new("ca.pem"))).is_err());
    }

    #[test]
    fn tuning_is_bounded() {
        assert!(Tuning::check("s", 500, 1000, 1000, 10_000, 5000).is_ok());
        assert!(Tuning::check("s", 0, 1000, 1000, 10_000, 5000).is_err());
        assert!(Tuning::check("s", 2000, 1000, 1000, 10_000, 5000).is_err());
        assert!(Tuning::check("s", 500, 1000, 1, 10_000, 5000).is_err());
        assert!(Tuning::check("s", 500, 1000, 1000, 100, 5000).is_err());
        assert!(Tuning::check("s", 500, 1000, 1000, 10_000, 5).is_err());
    }
}
