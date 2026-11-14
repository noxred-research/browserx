//! Shared rate limits and engagement call budgets in Valkey or Redis (`[cache]`).
//!
//! One MCP server keeps its limits in memory. Several servers in front of one worker need one
//! shared counter, or the limit is multiplied by the number of servers. This module holds that
//! counter. Both engines speak the same protocol; every command used here exists in both.
//!
//! * Per-tool calls per minute: a sorted set `<prefix>rl:<tool>` per tool, checked and updated
//!   by one Lua script that reads the server clock (`TIME`), so servers with different clocks
//!   agree.
//! * Engagement budgets: `<prefix>eng:<id>:calls` counts calls (`limits.max_calls`) and a
//!   one-second sorted set `<prefix>eng:<id>:rps` limits their rate (`limits.rps`), both in one
//!   script.
//!
//! The cache never relaxes a limit. When it is unreachable, slow or answers something
//! unexpected, the caller falls back to the in-memory limiter, the state becomes `degraded`, the
//! transition is logged once and every fallback is counted. The next successful command clears
//! the state. While degraded, one caller per second probes the cache and everyone else goes
//! straight to the fallback, so an outage costs one slow call per second, not one per call.
//!
//! Only keys that start with the configured prefix are read, written or deleted. The one scan
//! (`clear_namespace`) is `SCAN MATCH <prefix>*`, never `KEYS`, `FLUSHDB` or `FLUSHALL`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use browserx_core::Secret;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{Client, ConnectionInfo, FromRedisValue, IntoConnectionInfo, RedisConnectionInfo};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::read_secret;
use crate::error::McpError;
use crate::manifest::Limits;

/// The environment variable that holds the cache password when `password_file` is not set.
pub const PASSWORD_ENV: &str = "BROWSERX_CACHE_PASSWORD";

/// Length of the sliding window of per-tool limits.
const RATE_WINDOW_MS: u64 = 60_000;
/// Expiry of a per-tool window key: twice the window, so idle tools leave no key behind.
const RATE_TTL_MS: u64 = 2 * RATE_WINDOW_MS;
/// Expiry of an engagement call counter, refreshed by every call.
const BUDGET_TTL_SECS: u64 = 30 * 24 * 3600;
/// How often one caller probes a degraded cache.
const PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// Keys deleted by one `clear_namespace` at most.
const CLEAR_CAP: u64 = 100_000;
/// Keys asked of the server per `SCAN` step.
const SCAN_COUNT: u32 = 200;
/// Largest CA file read.
const MAX_CA_BYTES: u64 = 1024 * 1024;

const STATE_UNKNOWN: u8 = 0;
const STATE_HEALTHY: u8 = 1;
const STATE_DEGRADED: u8 = 2;

/// `KEYS[1]` window key; `ARGV` limit, window in ms, ttl in ms, unique member.
/// Returns 0 when admitted, else the seconds until a slot frees.
const RATE_SCRIPT: &str = r"
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
if redis.call('ZCARD', KEYS[1]) >= limit then
  local first = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  local wait = 60
  if first[2] then
    wait = math.ceil((tonumber(first[2]) + window - now) / 1000)
  end
  if wait < 1 then wait = 1 end
  return wait
end
redis.call('ZADD', KEYS[1], now, ARGV[4])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[3]))
return 0
";

/// `KEYS[1]` one-second window key, `KEYS[2]` call counter; `ARGV` rps (-1: none), max calls
/// (-1: none), unique member, counter ttl in seconds. Returns `{code, value}`: 0 admitted,
/// 1 rate exceeded, 2 budget exhausted (value: the count including this call).
const ENGAGEMENT_SCRIPT: &str = r"
local rps = tonumber(ARGV[1])
local max = tonumber(ARGV[2])
if rps >= 0 then
  local t = redis.call('TIME')
  local now = t[1] * 1000 + math.floor(t[2] / 1000)
  redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - 1000)
  if redis.call('ZCARD', KEYS[1]) >= rps then
    return {1, 0}
  end
  redis.call('ZADD', KEYS[1], now, ARGV[3])
  redis.call('PEXPIRE', KEYS[1], 2000)
end
if max >= 0 then
  local used = redis.call('INCR', KEYS[2])
  redis.call('EXPIRE', KEYS[2], tonumber(ARGV[4]))
  if used > max then
    return {2, used}
  end
end
return {0, 0}
";

/// Why a cache operation failed.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// The configuration cannot be honoured.
    #[error("{0}")]
    Config(String),
    /// The cache refused the credentials or the user may not run the command.
    #[error("the cache refused the credentials or the command ({0})")]
    Auth(String),
    /// The cache cannot be reached.
    #[error("the cache is unreachable: {0}")]
    Unreachable(String),
    /// The cache did not answer in time.
    #[error("the cache did not answer within {0} ms")]
    Timeout(u128),
    /// The cache answered with an error.
    #[error("the cache answered with an error: {0}")]
    Command(String),
    /// The cache is degraded and the next probe is not due yet.
    #[error("the cache is degraded; the in-memory limits apply until it answers again")]
    Degraded,
}

impl From<CacheError> for McpError {
    fn from(error: CacheError) -> Self {
        match error {
            CacheError::Config(message) => Self::Config(message),
            other => Self::Cache(other.to_string()),
        }
    }
}

fn bad(message: impl Into<String>) -> CacheError {
    CacheError::Config(format!("cache: {}", message.into()))
}

fn default_prefix() -> String {
    "browserx:".into()
}

const fn default_connect_timeout_ms() -> u64 {
    2000
}

const fn default_command_timeout_ms() -> u64 {
    500
}

/// `[cache]`: Valkey or Redis for limits shared by several MCP servers.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheSection {
    /// `redis://host[:port]` or `rediss://host[:port]`. No user, password, path or query.
    pub url: String,
    /// Prefix of every key: 1..=64 of `[A-Za-z0-9:_.-]`, ending in `:`.
    #[serde(default = "default_prefix")]
    pub key_prefix: String,
    /// Database index 0..=15; the server default when absent.
    #[serde(default)]
    pub db: Option<u32>,
    /// ACL user name.
    #[serde(default)]
    pub username: Option<String>,
    /// File holding the password. Without it the password comes from `BROWSERX_CACHE_PASSWORD`.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// PEM file with the certificate authority that signed the server certificate (`rediss://`
    /// only). Without it the system and bundled roots are used.
    #[serde(default)]
    pub tls_ca_file: Option<PathBuf>,
    /// Longest wait for a connection, in milliseconds.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Longest wait for one command, in milliseconds.
    #[serde(default = "default_command_timeout_ms")]
    pub command_timeout_ms: u64,
    /// Allow `redis://` to a host that is not loopback.
    #[serde(default)]
    pub allow_plaintext: bool,
    /// Refuse to start when the cache cannot be reached. Otherwise the server starts degraded.
    #[serde(default)]
    pub required: bool,
}

/// Whether a host name or address is the local machine. The URL parser keeps the host of a
/// `redis://` URL as plain text, so addresses are parsed here.
fn is_loopback(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(name) => {
            name.eq_ignore_ascii_case("localhost")
                || name
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    }
}

impl CacheSection {
    /// Makes relative file paths absolute against `base`.
    pub fn resolve_paths(&mut self, base: &Path) {
        for file in [&mut self.password_file, &mut self.tls_ca_file]
            .into_iter()
            .flatten()
        {
            if file.is_relative() {
                *file = base.join(&*file);
            }
        }
    }

    /// Checks the section without touching the network.
    ///
    /// # Errors
    /// [`McpError::Config`] for a URL that carries credentials, a path or a query, a plain-text
    /// connection to a non-loopback host that is not allowed, a bad prefix, an out-of-range
    /// database or timeout, or a TLS setting on a plain-text URL.
    pub fn validate(&self) -> Result<(), McpError> {
        self.parse().map(|_| ()).map_err(McpError::from)
    }

    /// The parsed URL, after every check.
    fn parse(&self) -> Result<url::Url, CacheError> {
        let url = url::Url::parse(&self.url).map_err(|_| bad("url is not a valid URL"))?;
        let tls = match url.scheme() {
            "redis" => false,
            "rediss" => true,
            _ => return Err(bad("url must start with redis:// or rediss://")),
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(bad(
                "url must not carry a user or a password: use cache.username and cache.password_file (or BROWSERX_CACHE_PASSWORD)",
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(bad(
                "url must not carry a query or a fragment: use the cache.* keys",
            ));
        }
        if !matches!(url.path(), "" | "/") {
            return Err(bad("url must not carry a path: use cache.db"));
        }
        let Some(host) = url.host() else {
            return Err(bad("url needs a host"));
        };
        if !tls && !self.allow_plaintext && !is_loopback(&host) {
            return Err(bad(
                "redis:// to a host that is not loopback is refused: use rediss:// or set cache.allow_plaintext = true",
            ));
        }
        if tls && self.allow_plaintext {
            return Err(bad("allow_plaintext has no meaning with rediss://"));
        }
        if !tls && self.tls_ca_file.is_some() {
            return Err(bad("tls_ca_file needs a rediss:// url"));
        }
        let prefix = &self.key_prefix;
        if prefix.is_empty()
            || prefix.len() > 64
            || !prefix.ends_with(':')
            || !prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.' | '-'))
        {
            return Err(bad(
                "key_prefix must be 1..=64 of [A-Za-z0-9:_.-] and end in ':'",
            ));
        }
        if self.db.is_some_and(|db| db > 15) {
            return Err(bad("db must be 0..=15"));
        }
        if self.username.as_deref().is_some_and(str::is_empty) {
            return Err(bad("username must not be empty"));
        }
        if !(1..=30_000).contains(&self.connect_timeout_ms) {
            return Err(bad("connect_timeout_ms must be 1..=30000"));
        }
        if !(1..=10_000).contains(&self.command_timeout_ms) {
            return Err(bad("command_timeout_ms must be 1..=10000"));
        }
        Ok(url)
    }
}

/// The verdict on one call against a per-minute limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The call was counted.
    Admitted,
    /// The limit is reached; a slot frees after this many seconds.
    Wait(u64),
}

/// The verdict on one call against the engagement limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngagementAdmission {
    /// The call was counted.
    Admitted,
    /// More than `rps` calls in the last second.
    RateExceeded,
    /// The call budget is used up; `used` counts this call.
    BudgetExhausted {
        /// Calls counted so far, including this one.
        used: u64,
    },
}

/// What `capabilities` shows about the cache. It carries no address and no credential.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Status {
    /// Always true: the section exists.
    pub configured: bool,
    /// The last command succeeded.
    pub healthy: bool,
    /// The last command failed; the in-memory limits apply.
    pub degraded: bool,
    /// The key prefix.
    pub key_prefix: String,
    /// Calls that used the in-memory fallback since start.
    pub fallback_total: u64,
}

/// A connection to the shared cache. Cheap to share behind an `Arc`; the connection is one
/// multiplexed, self-healing socket.
pub struct Cache {
    conn: ConnectionManager,
    prefix: String,
    connect_timeout: Duration,
    command_timeout: Duration,
    password: Option<Secret>,
    state: AtomicU8,
    /// Milliseconds since `started` after which the next probe may run.
    retry_at_ms: AtomicU64,
    fallbacks: AtomicU64,
    started: Instant,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("prefix", &self.prefix)
            .field("degraded", &self.degraded())
            .finish_non_exhaustive()
    }
}

/// The class of a client error, without its text.
fn redis_kind(error: &redis::RedisError) -> String {
    format!("{:?}", error.kind())
}

fn nonce() -> String {
    format!(
        "{:016x}{:016x}",
        rand::random::<u64>(),
        rand::random::<u64>()
    )
}

/// The part of an engagement id that goes into a key: the id itself when it is plain, else its
/// digest, so the key stays short and free of surprises.
fn engagement_key_part(id: &str) -> String {
    if !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        id.to_owned()
    } else {
        format!("h-{}", &hex::encode(Sha256::digest(id.as_bytes()))[..32])
    }
}

fn read_ca(path: &Path) -> Result<Vec<u8>, CacheError> {
    let fail = |why: String| bad(format!("tls_ca_file {}: {why}", path.display()));
    let meta = std::fs::metadata(path).map_err(|e| fail(e.to_string()))?;
    if meta.len() > MAX_CA_BYTES {
        return Err(fail("the file is larger than 1 MiB".into()));
    }
    let bytes = std::fs::read(path).map_err(|e| fail(e.to_string()))?;
    if !String::from_utf8_lossy(&bytes).contains("-----BEGIN CERTIFICATE-----") {
        return Err(fail("no PEM certificate found".into()));
    }
    Ok(bytes)
}

fn password(section: &CacheSection) -> Result<Option<Secret>, CacheError> {
    if let Some(file) = &section.password_file {
        return read_secret(file).map(Some).map_err(|e| bad(e.to_string()));
    }
    match std::env::var(PASSWORD_ENV) {
        Ok(value) if !value.trim().is_empty() => Ok(Some(Secret::new(value.trim()))),
        Ok(_) => Err(bad(format!("{PASSWORD_ENV} is set but empty"))),
        Err(_) => Ok(None),
    }
}

impl Cache {
    /// Builds the client. No connection is made yet: the first command connects, and
    /// [`Cache::probe`] checks the server at startup. Must run inside a Tokio runtime.
    ///
    /// # Errors
    /// [`CacheError::Config`] when the section is invalid or a secret or CA file is unreadable.
    pub fn new(section: &CacheSection) -> Result<Self, CacheError> {
        let url = section.parse()?;
        if url.scheme() == "rediss" {
            // The process has more than one TLS crypto provider compiled in, so none is the
            // default. Another component may have chosen one already; that is fine.
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let password = password(section)?;
        let info: ConnectionInfo = url
            .as_str()
            .into_connection_info()
            .map_err(|_| bad("url is not accepted by the client"))?;
        let mut settings = RedisConnectionInfo::default();
        if let Some(db) = section.db {
            settings = settings.set_db(i64::from(db));
        }
        if let Some(user) = &section.username {
            settings = settings.set_username(user);
        }
        if let Some(secret) = &password {
            settings = settings.set_password(secret.expose());
        }
        let info = info.set_redis_settings(settings);
        let client = match &section.tls_ca_file {
            Some(path) => Client::build_with_tls(
                info,
                redis::TlsCertificates {
                    client_tls: None,
                    root_cert: Some(read_ca(path)?),
                },
            ),
            None => Client::open(info),
        }
        .map_err(|e| bad(format!("cannot build the client: {}", redis_kind(&e))))?;
        let connect_timeout = Duration::from_millis(section.connect_timeout_ms);
        let command_timeout = Duration::from_millis(section.command_timeout_ms);
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(connect_timeout))
            .set_response_timeout(Some(command_timeout))
            .set_number_of_retries(1)
            .set_min_delay(Duration::from_millis(50));
        let conn = ConnectionManager::new_lazy_with_config(client, config)
            .map_err(|e| bad(format!("cannot build the client: {}", redis_kind(&e))))?;
        Ok(Self {
            conn,
            prefix: section.key_prefix.clone(),
            connect_timeout,
            command_timeout,
            password,
            state: AtomicU8::new(STATE_UNKNOWN),
            retry_at_ms: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
            started: Instant::now(),
        })
    }

    /// The key prefix.
    #[must_use]
    pub fn key_prefix(&self) -> &str {
        &self.prefix
    }

    /// Whether the last command failed.
    #[must_use]
    pub fn degraded(&self) -> bool {
        self.state.load(Ordering::Relaxed) == STATE_DEGRADED
    }

    /// Whether the last command succeeded.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.state.load(Ordering::Relaxed) == STATE_HEALTHY
    }

    /// Calls that used the in-memory fallback since start.
    #[must_use]
    pub fn fallback_total(&self) -> u64 {
        self.fallbacks.load(Ordering::Relaxed)
    }

    /// What `capabilities` shows.
    #[must_use]
    pub fn status(&self) -> Status {
        Status {
            configured: true,
            healthy: self.healthy(),
            degraded: self.degraded(),
            key_prefix: self.prefix.clone(),
            fallback_total: self.fallback_total(),
        }
    }

    /// Pings the server. A failure marks the cache degraded.
    ///
    /// # Errors
    /// Why the server could not be reached or refused the credentials.
    pub async fn probe(&self) -> Result<(), CacheError> {
        self.exec::<String>(redis::cmd("PING")).await.map(|_| ())
    }

    /// Counts a call of `tool` against `per_minute` in the shared sliding window.
    ///
    /// # Errors
    /// When the cache cannot answer. The caller must apply its in-memory limit instead.
    pub async fn rate_limit(&self, tool: &str, per_minute: u32) -> Result<Admission, CacheError> {
        let mut cmd = redis::cmd("EVAL");
        cmd.arg(RATE_SCRIPT)
            .arg(1)
            .arg(format!("{}rl:{tool}", self.prefix))
            .arg(per_minute)
            .arg(RATE_WINDOW_MS)
            .arg(RATE_TTL_MS)
            .arg(nonce());
        let wait: i64 = self.limited(cmd).await?;
        Ok(u64::try_from(wait)
            .ok()
            .filter(|wait| *wait > 0)
            .map_or(Admission::Admitted, Admission::Wait))
    }

    /// Counts a call against the limits of engagement `id`.
    ///
    /// # Errors
    /// When the cache cannot answer. The caller must apply its in-memory limit instead.
    pub async fn engagement(
        &self,
        id: &str,
        limits: Limits,
    ) -> Result<EngagementAdmission, CacheError> {
        let part = engagement_key_part(id);
        let mut cmd = redis::cmd("EVAL");
        cmd.arg(ENGAGEMENT_SCRIPT)
            .arg(2)
            .arg(format!("{}eng:{part}:rps", self.prefix))
            .arg(format!("{}eng:{part}:calls", self.prefix))
            .arg(limits.rps.map_or(-1_i64, i64::from))
            .arg(
                limits
                    .max_calls
                    .map_or(-1_i64, |max| i64::try_from(max).unwrap_or(i64::MAX)),
            )
            .arg(nonce())
            .arg(BUDGET_TTL_SECS);
        let reply: Vec<i64> = self.limited(cmd).await?;
        match reply.as_slice() {
            [0, _] => Ok(EngagementAdmission::Admitted),
            [1, _] => Ok(EngagementAdmission::RateExceeded),
            [2, used] => Ok(EngagementAdmission::BudgetExhausted {
                used: u64::try_from(*used).unwrap_or(u64::MAX),
            }),
            _ => {
                let error = CacheError::Command("unexpected reply of the budget script".into());
                self.mark_failed(&error);
                Err(error)
            }
        }
    }

    /// Deletes every key that starts with this cache's prefix, at most 100000 per call, and
    /// returns how many it deleted. Keys outside the prefix are never touched.
    ///
    /// # Errors
    /// When the cache cannot answer.
    pub async fn clear_namespace(&self) -> Result<u64, CacheError> {
        let pattern = format!("{}*", self.prefix);
        let mut cursor: u64 = 0;
        let mut deleted: u64 = 0;
        loop {
            let mut scan = redis::cmd("SCAN");
            scan.arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(SCAN_COUNT);
            let (next, keys): (u64, Vec<String>) = self.exec(scan).await?;
            // The server may return keys twice and a pattern can match more than the prefix
            // intends only if the prefix held glob characters, which validation forbids.
            let keys: Vec<String> = keys
                .into_iter()
                .filter(|key| key.starts_with(&self.prefix))
                .collect();
            if !keys.is_empty() {
                let room = usize::try_from(CLEAR_CAP.saturating_sub(deleted)).unwrap_or(usize::MAX);
                let mut del = redis::cmd("UNLINK");
                for key in keys.iter().take(room) {
                    del.arg(key);
                }
                let count: u64 = self.exec(del).await?;
                deleted = deleted.saturating_add(count);
            }
            if next == 0 || deleted >= CLEAR_CAP {
                return Ok(deleted);
            }
            cursor = next;
        }
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Whether a limiter command may go to the server now. A degraded cache admits one probe
    /// per interval.
    fn attempt_allowed(&self) -> bool {
        if self.state.load(Ordering::Relaxed) != STATE_DEGRADED {
            return true;
        }
        let now = self.elapsed_ms();
        let due = self.retry_at_ms.load(Ordering::Relaxed);
        now >= due
            && self
                .retry_at_ms
                .compare_exchange(
                    due,
                    now.saturating_add(u64::try_from(PROBE_INTERVAL.as_millis()).unwrap_or(1000)),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
    }

    /// A command of the limiter: counted as a fallback when it cannot be answered.
    async fn limited<T: FromRedisValue>(&self, cmd: redis::Cmd) -> Result<T, CacheError> {
        if !self.attempt_allowed() {
            self.fallbacks.fetch_add(1, Ordering::Relaxed);
            return Err(CacheError::Degraded);
        }
        let result = self.exec(cmd).await;
        if result.is_err() {
            self.fallbacks.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn exec<T: FromRedisValue>(&self, cmd: redis::Cmd) -> Result<T, CacheError> {
        // A connection that is not known to work may need its connect time as well.
        let limit = if self.healthy() {
            self.command_timeout
        } else {
            self.connect_timeout + self.command_timeout
        };
        let mut conn = self.conn.clone();
        match tokio::time::timeout(limit, cmd.query_async::<T>(&mut conn)).await {
            Ok(Ok(value)) => {
                if self.state.swap(STATE_HEALTHY, Ordering::Relaxed) == STATE_DEGRADED {
                    tracing::info!("the shared cache answers again: its limits apply again");
                }
                Ok(value)
            }
            Ok(Err(error)) => {
                let error = self.classify(&error);
                self.mark_failed(&error);
                Err(error)
            }
            Err(_) => {
                let error = CacheError::Timeout(limit.as_millis());
                self.mark_failed(&error);
                Err(error)
            }
        }
    }

    fn mark_failed(&self, error: &CacheError) {
        let due = self
            .elapsed_ms()
            .saturating_add(u64::try_from(PROBE_INTERVAL.as_millis()).unwrap_or(1000));
        self.retry_at_ms.store(due, Ordering::Relaxed);
        if self.state.swap(STATE_DEGRADED, Ordering::Relaxed) != STATE_DEGRADED {
            tracing::warn!(%error, "the shared cache is unavailable: the in-memory limits apply until it answers again");
        }
    }

    /// Removes the password from text that came from the client or the server.
    fn scrub(&self, text: String) -> String {
        match &self.password {
            Some(secret) if !secret.expose().is_empty() => {
                text.replace(secret.expose(), "[redacted]")
            }
            _ => text,
        }
    }

    fn classify(&self, error: &redis::RedisError) -> CacheError {
        let code = error.code().unwrap_or_default();
        if error.kind() == redis::ErrorKind::AuthenticationFailed
            || matches!(code, "WRONGPASS" | "NOAUTH" | "NOPERM")
        {
            let what = if code.is_empty() {
                "authentication failed"
            } else {
                code
            };
            return CacheError::Auth(what.to_owned());
        }
        if error.is_io_error()
            || error.is_connection_refusal()
            || error.is_connection_dropped()
            || error.is_timeout()
        {
            return CacheError::Unreachable(self.scrub(error.to_string()));
        }
        CacheError::Command(self.scrub(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn section(extra: &str) -> Result<CacheSection, toml::de::Error> {
        toml::from_str(&format!("url = \"redis://127.0.0.1:6379\"\n{extra}"))
    }

    fn rejected(extra: &str) -> String {
        section(extra).map_or_else(|e| e.to_string(), |s| s.validate().unwrap_err().to_string())
    }

    #[test]
    fn defaults_are_valid() {
        let s = section("").unwrap();
        s.validate().unwrap();
        assert_eq!(s.key_prefix, "browserx:");
        assert_eq!(s.connect_timeout_ms, 2000);
        assert_eq!(s.command_timeout_ms, 500);
        assert!(!s.required && !s.allow_plaintext);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(rejected("pasword_file = \"x\"").contains("unknown field"));
    }

    #[test]
    fn a_password_in_the_url_is_rejected() {
        let s: CacheSection =
            toml::from_str("url = \"redis://user:hunter2@127.0.0.1:6379\"").unwrap();
        let message = s.validate().unwrap_err().to_string();
        assert!(
            message.contains("must not carry a user or a password"),
            "{message}"
        );
        assert!(!message.contains("hunter2"), "{message}");
    }

    #[test]
    fn url_parts_that_the_client_would_interpret_are_rejected() {
        for url in [
            "redis://127.0.0.1/3",
            "redis://127.0.0.1?password=x",
            "redis://127.0.0.1#insecure",
            "redis+unix:///tmp/sock",
            "http://127.0.0.1",
            "redis://",
        ] {
            let s = CacheSection {
                url: url.into(),
                ..section("").unwrap()
            };
            assert!(s.validate().is_err(), "{url} must be rejected");
        }
    }

    #[test]
    fn plain_text_needs_loopback_or_an_explicit_switch() {
        let remote = |extra: &str| {
            toml::from_str::<CacheSection>(&format!(
                "url = \"redis://cache.internal:6379\"\n{extra}"
            ))
            .unwrap()
        };
        assert!(
            remote("")
                .validate()
                .unwrap_err()
                .to_string()
                .contains("not loopback")
        );
        remote("allow_plaintext = true").validate().unwrap();
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            let s = CacheSection {
                url: format!("redis://{host}:6379"),
                ..section("").unwrap()
            };
            s.validate().unwrap();
        }
        let tls = CacheSection {
            url: "rediss://cache.internal:6380".into(),
            ..section("").unwrap()
        };
        tls.validate().unwrap();
    }

    #[test]
    fn tls_settings_need_tls_and_plaintext_switch_needs_plaintext() {
        assert!(rejected("tls_ca_file = \"ca.pem\"").contains("needs a rediss://"));
        let tls = CacheSection {
            url: "rediss://cache.internal:6380".into(),
            allow_plaintext: true,
            ..section("").unwrap()
        };
        assert!(
            tls.validate()
                .unwrap_err()
                .to_string()
                .contains("no meaning")
        );
    }

    #[test]
    fn prefix_db_and_timeouts_are_bounded() {
        for bad in [
            "key_prefix = \"\"",
            "key_prefix = \"noColon\"",
            "key_prefix = \"a b:\"",
            "key_prefix = \"a*:\"",
            "db = 16",
            "connect_timeout_ms = 0",
            "command_timeout_ms = 0",
            "command_timeout_ms = 10001",
            "username = \"\"",
        ] {
            assert!(
                section(bad).map_or(true, |s| s.validate().is_err()),
                "{bad}"
            );
        }
        let long = format!("key_prefix = \"{}:\"", "a".repeat(64));
        assert!(rejected(&long).contains("key_prefix"));
        section("key_prefix = \"team-a.prod:\"\ndb = 15\nusername = \"bx\"")
            .unwrap()
            .validate()
            .unwrap();
    }

    #[test]
    fn relative_files_resolve_against_the_config_directory() {
        let mut s = section("password_file = \"pw\"\ntls_ca_file = \"/abs/ca.pem\"").unwrap();
        s.resolve_paths(Path::new("/etc/bx"));
        assert_eq!(s.password_file.as_deref(), Some(Path::new("/etc/bx/pw")));
        assert_eq!(s.tls_ca_file.as_deref(), Some(Path::new("/abs/ca.pem")));
    }

    #[test]
    fn engagement_ids_become_safe_key_parts() {
        assert_eq!(engagement_key_part("eng-2026.1_a"), "eng-2026.1_a");
        let odd = engagement_key_part("a b*\n:x");
        assert!(odd.starts_with("h-") && odd.len() == 34, "{odd}");
        assert_eq!(odd, engagement_key_part("a b*\n:x"));
        assert_ne!(odd, engagement_key_part("a b*\n:y"));
    }

    #[tokio::test]
    async fn a_missing_ca_file_is_a_config_error() {
        let s = CacheSection {
            url: "rediss://cache.internal:6380".into(),
            tls_ca_file: Some("/nonexistent/ca.pem".into()),
            ..section("").unwrap()
        };
        let error = Cache::new(&s).unwrap_err();
        assert!(matches!(error, CacheError::Config(_)), "{error}");
    }

    #[tokio::test]
    async fn debug_and_status_carry_no_address_or_secret() {
        let cache = Cache::new(&section("").unwrap()).unwrap();
        let text = format!("{cache:?} {:?}", cache.status());
        assert!(!text.contains("127.0.0.1"), "{text}");
        assert!(cache.status().configured && !cache.healthy() && !cache.degraded());
    }
}
