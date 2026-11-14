//! Configuration and helpers shared by the PostgreSQL and MariaDB lease stores.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use browserx_core::{Error, Generation, Result, Secret, SessionLease, SessionStatus};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::common::{check_cas, micros, scrubbed_if_terminal};

/// Namespace used when `schema` is not set.
pub const DEFAULT_SCHEMA: &str = "browserx";
/// Environment variable that carries the database password when no `password_file` is set.
pub const PASSWORD_ENV: &str = "BROWSERX_DATABASE_PASSWORD";

const DEFAULT_POOL_SIZE: usize = 8;
const MAX_POOL_SIZE: usize = 64;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
const MAX_CONNECT_TIMEOUT_SECS: u64 = 120;
const MAX_NODE_LEN: usize = 64;
const MAX_PASSWORD_BYTES: u64 = 4096;

/// Longest time one lease operation may take, from taking a connection to the answer.
pub(crate) const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
/// Server-side limit of one statement; shorter than [`OPERATION_TIMEOUT`] so the server answers first.
pub(crate) const STATEMENT_TIMEOUT: Duration = Duration::from_secs(25);
/// Longest time startup migrations may take, including waiting for a concurrent starter.
pub(crate) const MIGRATION_TIMEOUT: Duration = Duration::from_secs(90);

fn default_pool() -> usize {
    DEFAULT_POOL_SIZE
}

fn default_timeout() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_SECS
}

/// Transport security of a database connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Plain text. The only mode that allows plain text to a host other than loopback.
    Disable,
    /// TLS when the server offers it. To a host other than loopback this behaves like
    /// `require`: a plain-text fall back is refused. To loopback it may fall back.
    #[default]
    Prefer,
    /// TLS is mandatory; the connection fails when the server has none.
    Require,
}

/// Which database engine a [`DatabaseConfig`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// A local SQLite file, handled by [`crate::SqliteLeaseStore`].
    Sqlite,
    /// PostgreSQL.
    Postgres,
    /// MariaDB (and MySQL-protocol compatible servers).
    MariaDb,
}

/// Where the lease registry lives.
///
/// `url` selects the engine: `sqlite://<path>`, `postgres://host[:port][/database]` or
/// `mysql://host[:port]` / `mariadb://host[:port]`. The URL never carries a password: it is
/// read from `password_file`, or from the `BROWSERX_DATABASE_PASSWORD` environment variable
/// when no file is set.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Connection URL, without credentials other than a user name.
    pub url: String,
    /// PostgreSQL schema or MariaDB database that holds this product's tables. Default `browserx`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// Name of this worker. Required for PostgreSQL and MariaDB; two workers that share a
    /// database need different names, and a replacement worker keeps the name to take over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Database user (overrides a user name in the URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// File that holds the password (one line).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_file: Option<PathBuf>,
    /// Largest number of connections, 1 to 64. Default 8.
    #[serde(default = "default_pool")]
    pub pool_size: usize,
    /// PEM file with extra trusted certificate authorities (added to the built-in web roots).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_file: Option<PathBuf>,
    /// Transport security. Default `prefer`.
    #[serde(default)]
    pub tls: TlsMode,
    /// Longest time to wait for a connection, 1 to 120 seconds. Default 10.
    #[serde(default = "default_timeout")]
    pub connect_timeout_secs: u64,
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &redacted_url(&self.url))
            .field("schema", &self.schema)
            .field("node", &self.node)
            .field("user", &self.user)
            .field("password_file", &self.password_file)
            .field("pool_size", &self.pool_size)
            .field("tls_ca_file", &self.tls_ca_file)
            .field("tls", &self.tls)
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .finish()
    }
}

/// The URL with anything between `://` and `@` reduced to the user name, so a password that
/// was typed into a rejected URL never reaches a log line.
fn redacted_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "<invalid url>".to_owned();
    };
    let (authority, tail) = rest
        .split_once(['/', '?', '#'])
        .map_or((rest, ""), |(a, _)| (a, &rest[a.len()..]));
    match authority.rsplit_once('@') {
        Some((userinfo, host)) => {
            let user = userinfo.split_once(':').map_or(userinfo, |(u, _)| u);
            format!("{scheme}://{user}@{host}{tail}")
        }
        None => format!("{scheme}://{authority}{tail}"),
    }
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::InvalidRequest(msg.into())
}

/// How a relational store must secure its connection after the loopback rule is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsPlan {
    /// Plain text, explicitly requested.
    Plain,
    /// TLS or fail.
    Required,
    /// Loopback only: try TLS, fall back to plain text.
    Opportunistic,
}

/// A validated relational configuration with its secret loaded.
#[derive(Debug)]
pub(crate) struct Target {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    /// PostgreSQL database name (the URL path); `None` lets the server pick the user name.
    pub database: Option<String>,
    pub password: Option<Secret>,
    pub schema: String,
    pub node: String,
    pub pool_size: usize,
    pub connect_timeout: Duration,
    pub tls: TlsPlan,
    pub tls_ca_file: Option<PathBuf>,
}

impl DatabaseConfig {
    /// A configuration for `url` with every other setting at its default.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            schema: None,
            node: None,
            user: None,
            password_file: None,
            pool_size: DEFAULT_POOL_SIZE,
            tls_ca_file: None,
            tls: TlsMode::default(),
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
        }
    }

    /// The engine the URL scheme names.
    pub fn engine(&self) -> Result<Engine> {
        let (scheme, _) = self
            .url
            .split_once("://")
            .ok_or_else(|| invalid("database.url must look like scheme://..."))?;
        match scheme.to_ascii_lowercase().as_str() {
            "sqlite" => Ok(Engine::Sqlite),
            "postgres" | "postgresql" => Ok(Engine::Postgres),
            "mysql" | "mariadb" => Ok(Engine::MariaDb),
            other => Err(invalid(format!(
                "unsupported database.url scheme `{other}`; use sqlite://, postgres://, mysql:// or mariadb://"
            ))),
        }
    }

    /// The database file of a `sqlite:///absolute/path` or `sqlite://relative/path` URL; `None`
    /// for any other engine.
    #[must_use]
    pub fn sqlite_path(&self) -> Option<PathBuf> {
        if self.engine().ok()? != Engine::Sqlite {
            return None;
        }
        let (_, rest) = self.url.split_once("://")?;
        (!rest.is_empty()).then(|| PathBuf::from(rest))
    }

    /// The schema (PostgreSQL) or database (MariaDB) name after the default is applied.
    #[must_use]
    pub fn schema_name(&self) -> &str {
        self.schema.as_deref().unwrap_or(DEFAULT_SCHEMA)
    }

    /// Checks every setting without touching the network or reading a secret. Refuses unsupported
    /// combinations with an error that names the setting.
    pub fn validate(&self) -> Result<()> {
        match self.engine()? {
            Engine::Sqlite => self.parse_sqlite(),
            Engine::Postgres | Engine::MariaDb => self.parse().map(|_| ()),
        }
    }

    /// Validates and loads the password. Used by the relational stores.
    pub(crate) fn resolve(&self, expected: Engine) -> Result<Target> {
        let engine = self.engine()?;
        if engine != expected {
            return Err(invalid(format!(
                "database.url names {engine:?}, but this store opens {expected:?}"
            )));
        }
        let mut target = self.parse()?;
        target.password = self.read_password()?;
        Ok(target)
    }

    fn parse(&self) -> Result<Target> {
        let engine = self.engine()?;
        if engine == Engine::Sqlite {
            return Err(invalid("a sqlite:// url is opened by the SQLite store"));
        }
        let schema = self.schema_name();
        check_identifier("database.schema", schema)?;
        check_reserved_schema(engine, schema)?;
        let node = self
            .node
            .as_deref()
            .ok_or_else(|| invalid("database.node is required for PostgreSQL and MariaDB"))?;
        check_node(node)?;
        if !(1..=MAX_POOL_SIZE).contains(&self.pool_size) {
            return Err(invalid(format!(
                "database.pool_size must be between 1 and {MAX_POOL_SIZE}"
            )));
        }
        if !(1..=MAX_CONNECT_TIMEOUT_SECS).contains(&self.connect_timeout_secs) {
            return Err(invalid(format!(
                "database.connect_timeout_secs must be between 1 and {MAX_CONNECT_TIMEOUT_SECS}"
            )));
        }
        if self.tls == TlsMode::Disable && self.tls_ca_file.is_some() {
            return Err(invalid(
                "database.tls_ca_file has no effect with tls = \"disable\"",
            ));
        }
        for (key, path) in [
            ("database.password_file", &self.password_file),
            ("database.tls_ca_file", &self.tls_ca_file),
        ] {
            if let Some(path) = path
                && !path.is_file()
            {
                return Err(invalid(format!("{key} is not a readable file")));
            }
        }

        let url = Url::parse(&self.url).map_err(|e| invalid(format!("database.url: {e}")))?;
        if url.password().is_some() {
            return Err(invalid(
                "database.url must not carry a password; use database.password_file or the BROWSERX_DATABASE_PASSWORD environment variable",
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(invalid(
                "database.url must not carry a query or fragment; use the database.* settings",
            ));
        }
        let (host, loopback) = match url.host() {
            Some(Host::Ipv4(a)) => (a.to_string(), a.is_loopback()),
            Some(Host::Ipv6(a)) => (a.to_string(), a.is_loopback()),
            Some(Host::Domain(d)) if !d.is_empty() => {
                let loopback = d.parse::<IpAddr>().map_or_else(
                    |_| {
                        d.eq_ignore_ascii_case("localhost")
                            || d.to_ascii_lowercase().ends_with(".localhost")
                    },
                    |ip| ip.is_loopback(),
                );
                (d.to_owned(), loopback)
            }
            _ => return Err(invalid("database.url needs a host name")),
        };
        let url_user = url.username();
        if url_user.contains('%') {
            return Err(invalid(
                "database.url user names must not be percent-encoded; set database.user",
            ));
        }
        let user = match (&self.user, url_user) {
            (Some(u), "") => Some(u.clone()),
            (Some(u), from_url) if u == from_url => Some(u.clone()),
            (Some(_), _) => {
                return Err(invalid(
                    "database.user and the user name in database.url differ; set only one",
                ));
            }
            (None, "") => None,
            (None, from_url) => Some(from_url.to_owned()),
        };
        if user.as_deref().is_some_and(str::is_empty) {
            return Err(invalid("database.user must not be empty"));
        }
        let path = url.path().trim_start_matches('/');
        let database = match engine {
            Engine::Postgres => {
                if path.is_empty() {
                    None
                } else {
                    if !path
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                    {
                        return Err(invalid(
                            "database.url database name may use only letters, digits, `_`, `-` and `.`",
                        ));
                    }
                    Some(path.to_owned())
                }
            }
            _ => {
                if !path.is_empty() {
                    return Err(invalid(
                        "database.url must not name a database for MariaDB; the database is database.schema",
                    ));
                }
                None
            }
        };
        let tls = match self.tls {
            TlsMode::Disable => TlsPlan::Plain,
            TlsMode::Require => TlsPlan::Required,
            TlsMode::Prefer if loopback => TlsPlan::Opportunistic,
            TlsMode::Prefer => TlsPlan::Required,
        };
        Ok(Target {
            host,
            port: url.port().unwrap_or(match engine {
                Engine::Postgres => 5432,
                _ => 3306,
            }),
            user,
            database,
            password: None,
            schema: schema.to_owned(),
            node: node.to_owned(),
            pool_size: self.pool_size,
            connect_timeout: Duration::from_secs(self.connect_timeout_secs),
            tls,
            tls_ca_file: self.tls_ca_file.clone(),
        })
    }

    fn parse_sqlite(&self) -> Result<()> {
        let unsupported =
            |key: &str| invalid(format!("{key} is not supported with a sqlite:// url"));
        if self.schema.is_some() {
            return Err(unsupported("database.schema"));
        }
        if self.node.is_some() {
            return Err(unsupported("database.node"));
        }
        if self.user.is_some() {
            return Err(unsupported("database.user"));
        }
        if self.password_file.is_some() {
            return Err(unsupported("database.password_file"));
        }
        if self.tls_ca_file.is_some() {
            return Err(unsupported("database.tls_ca_file"));
        }
        if self.pool_size != DEFAULT_POOL_SIZE {
            return Err(unsupported("database.pool_size"));
        }
        if self.tls != TlsMode::default() {
            return Err(unsupported("database.tls"));
        }
        if self.connect_timeout_secs != DEFAULT_CONNECT_TIMEOUT_SECS {
            return Err(unsupported("database.connect_timeout_secs"));
        }
        if self.sqlite_path().is_none() {
            return Err(invalid("database.url names no file after sqlite://"));
        }
        Ok(())
    }

    /// The password from `password_file`, else from [`PASSWORD_ENV`], else none.
    fn read_password(&self) -> Result<Option<Secret>> {
        if let Some(path) = &self.password_file {
            return read_password_file(path).map(Some);
        }
        match std::env::var(PASSWORD_ENV) {
            Ok(v) if v.is_empty() => Ok(None),
            Ok(v) => Ok(Some(Secret::new(v))),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(invalid(format!("{PASSWORD_ENV} is not valid UTF-8")))
            }
        }
    }
}

fn read_password_file(path: &Path) -> Result<Secret> {
    let len = std::fs::metadata(path)
        .map_err(|e| invalid(format!("database.password_file: {e}")))?
        .len();
    if len > MAX_PASSWORD_BYTES {
        return Err(invalid(
            "database.password_file is too large for a password",
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| invalid(format!("database.password_file: {e}")))?;
    let line = text.trim_end_matches(['\n', '\r']);
    if line.is_empty() {
        return Err(invalid("database.password_file is empty"));
    }
    Ok(Secret::new(line))
}

/// `^[a-z_][a-z0-9_]{0,62}$`
fn check_identifier(key: &str, name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    let ok_first = bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b == b'_');
    let ok_rest = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if ok_first && ok_rest && name.len() <= 63 {
        Ok(())
    } else {
        Err(invalid(format!(
            "{key} must match ^[a-z_][a-z0-9_]{{0,62}}$"
        )))
    }
}

/// Names the engine itself owns; a product namespace must never be one of them.
fn check_reserved_schema(engine: Engine, schema: &str) -> Result<()> {
    let reserved = match engine {
        Engine::Postgres => {
            schema.starts_with("pg_") || schema == "information_schema" || schema == "public"
        }
        _ => matches!(
            schema,
            "mysql" | "information_schema" | "performance_schema" | "sys" | "test"
        ),
    };
    if reserved {
        Err(invalid(format!(
            "database.schema `{schema}` is reserved by the database engine; choose a namespace of your own"
        )))
    } else {
        Ok(())
    }
}

/// 1 to 64 characters of `[A-Za-z0-9._-]`.
fn check_node(node: &str) -> Result<()> {
    let ok = !node.is_empty()
        && node.len() <= MAX_NODE_LEN
        && node
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "database.node must be 1 to {MAX_NODE_LEN} characters of letters, digits, `.`, `_` and `-`"
        )))
    }
}

/// Runs `fut`, failing with a timeout error when it takes longer than `limit`.
pub(crate) async fn within<T>(
    what: &'static str,
    limit: Duration,
    fut: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(limit, fut)
        .await
        .map_err(|_| Error::Timeout(format!("{what} took longer than {}s", limit.as_secs())))?
}

/// Display of an error with its whole source chain. Driver errors name the failing step and
/// the server message, never the connection string.
pub(crate) fn chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        let next = s.to_string();
        if !text.contains(&next) {
            text.push_str(": ");
            text.push_str(&next);
        }
        source = s.source();
    }
    text
}

pub(crate) fn status_str(s: SessionStatus) -> &'static str {
    match s {
        SessionStatus::Queued => "queued",
        SessionStatus::Allocating => "allocating",
        SessionStatus::Active => "active",
        SessionStatus::Idle => "idle",
        SessionStatus::Recovering => "recovering",
        SessionStatus::Draining => "draining",
        SessionStatus::Lost => "lost",
        SessionStatus::Closed => "closed",
    }
}

pub(crate) fn generation_i64(g: Generation) -> Result<i64> {
    i64::try_from(g.0).map_err(|_| Error::InvalidRequest("generation exceeds i64 range".into()))
}

pub(crate) fn decode(id: &str, json: &str) -> Result<SessionLease> {
    serde_json::from_str(json)
        .map_err(|e| Error::Storage(format!("corrupt lease record {id}: {e}")))
}

/// The columns of one lease row, as bound to a statement.
pub(crate) struct LeaseRow {
    pub id: String,
    pub owner: String,
    pub status: &'static str,
    pub generation: i64,
    pub created_us: i64,
    pub json: String,
}

impl LeaseRow {
    /// Terminal leases are stored without the upstream proxy password.
    pub(crate) fn of(lease: &SessionLease) -> Result<Self> {
        let scrubbed = scrubbed_if_terminal(lease);
        let json = serde_json::to_string(scrubbed.as_ref().unwrap_or(lease))
            .map_err(|e| Error::Internal(format!("encode lease: {e}")))?;
        Ok(Self {
            id: lease.session_id.to_string(),
            owner: lease.owner.clone(),
            status: status_str(lease.status),
            generation: generation_i64(lease.generation)?,
            created_us: micros(lease.created_at),
            json,
        })
    }
}

/// Rejects a compare-and-swap whose new generation is neither the old one nor the next.
pub(crate) fn check_cas_request(expected: Generation, lease: &SessionLease) -> Result<()> {
    if lease.generation != expected && lease.generation != expected.next() {
        return Err(Error::InvalidRequest(format!(
            "lease generation must stay {expected} or advance to {}, got {}",
            expected.next(),
            lease.generation
        )));
    }
    Ok(())
}

/// The error for a compare-and-swap that changed no row, given the stored generation (if any).
pub(crate) fn cas_failure(
    id: &str,
    stored: Option<i64>,
    expected: Generation,
    candidate: &SessionLease,
) -> Error {
    match stored {
        None => Error::NotFound(format!("lease {id}")),
        Some(found) => {
            let found = Generation(u64::try_from(found).unwrap_or(u64::MAX));
            match check_cas(found, expected, candidate) {
                Err(e) => e,
                Ok(()) => Error::Internal("compare-and-swap affected no row".into()),
            }
        }
    }
}

/// Removes the proxy password from a stored terminal lease; `None` when it has none.
pub(crate) fn scrub_json(id: &str, json: &str) -> Result<Option<String>> {
    let lease = decode(id, json)?;
    scrubbed_if_terminal(&lease)
        .map(|clean| {
            serde_json::to_string(&clean).map_err(|e| Error::Internal(format!("encode lease: {e}")))
        })
        .transpose()
}

/// The 64-bit key of the migration lock of one namespace.
pub(crate) fn lock_digest(schema: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"browserx.lease.migrate:");
    hasher.update(schema.as_bytes());
    hasher.finalize().into()
}

/// Refuses a database that a newer build migrated.
pub(crate) fn check_not_newer(current: i64, latest: i64) -> Result<()> {
    if current > latest {
        return Err(Error::Storage(format!(
            "database schema v{current} is newer than this build supports (v{latest}); upgrade BrowserX"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn pg() -> DatabaseConfig {
        DatabaseConfig {
            node: Some("node-a".into()),
            ..DatabaseConfig::new("postgres://db.example.test/browserx")
        }
    }

    fn message(r: Result<()>) -> String {
        match r {
            Err(Error::InvalidRequest(m)) => m,
            other => format!("unexpected {other:?}"),
        }
    }

    #[test]
    fn engines_follow_the_scheme() {
        assert_eq!(pg().engine().unwrap(), Engine::Postgres);
        assert_eq!(
            DatabaseConfig::new("mariadb://h").engine().unwrap(),
            Engine::MariaDb
        );
        assert_eq!(
            DatabaseConfig::new("mysql://h").engine().unwrap(),
            Engine::MariaDb
        );
        assert_eq!(
            DatabaseConfig::new("sqlite:///var/x.db").engine().unwrap(),
            Engine::Sqlite
        );
        assert!(DatabaseConfig::new("redis://h").engine().is_err());
        assert!(DatabaseConfig::new("no-scheme").engine().is_err());
    }

    #[test]
    fn sqlite_path_covers_absolute_and_relative() {
        assert_eq!(
            DatabaseConfig::new("sqlite:///var/lib/x.db").sqlite_path(),
            Some(PathBuf::from("/var/lib/x.db"))
        );
        assert_eq!(
            DatabaseConfig::new("sqlite://state/x.db").sqlite_path(),
            Some(PathBuf::from("state/x.db"))
        );
        assert_eq!(DatabaseConfig::new("sqlite://").sqlite_path(), None);
        assert_eq!(pg().sqlite_path(), None);
    }

    #[test]
    fn a_complete_postgres_config_is_valid() {
        pg().validate().unwrap();
        let mut c = pg();
        c.tls = TlsMode::Require;
        c.schema = Some("other_product".into());
        c.validate().unwrap();
    }

    #[test]
    fn node_is_required_and_checked() {
        let mut c = pg();
        c.node = None;
        assert!(message(c.validate()).contains("database.node is required"));
        for bad in ["", "has space", "slash/node", &"n".repeat(65)] {
            c.node = Some(bad.to_owned());
            assert!(message(c.validate()).contains("database.node"), "{bad}");
        }
        c.node = Some("a.b_c-9".into());
        c.validate().unwrap();
    }

    #[test]
    fn url_with_password_is_refused_and_never_echoed() {
        let c = DatabaseConfig {
            node: Some("n".into()),
            ..DatabaseConfig::new("postgres://app:hunter2@db.example.test/browserx")
        };
        let msg = message(c.validate());
        assert!(msg.contains("must not carry a password"));
        assert!(!msg.contains("hunter2"));
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    #[test]
    fn url_query_and_mariadb_database_path_are_refused() {
        let mut c = pg();
        c.url = "postgres://h/db?sslmode=disable".into();
        assert!(message(c.validate()).contains("query"));
        let m = DatabaseConfig {
            node: Some("n".into()),
            ..DatabaseConfig::new("mariadb://h/some_db")
        };
        assert!(message(m.validate()).contains("must not name a database"));
    }

    #[test]
    fn bad_identifiers_are_refused() {
        let mut c = pg();
        for bad in [
            "",
            "Upper",
            "9lead",
            "has-dash",
            "semi;colon",
            "quo\"te",
            &"a".repeat(64),
        ] {
            c.schema = Some(bad.to_owned());
            assert!(message(c.validate()).contains("database.schema"), "{bad}");
        }
        for reserved in ["pg_catalog", "public", "information_schema"] {
            c.schema = Some(reserved.to_owned());
            assert!(message(c.validate()).contains("reserved"), "{reserved}");
        }
        c.schema = Some("_ok_1".into());
        c.validate().unwrap();
        let m = DatabaseConfig {
            node: Some("n".into()),
            schema: Some("mysql".into()),
            ..DatabaseConfig::new("mariadb://h")
        };
        assert!(message(m.validate()).contains("reserved"));
    }

    #[test]
    fn ranges_are_enforced() {
        let mut c = pg();
        c.pool_size = 0;
        assert!(message(c.validate()).contains("pool_size"));
        c.pool_size = 65;
        assert!(message(c.validate()).contains("pool_size"));
        c.pool_size = 64;
        c.validate().unwrap();
        c.connect_timeout_secs = 0;
        assert!(message(c.validate()).contains("connect_timeout_secs"));
        c.connect_timeout_secs = 121;
        assert!(message(c.validate()).contains("connect_timeout_secs"));
    }

    #[test]
    fn sqlite_rejects_relational_settings() {
        let base = DatabaseConfig::new("sqlite:///tmp/x.db");
        base.validate().unwrap();
        let cases: Vec<(&str, DatabaseConfig)> = vec![
            (
                "database.node",
                DatabaseConfig {
                    node: Some("n".into()),
                    ..base.clone()
                },
            ),
            (
                "database.schema",
                DatabaseConfig {
                    schema: Some("s".into()),
                    ..base.clone()
                },
            ),
            (
                "database.user",
                DatabaseConfig {
                    user: Some("u".into()),
                    ..base.clone()
                },
            ),
            (
                "database.pool_size",
                DatabaseConfig {
                    pool_size: 4,
                    ..base.clone()
                },
            ),
            (
                "database.tls",
                DatabaseConfig {
                    tls: TlsMode::Require,
                    ..base.clone()
                },
            ),
            (
                "database.tls_ca_file",
                DatabaseConfig {
                    tls_ca_file: Some("/x".into()),
                    ..base.clone()
                },
            ),
            (
                "database.password_file",
                DatabaseConfig {
                    password_file: Some("/x".into()),
                    ..base.clone()
                },
            ),
            (
                "database.connect_timeout_secs",
                DatabaseConfig {
                    connect_timeout_secs: 3,
                    ..base.clone()
                },
            ),
        ];
        for (key, cfg) in cases {
            let msg = message(cfg.validate());
            assert!(msg.contains(key) && msg.contains("sqlite"), "{key}: {msg}");
        }
        assert!(message(DatabaseConfig::new("sqlite://").validate()).contains("no file"));
    }

    #[test]
    fn missing_secret_files_are_refused_at_load() {
        let mut c = pg();
        c.password_file = Some("/definitely/missing/password".into());
        assert!(message(c.validate()).contains("password_file"));
        c.password_file = None;
        c.tls_ca_file = Some("/definitely/missing/ca.pem".into());
        assert!(message(c.validate()).contains("tls_ca_file"));
    }

    #[test]
    fn tls_disable_with_a_ca_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, "x").unwrap();
        let mut c = pg();
        c.tls = TlsMode::Disable;
        c.tls_ca_file = Some(ca);
        assert!(message(c.validate()).contains("tls_ca_file"));
    }

    #[test]
    fn prefer_is_required_off_loopback_and_opportunistic_on_it() {
        let remote = pg().parse().unwrap();
        assert_eq!(remote.tls, TlsPlan::Required);
        for host in ["127.0.0.1", "localhost", "[::1]"] {
            let c = DatabaseConfig {
                node: Some("n".into()),
                ..DatabaseConfig::new(format!("postgres://{host}/db"))
            };
            assert_eq!(c.parse().unwrap().tls, TlsPlan::Opportunistic, "{host}");
        }
        let mut c = pg();
        c.tls = TlsMode::Disable;
        assert_eq!(c.parse().unwrap().tls, TlsPlan::Plain);
    }

    #[test]
    fn user_comes_from_config_or_url_but_not_both_differently() {
        let mut c = DatabaseConfig {
            node: Some("n".into()),
            ..DatabaseConfig::new("postgres://alice@h/db")
        };
        assert_eq!(c.parse().unwrap().user.as_deref(), Some("alice"));
        c.user = Some("alice".into());
        assert_eq!(c.parse().unwrap().user.as_deref(), Some("alice"));
        c.user = Some("bob".into());
        assert!(message(c.validate()).contains("differ"));
    }

    #[test]
    fn password_file_wins_and_is_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pw");
        std::fs::write(&file, "from-file\n").unwrap();
        let mut c = pg();
        c.password_file = Some(file.clone());
        let secret = c.read_password().unwrap().unwrap();
        assert_eq!(secret.expose(), "from-file");
        std::fs::write(&file, "\n").unwrap();
        assert!(c.read_password().is_err());
    }

    #[test]
    fn config_round_trips_and_rejects_unknown_keys() {
        let c: DatabaseConfig = serde_json::from_str(
            r#"{"url":"postgres://h/db","node":"n","tls":"require","pool_size":4}"#,
        )
        .unwrap();
        assert_eq!(c.tls, TlsMode::Require);
        assert_eq!(c.pool_size, 4);
        assert_eq!(c.connect_timeout_secs, 10);
        let again: DatabaseConfig =
            serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(again.node.as_deref(), Some("n"));
        assert!(
            serde_json::from_str::<DatabaseConfig>(r#"{"url":"sqlite://x","password":"p"}"#)
                .is_err()
        );
    }

    #[test]
    fn debug_hides_userinfo() {
        let c = DatabaseConfig::new("mysql://app:secret@h:3306/x?a=b");
        let text = format!("{c:?}");
        assert!(!text.contains("secret"));
        assert!(text.contains("app@h"));
    }
}
