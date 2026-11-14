//! ClickHouse export sink: the audit log as rows of one table, over the HTTP interface.
//!
//! The sink works only inside the configured database. Its schema is created by versioned
//! migrations (the table `schema_migrations` records them); a database whose schema is newer
//! than this build is refused. Rows are inserted with `INSERT ... FORMAT JSONEachRow`. The
//! full record, exactly as written to the local log, is kept in the column `raw`, so a reader
//! can recompute the hash chain from the rows.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use browserx_core::Secret;
use serde::Deserialize;
use serde_json::{Value, json};

use super::export::{
    Extracted, MAX_BODY_BYTES, Report, SinkError, Tuning, bad, base_of, chunk_indices, http_client,
    http_url, resolve, secret_from, short,
};
use crate::error::McpError;

/// The environment variable that holds the password when `password_file` is not set.
pub const PASSWORD_ENV: &str = "BROWSERX_ANALYTICS_PASSWORD";
const TABLE: &str = "audit_v1";
const MAX_BATCH: usize = 10_000;

/// `[analytics]`: ClickHouse over HTTP.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AnalyticsSection {
    /// Base URL of the HTTP interface, for example `http://clickhouse:8123`. No credentials.
    pub url: String,
    /// The database the sink owns; created when missing. Other databases are never touched.
    pub database: String,
    /// The ClickHouse user.
    pub user: String,
    /// File holding the user's password; default: the environment variable
    /// `BROWSERX_ANALYTICS_PASSWORD`, else no password.
    pub password_file: Option<PathBuf>,
    /// Records per insert.
    pub batch_size: usize,
    /// How long a batch waits for more records, in milliseconds.
    pub flush_interval_ms: u64,
    /// Records buffered in memory before new ones are dropped.
    pub buffer: usize,
    /// Extra root certificates (PEM) for an `https` URL.
    pub tls_ca_file: Option<PathBuf>,
    /// Timeout of one HTTP request, in milliseconds.
    pub request_timeout_ms: u64,
    /// Allow plain `http` to a host that is not loopback.
    pub allow_plaintext: bool,
}

impl Default for AnalyticsSection {
    fn default() -> Self {
        Self {
            url: String::new(),
            database: "browserx".into(),
            user: "default".into(),
            password_file: None,
            batch_size: 500,
            flush_interval_ms: 1000,
            buffer: 10_000,
            tls_ca_file: None,
            request_timeout_ms: 5000,
            allow_plaintext: false,
        }
    }
}

/// A database name that is safe inside backticks and in a string literal.
pub(crate) fn valid_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.len() <= 63
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl AnalyticsSection {
    pub(crate) fn resolve(&mut self, base: &Path) {
        if let Some(file) = &mut self.password_file {
            resolve(file, base);
        }
        if let Some(file) = &mut self.tls_ca_file {
            resolve(file, base);
        }
    }

    pub(crate) fn validate(&self) -> Result<(), McpError> {
        http_url(
            "analytics.url",
            &self.url,
            self.allow_plaintext,
            self.tls_ca_file.as_deref(),
        )?;
        if !valid_identifier(&self.database) {
            return Err(bad(
                "analytics.database must be 1..=63 characters of [A-Za-z0-9_] and not start with a digit",
            ));
        }
        if self.user.is_empty() || self.user.len() > 128 || self.user.chars().any(char::is_control)
        {
            return Err(bad("analytics.user must be 1..=128 printable characters"));
        }
        Tuning::check(
            "analytics",
            self.batch_size,
            MAX_BATCH,
            self.flush_interval_ms,
            self.buffer,
            self.request_timeout_ms,
        )?;
        Ok(())
    }
}

/// One schema version: the statements that bring a database from the one before.
struct Migration {
    version: u32,
    name: &'static str,
    statements: fn(&str) -> Vec<String>,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "audit_v1",
    statements: audit_v1,
}];

/// The newest schema this build knows.
const LATEST: u32 = 1;

fn audit_v1(db: &str) -> Vec<String> {
    vec![format!(
        "CREATE TABLE IF NOT EXISTS `{db}`.`{TABLE}` (\
         seq UInt64, \
         ts DateTime64(6, 'UTC'), \
         prev String, \
         hash String, \
         phase LowCardinality(String), \
         tool LowCardinality(String), \
         outcome LowCardinality(String), \
         detail String, \
         duration_ms UInt64, \
         caller String, \
         context String, \
         arguments String, \
         engagement String, \
         operator String, \
         reason LowCardinality(String), \
         action_class LowCardinality(String), \
         trace_id String, \
         raw String\
         ) ENGINE = MergeTree PARTITION BY toYYYYMM(ts) ORDER BY (engagement, ts, seq)"
    )]
}

/// The ClickHouse sink.
pub(crate) struct ClickHouse {
    http: reqwest::Client,
    base: String,
    database: String,
    user: String,
    password: Option<Secret>,
    ready: bool,
}

/// The row of one record. `caller`, `context` and `arguments` are JSON text; `raw` is the whole
/// record as exported.
pub(crate) fn row(record: &Value) -> Value {
    let extracted = Extracted::of(record);
    let text = |key: &str| record.get(key).and_then(Value::as_str).unwrap_or("");
    let json_text = |key: &str| {
        record
            .get(key)
            .map_or_else(|| "null".to_owned(), Value::to_string)
    };
    json!({
        "seq": record.get("seq").and_then(Value::as_u64).unwrap_or(0),
        "ts": text("ts"),
        "prev": text("prev"),
        "hash": text("hash"),
        "phase": text("phase"),
        "tool": text("tool"),
        "outcome": text("outcome"),
        "detail": text("detail"),
        "duration_ms": record.get("duration_ms").and_then(Value::as_u64).unwrap_or(0),
        "caller": json_text("caller"),
        "context": json_text("context"),
        "arguments": json_text("arguments"),
        "engagement": extracted.engagement,
        "operator": extracted.operator,
        "reason": extracted.reason,
        "action_class": extracted.action_class,
        "trace_id": extracted.trace_id,
        "raw": record.to_string(),
    })
}

impl ClickHouse {
    pub(crate) fn build(section: &AnalyticsSection) -> Result<(Self, Tuning), McpError> {
        let tuning = Tuning::check(
            "analytics",
            section.batch_size,
            MAX_BATCH,
            section.flush_interval_ms,
            section.buffer,
            section.request_timeout_ms,
        )?;
        let url = http_url(
            "analytics.url",
            &section.url,
            section.allow_plaintext,
            section.tls_ca_file.as_deref(),
        )?;
        let password = secret_from(section.password_file.as_deref(), PASSWORD_ENV)?;
        Ok((
            Self {
                http: http_client(section.tls_ca_file.as_deref(), tuning.request_timeout)?,
                base: base_of(&url),
                database: section.database.clone(),
                user: section.user.clone(),
                password,
                ready: false,
            },
            tuning,
        ))
    }

    /// Runs one statement and returns the response text.
    async fn exec(
        &self,
        sql: &str,
        data: Option<Vec<u8>>,
        database: bool,
    ) -> Result<String, SinkError> {
        let mut request = self
            .http
            .post(format!("{}/", self.base))
            .basic_auth(&self.user, self.password.as_ref().map(Secret::expose));
        let query: Vec<(&str, &str)> = {
            let mut query = vec![("date_time_input_format", "best_effort")];
            if database {
                query.push(("database", self.database.as_str()));
            }
            if data.is_some() {
                query.push(("query", sql));
            }
            query
        };
        request = request.query(&query);
        request = match data {
            Some(body) => request.body(body),
            None => request.body(sql.to_owned()),
        };
        let response = request
            .send()
            .await
            .map_err(|e| SinkError::Transient(format!("request failed: {}", e.without_url())))?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.is_success() {
            return Ok(body);
        }
        let message = format!("ClickHouse answered {}: {}", status.as_u16(), short(&body));
        match status.as_u16() {
            401 | 403 => Err(SinkError::Rejected(format!(
                "ClickHouse refused the credentials ({status})"
            ))),
            400 | 413 | 422 => Err(SinkError::Rejected(message)),
            _ => Err(SinkError::Transient(message)),
        }
    }

    pub(crate) async fn ensure_ready(&mut self) -> Result<(), SinkError> {
        if self.ready {
            return Ok(());
        }
        let db = self.database.clone();
        let exists = self
            .exec(
                &format!("SELECT count() FROM system.databases WHERE name = '{db}'"),
                None,
                false,
            )
            .await?;
        if exists.trim() == "0" {
            self.exec(
                &format!("CREATE DATABASE IF NOT EXISTS `{db}`"),
                None,
                false,
            )
            .await?;
        }
        self.exec(
            &format!(
                "CREATE TABLE IF NOT EXISTS `{db}`.schema_migrations (\
                 version UInt32, name String, applied_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')\
                 ) ENGINE = MergeTree ORDER BY version"
            ),
            None,
            false,
        )
        .await?;
        let current: u32 = self
            .exec(
                &format!("SELECT max(version) FROM `{db}`.schema_migrations"),
                None,
                false,
            )
            .await?
            .trim()
            .parse()
            .map_err(|_| SinkError::Transient("unreadable schema version".into()))?;
        if current > LATEST {
            return Err(SinkError::Fatal(format!(
                "database `{db}` has schema version {current}, but this build supports up to {LATEST}: upgrade BrowserX or use another database"
            )));
        }
        for migration in MIGRATIONS.iter().filter(|m| m.version > current) {
            for statement in (migration.statements)(&db) {
                self.exec(&statement, None, false).await?;
            }
            self.exec(
                &format!(
                    "INSERT INTO `{db}`.schema_migrations (version, name) VALUES ({}, '{}')",
                    migration.version, migration.name
                ),
                None,
                false,
            )
            .await?;
        }
        self.ready = true;
        Ok(())
    }

    pub(crate) async fn send(&mut self, batch: &[Arc<Value>]) -> Result<Report, SinkError> {
        let rows: Vec<Vec<u8>> = batch
            .iter()
            .map(|record| {
                let mut line = row(record).to_string().into_bytes();
                line.push(b'\n');
                line
            })
            .collect();
        let sizes: Vec<usize> = rows.iter().map(Vec::len).collect();
        let (chunks, oversize) = chunk_indices(&sizes, MAX_BODY_BYTES);
        let mut report = Report {
            rejected: oversize.len(),
            ..Report::default()
        };
        if !oversize.is_empty() {
            report.error = Some("a record is larger than the request limit".into());
        }
        let sql = format!(
            "INSERT INTO `{}`.`{TABLE}` FORMAT JSONEachRow",
            self.database
        );
        for chunk in chunks {
            let body: Vec<u8> = chunk
                .iter()
                .flat_map(|i| rows[*i].iter().copied())
                .collect();
            match self.exec(&sql, Some(body), false).await {
                Ok(_) => {}
                Err(SinkError::Transient(message)) => {
                    report.retry.extend(chunk);
                    report.error = Some(message);
                }
                Err(SinkError::Rejected(message)) => {
                    report.rejected += chunk.len();
                    report.error = Some(message);
                }
                Err(fatal) => return Err(fatal),
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::config::Config;

    fn parse(extra: &str) -> Result<Config, McpError> {
        Config::parse(
            &format!(
                "[server]\nurl = \"http://127.0.0.1:7690\"\napi_key_file = \"key\"\n[audit]\npath = \"audit.jsonl\"\n{extra}"
            ),
            Path::new("/etc/browserx"),
        )
    }

    #[test]
    fn defaults_and_path_resolution() {
        let config = parse(
            "[analytics]\nurl = \"https://ch.example.test:8443\"\npassword_file = \"pw\"\ntls_ca_file = \"ca.pem\"\n",
        )
        .unwrap();
        let section = config.analytics.unwrap();
        assert_eq!(section.database, "browserx");
        assert_eq!(
            (
                section.batch_size,
                section.flush_interval_ms,
                section.buffer
            ),
            (500, 1000, 10_000)
        );
        assert_eq!(
            section.password_file.unwrap(),
            Path::new("/etc/browserx/pw")
        );
        assert_eq!(
            section.tls_ca_file.unwrap(),
            Path::new("/etc/browserx/ca.pem")
        );
    }

    #[test]
    fn unsupported_settings_are_refused() {
        for (extra, what) in [
            (
                "[analytics]\nurl = \"http://127.0.0.1:8123\"\ntable_prefix = \"x\"\n",
                "unknown key",
            ),
            (
                "[analytics]\nurl = \"http://user:pw@127.0.0.1:8123\"\n",
                "password in the URL",
            ),
            (
                "[analytics]\nurl = \"http://clickhouse:8123\"\n",
                "plain http to a remote host",
            ),
            (
                "[analytics]\nurl = \"https://ch:8443\"\nallow_plaintext = true\n",
                "allow_plaintext on https",
            ),
            (
                "[analytics]\nurl = \"http://127.0.0.1:8123\"\ntls_ca_file = \"ca\"\n",
                "CA for plain http",
            ),
            (
                "[analytics]\nurl = \"http://127.0.0.1:8123\"\ndatabase = \"a`b\"\n",
                "bad database name",
            ),
            (
                "[analytics]\nurl = \"http://127.0.0.1:8123\"\ndatabase = \"1db\"\n",
                "database starts with a digit",
            ),
            (
                "[analytics]\nurl = \"http://127.0.0.1:8123\"\nbatch_size = 0\n",
                "empty batch",
            ),
            (
                "[analytics]\nurl = \"http://127.0.0.1:8123\"\nbuffer = 10\nbatch_size = 500\n",
                "buffer under batch",
            ),
            ("[analytics]\n", "missing url"),
        ] {
            assert!(parse(extra).is_err(), "{what} must be refused");
        }
        assert!(
            parse("[analytics]\nurl = \"http://clickhouse:8123\"\nallow_plaintext = true\n")
                .is_ok()
        );
    }

    #[test]
    fn a_row_carries_the_whole_record() {
        let record = json!({"seq": 7, "ts": "2026-01-01T00:00:00.123456789Z", "prev": "p", "hash": "h",
            "phase": "result", "tool": "click", "outcome": "refused", "detail": "d", "duration_ms": 3,
            "caller": {"transport": "stdio"}, "arguments": {"url": "https://a.test"},
            "context": {"engagement": "E1", "operator": "alice", "reason": "out_of_scope",
                        "action_class": "read", "trace_id": "t1"}});
        let row = row(&record);
        assert_eq!(row["seq"], 7);
        assert_eq!(row["engagement"], "E1");
        assert_eq!(row["reason"], "out_of_scope");
        assert_eq!(row["trace_id"], "t1");
        assert_eq!(
            serde_json::from_str::<Value>(row["raw"].as_str().unwrap()).unwrap(),
            record
        );
        assert_eq!(
            serde_json::from_str::<Value>(row["arguments"].as_str().unwrap()).unwrap(),
            record["arguments"]
        );
    }

    #[test]
    fn identifiers() {
        assert!(valid_identifier("browserx"));
        assert!(valid_identifier("_t2"));
        assert!(!valid_identifier(""));
        assert!(!valid_identifier("a-b"));
        assert!(!valid_identifier(&"a".repeat(64)));
    }
}
