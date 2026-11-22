//! Kafka export sink, with the pure-Rust `rskafka` client.
//!
//! * The topic `<topic_prefix>audit` must already exist: BrowserX never creates, changes or
//!   deletes topics. Until it exists the sink reports the error and retries.
//! * Records are produced to the partition their key hashes to, with all in-sync replicas
//!   acknowledging (`acks=all`). The key is the engagement id, or the tool name when the entry
//!   has none, so one engagement stays in order inside one partition.
//! * `rskafka` has no idempotent producer: a batch whose acknowledgement is lost is sent again,
//!   so delivery is at-least-once. Every message carries `seq` and `hash` (in the body and in
//!   the headers `audit-seq` and `audit-hash`); a consumer discards duplicates by that pair.
//! * TLS and SASL (`plain`, `scram-sha-256`, `scram-sha-512`) are supported.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use browserx_core::Secret;
use rskafka::BackoffConfig;
use rskafka::client::partition::{Compression, PartitionClient, UnknownTopicHandling};
use rskafka::client::{Client, ClientBuilder, Credentials, SaslConfig};
use rskafka::record::Record;
use serde::Deserialize;
use serde_json::Value;

use super::export::{
    Report, SinkError, Tuning, bad, chunk_indices, is_loopback, resolve, secret_from,
};
use crate::error::McpError;

/// The environment variable that holds the SASL password when `password_file` is not set.
pub const PASSWORD_ENV: &str = "BROWSERX_EVENTS_PASSWORD";
/// The largest produce request this sink builds (the broker default limit is 1 MiB).
const MAX_PRODUCE_BYTES: usize = 900 * 1024;
const MAX_BATCH: usize = 10_000;

/// The SASL mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SaslMechanism {
    /// `PLAIN`.
    Plain,
    /// `SCRAM-SHA-256`.
    ScramSha256,
    /// `SCRAM-SHA-512`.
    ScramSha512,
}

/// `[events.sasl]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaslSection {
    /// The mechanism; default `plain`.
    #[serde(default = "default_mechanism")]
    pub mechanism: SaslMechanism,
    /// The user name.
    pub username: String,
    /// File holding the password; default: the environment variable
    /// `BROWSERX_EVENTS_PASSWORD`.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
}

fn default_mechanism() -> SaslMechanism {
    SaslMechanism::Plain
}

/// `[events]` with `kind = "kafka"`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KafkaSection {
    /// Bootstrap brokers, `host:port`.
    pub brokers: Vec<String>,
    /// Prefix of the topic name; the topic is `<prefix>audit`.
    pub topic_prefix: String,
    /// The client id sent to the brokers.
    pub client_id: String,
    /// SASL credentials.
    pub sasl: Option<SaslSection>,
    /// Connect with TLS.
    pub tls: bool,
    /// Extra root certificates (PEM); needs `tls = true`.
    pub tls_ca_file: Option<PathBuf>,
    /// Allow plain connections to brokers that are not loopback (needs `tls = false`).
    pub allow_plaintext: bool,
    /// Records per produce call.
    pub batch_size: usize,
    /// How long a batch waits for more records, in milliseconds.
    pub flush_interval_ms: u64,
    /// Records buffered in memory before new ones are dropped.
    pub buffer: usize,
    /// Timeout of one broker request, in milliseconds.
    pub request_timeout_ms: u64,
}

impl Default for KafkaSection {
    fn default() -> Self {
        Self {
            brokers: Vec::new(),
            topic_prefix: "browserx.".into(),
            client_id: "browserx-mcp".into(),
            sasl: None,
            tls: false,
            tls_ca_file: None,
            allow_plaintext: false,
            batch_size: 500,
            flush_interval_ms: 1000,
            buffer: 10_000,
            request_timeout_ms: 5000,
        }
    }
}

/// A Kafka topic name part: `[A-Za-z0-9._-]`, at most 200 characters.
fn valid_topic_part(text: &str) -> bool {
    text.len() <= 200
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Splits `host:port` of a broker entry: no credentials, no path, a port is required.
fn broker_host(entry: &str) -> Option<(String, u16)> {
    let parsed = url::Url::parse(&format!("kafka://{entry}")).ok()?;
    if !parsed.username().is_empty() || parsed.password().is_some() || !parsed.path().is_empty() {
        return None;
    }
    Some((parsed.host_str()?.to_owned(), parsed.port()?))
}

impl KafkaSection {
    pub(crate) fn resolve(&mut self, base: &Path) {
        if let Some(file) = &mut self.tls_ca_file {
            resolve(file, base);
        }
        if let Some(sasl) = &mut self.sasl
            && let Some(file) = &mut sasl.password_file
        {
            resolve(file, base);
        }
    }

    pub(crate) fn validate(&self) -> Result<(), McpError> {
        if self.brokers.is_empty() || self.brokers.len() > 16 {
            return Err(bad("events.brokers must list 1..=16 `host:port` entries"));
        }
        let mut all_loopback = true;
        for entry in &self.brokers {
            let Some((host, _)) = broker_host(entry) else {
                return Err(bad(format!(
                    "events.brokers: `{entry}` is not `host:port` (no credentials, no path)"
                )));
            };
            all_loopback &= is_loopback(&host);
        }
        if !valid_topic_part(&self.topic_prefix) {
            return Err(bad(
                "events.topic_prefix may hold only letters, digits, `.`, `_` and `-` (at most 200)",
            ));
        }
        if self.client_id.is_empty()
            || self.client_id.len() > 128
            || self.client_id.chars().any(char::is_control)
        {
            return Err(bad("events.client_id must be 1..=128 printable characters"));
        }
        if self.tls_ca_file.is_some() && !self.tls {
            return Err(bad("events.tls_ca_file needs events.tls = true"));
        }
        // A client follows the broker addresses the cluster advertises, not just
        // the bootstrap list, and cannot see them before it connects. A loopback
        // bootstrap (a tunnel, a sidecar) therefore proves nothing about where a
        // SASL password goes, so SASL always needs TLS or an explicit opt-out.
        let plaintext_sasl = !self.tls && self.sasl.is_some();
        let plaintext_remote = !self.tls && !all_loopback;
        if plaintext_sasl && !self.allow_plaintext {
            return Err(bad(
                "events.sasl without events.tls sends the SASL password and the audit records in clear, and the brokers can advertise other addresses: set events.tls = true or events.allow_plaintext = true",
            ));
        }
        if plaintext_remote && !self.allow_plaintext {
            return Err(bad(
                "events.brokers are plain connections to hosts that are not loopback: set events.tls = true or events.allow_plaintext = true",
            ));
        }
        if self.allow_plaintext && !(plaintext_remote || plaintext_sasl) {
            return Err(bad(
                "events.allow_plaintext only applies to plain connections to brokers that are not loopback, or to SASL without events.tls",
            ));
        }
        if let Some(sasl) = &self.sasl
            && (sasl.username.is_empty() || sasl.username.len() > 256)
        {
            return Err(bad("events.sasl.username must be 1..=256 characters"));
        }
        Tuning::check(
            "events",
            self.batch_size,
            MAX_BATCH,
            self.flush_interval_ms,
            self.buffer,
            self.request_timeout_ms,
        )?;
        Ok(())
    }

    /// The topic the sink writes to.
    #[must_use]
    pub fn topic(&self) -> String {
        format!("{}audit", self.topic_prefix)
    }
}

/// The TLS client configuration: the web PKI roots, the optional extra roots.
pub(crate) fn tls_config(ca_file: Option<&Path>) -> Result<Arc<rustls::ClientConfig>, McpError> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject as _;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        let pem = std::fs::read(path)
            .map_err(|e| McpError::io(format!("cannot read tls_ca_file {}", path.display()), e))?;
        let mut added = 0_usize;
        for cert in CertificateDer::pem_slice_iter(&pem) {
            let cert = cert.map_err(|e| bad(format!("tls_ca_file {}: {e}", path.display())))?;
            roots
                .add(cert)
                .map_err(|e| bad(format!("tls_ca_file {}: {e}", path.display())))?;
            added += 1;
        }
        if added == 0 {
            return Err(bad(format!(
                "tls_ca_file {} holds no certificate",
                path.display()
            )));
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| bad(format!("TLS configuration failed: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// FNV-1a: a stable hash for choosing partitions.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The partition index (into the sorted partition list) a key belongs to.
pub(crate) fn partition_slot(key: &str, partitions: usize) -> usize {
    if partitions == 0 {
        return 0;
    }
    (fnv1a(key.as_bytes()) % partitions as u64) as usize
}

/// The message key: the engagement id, else the tool name.
pub(crate) fn message_key(record: &Value) -> String {
    let engagement = record
        .get("context")
        .and_then(|c| c.get("engagement"))
        .and_then(Value::as_str)
        .filter(|e| !e.is_empty());
    let tool = record.get("tool").and_then(Value::as_str).unwrap_or("");
    engagement.unwrap_or(tool).to_owned()
}

/// The Kafka sink.
pub(crate) struct Kafka {
    brokers: Vec<String>,
    client_id: String,
    topic: String,
    tls: Option<Arc<rustls::ClientConfig>>,
    sasl: Option<(SaslMechanism, String, Secret)>,
    timeout: Duration,
    client: Option<Client>,
    partitions: Vec<Arc<PartitionClient>>,
}

impl Kafka {
    pub(crate) fn build(section: &KafkaSection) -> Result<(Self, Tuning), McpError> {
        let tuning = Tuning::check(
            "events",
            section.batch_size,
            MAX_BATCH,
            section.flush_interval_ms,
            section.buffer,
            section.request_timeout_ms,
        )?;
        let sasl = match &section.sasl {
            None => None,
            Some(sasl) => {
                let password = secret_from(sasl.password_file.as_deref(), PASSWORD_ENV)?
                    .ok_or_else(|| {
                        bad(format!(
                            "events.sasl needs a password: set password_file or the environment variable {PASSWORD_ENV}"
                        ))
                    })?;
                Some((sasl.mechanism, sasl.username.clone(), password))
            }
        };
        let tls = if section.tls {
            Some(tls_config(section.tls_ca_file.as_deref())?)
        } else {
            None
        };
        Ok((
            Self {
                brokers: section.brokers.clone(),
                client_id: section.client_id.clone(),
                topic: section.topic(),
                tls,
                sasl,
                timeout: tuning.request_timeout,
                client: None,
                partitions: Vec::new(),
            },
            tuning,
        ))
    }

    pub(crate) fn reset(&mut self) {
        self.client = None;
        self.partitions.clear();
    }

    pub(crate) async fn ensure_ready(&mut self) -> Result<(), SinkError> {
        if self.client.is_some() && !self.partitions.is_empty() {
            return Ok(());
        }
        self.reset();
        let mut builder = ClientBuilder::new(self.brokers.clone())
            .client_id(self.client_id.as_str())
            .max_message_size(8 * 1024 * 1024)
            .backoff_config(BackoffConfig {
                init_backoff: Duration::from_millis(100),
                max_backoff: Duration::from_secs(1),
                base: 2.0,
                deadline: Some(self.timeout),
            });
        if let Some(tls) = &self.tls {
            builder = builder.tls_config(Arc::clone(tls));
        }
        if let Some((mechanism, username, password)) = &self.sasl {
            let credentials = Credentials::new(username.clone(), password.expose().to_owned());
            builder = builder.sasl_config(match mechanism {
                SaslMechanism::Plain => SaslConfig::Plain(credentials),
                SaslMechanism::ScramSha256 => SaslConfig::ScramSha256(credentials),
                SaslMechanism::ScramSha512 => SaslConfig::ScramSha512(credentials),
            });
        }
        let client = bounded(self.timeout, builder.build(), "connecting").await?;
        let topics = bounded(self.timeout, client.list_topics(), "listing topics").await?;
        let Some(topic) = topics.into_iter().find(|t| t.name == self.topic) else {
            return Err(SinkError::Transient(format!(
                "the topic `{}` does not exist: create it first, BrowserX never creates topics",
                self.topic
            )));
        };
        let mut partitions = Vec::new();
        for partition in topic.partitions {
            let pc = bounded(
                self.timeout,
                client.partition_client(self.topic.clone(), partition, UnknownTopicHandling::Error),
                "opening a partition",
            )
            .await?;
            partitions.push(Arc::new(pc));
        }
        if partitions.is_empty() {
            return Err(SinkError::Transient(format!(
                "the topic `{}` has no partitions",
                self.topic
            )));
        }
        self.client = Some(client);
        self.partitions = partitions;
        Ok(())
    }

    pub(crate) async fn send(&mut self, batch: &[Arc<Value>]) -> Result<Report, SinkError> {
        let mut report = Report::default();
        // index -> (slot, record); grouped per partition, chunked by size.
        let mut by_slot: BTreeMap<usize, Vec<(usize, Record, usize)>> = BTreeMap::new();
        for (index, value) in batch.iter().enumerate() {
            let key = message_key(value);
            let body = value.to_string().into_bytes();
            let size = body.len() + key.len() + 128;
            let mut headers = BTreeMap::new();
            headers.insert("content-type".to_owned(), b"application/json".to_vec());
            headers.insert(
                "audit-seq".to_owned(),
                value
                    .get("seq")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .to_string()
                    .into_bytes(),
            );
            headers.insert(
                "audit-hash".to_owned(),
                value
                    .get("hash")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .as_bytes()
                    .to_vec(),
            );
            let slot = partition_slot(&key, self.partitions.len());
            by_slot.entry(slot).or_default().push((
                index,
                Record {
                    key: Some(key.into_bytes()),
                    value: Some(body),
                    headers,
                    timestamp: std::time::SystemTime::now(),
                },
                size,
            ));
        }
        let mut failed = false;
        for (slot, entries) in by_slot {
            let Some(client) = self.partitions.get(slot).map(Arc::clone) else {
                report.retry.extend(entries.iter().map(|e| e.0));
                continue;
            };
            let sizes: Vec<usize> = entries.iter().map(|e| e.2).collect();
            let (chunks, oversize) = chunk_indices(&sizes, MAX_PRODUCE_BYTES);
            if !oversize.is_empty() {
                report.rejected += oversize.len();
                report.error = Some("a record is larger than the produce request limit".into());
            }
            for chunk in chunks {
                let records: Vec<Record> = chunk.iter().map(|i| entries[*i].1.clone()).collect();
                let produced = tokio::time::timeout(
                    self.timeout.saturating_mul(2),
                    client.produce(records, Compression::NoCompression),
                )
                .await;
                let failure = match produced {
                    Ok(Ok(_)) => continue,
                    Ok(Err(error)) => format!("produce failed: {error}"),
                    Err(_) => "produce timed out".to_owned(),
                };
                failed = true;
                report.retry.extend(chunk.iter().map(|i| entries[*i].0));
                report.error = Some(failure);
            }
        }
        if failed {
            self.reset();
        }
        Ok(report)
    }
}

async fn bounded<T, E: std::fmt::Display>(
    limit: Duration,
    future: impl std::future::Future<Output = Result<T, E>>,
    what: &str,
) -> Result<T, SinkError> {
    match tokio::time::timeout(limit, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(SinkError::Transient(format!("{what}: {error}"))),
        Err(_) => Err(SinkError::Transient(format!("{what}: timed out"))),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::config::Config;
    use serde_json::json;

    fn parse(extra: &str) -> Result<Config, McpError> {
        Config::parse(
            &format!(
                "[server]\nurl = \"http://127.0.0.1:7690\"\napi_key_file = \"key\"\n[audit]\npath = \"audit.jsonl\"\n{extra}"
            ),
            Path::new("/etc/browserx"),
        )
    }

    #[test]
    fn keys_are_stable_and_partitions_are_in_range() {
        let record = json!({"tool": "click", "context": {"engagement": "E1"}});
        assert_eq!(message_key(&record), "E1");
        assert_eq!(
            message_key(&json!({"tool": "click", "context": {"engagement": null}})),
            "click"
        );
        assert_eq!(partition_slot("E1", 3), partition_slot("E1", 3));
        assert!((0..50).all(|i| partition_slot(&format!("k{i}"), 4) < 4));
        let spread: std::collections::BTreeSet<usize> = (0..50)
            .map(|i| partition_slot(&format!("k{i}"), 4))
            .collect();
        assert!(spread.len() > 1);
        assert_eq!(partition_slot("x", 0), 0);
    }

    #[test]
    fn valid_and_invalid_sections() {
        let ok = parse(
            "[events]\nkind = \"kafka\"\nbrokers = [\"127.0.0.1:9092\"]\ntls = true\n[events.sasl]\nusername = \"u\"\npassword_file = \"pw\"\n",
        )
        .unwrap();
        let Some(crate::backends::export::EventsSection::Kafka(section)) = ok.events else {
            panic!("kafka section");
        };
        assert_eq!(section.topic(), "browserx.audit");
        assert_eq!(section.sasl.unwrap().mechanism, SaslMechanism::Plain);
        for (extra, what) in [
            ("[events]\nkind = \"kafka\"\n", "no brokers"),
            (
                "[events]\nkind = \"kafka\"\nbrokers = [\"kafka:9092\"]\n",
                "plain to a remote broker",
            ),
            (
                "[events]\nkind = \"kafka\"\nbrokers = [\"127.0.0.1:9092\"]\nallow_plaintext = true\n",
                "allow_plaintext without need",
            ),
            (
                "[events]\nkind = \"kafka\"\nbrokers = [\"127.0.0.1:9092\"]\ntls_ca_file = \"ca\"\n",
                "CA without tls",
            ),
            (
                "[events]\nkind = \"kafka\"\nbrokers = [\"user:pw@kafka:9092\"]\ntls = true\n",
                "credentials in a broker",
            ),
            (
                "[events]\nkind = \"kafka\"\nbrokers = [\"kafka\"]\ntls = true\n",
                "no port",
            ),
            (
                "[events]\nkind = \"kafka\"\nbrokers = [\"127.0.0.1:9092\"]\ntopic_prefix = \"a b\"\n",
                "bad prefix",
            ),
            (
                "[events]\nkind = \"kafka\"\nbrokers = [\"127.0.0.1:9092\"]\nurl = \"amqp://x\"\n",
                "amqp key on kafka",
            ),
            (
                "[events]\nkind = \"kafka\"\nbrokers = [\"127.0.0.1:9092\"]\n[events.sasl]\nmechanism = \"gssapi\"\nusername = \"u\"\n",
                "unknown mechanism",
            ),
            (
                "[events]\nkind = \"kafka\"\nbrokers = [\"127.0.0.1:9092\"]\n[events.sasl]\nusername = \"u\"\npassword_file = \"pw\"\n",
                "sasl without tls, even to a loopback bootstrap",
            ),
            (
                "[events]\nkind = \"kafka\"\nbrokers = [\"kafka:9093\"]\ntls = true\nallow_plaintext = true\n[events.sasl]\nusername = \"u\"\npassword_file = \"pw\"\n",
                "allow_plaintext on a tls connection",
            ),
            ("[events]\nkind = \"nats\"\n", "unknown kind"),
            (
                "[events]\nkind = \"none\"\nbrokers = [\"a:1\"]\n",
                "keys on none",
            ),
        ] {
            assert!(parse(extra).is_err(), "{what} must be refused");
        }
        assert!(parse("[events]\nkind = \"none\"\n").is_ok());
        assert!(
            parse("[events]\nkind = \"kafka\"\nbrokers = [\"kafka:9093\"]\ntls = true\n").is_ok()
        );
        assert!(
            parse(
                "[events]\nkind = \"kafka\"\nbrokers = [\"kafka:9092\"]\nallow_plaintext = true\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn sasl_needs_tls_or_an_explicit_opt_out() {
        let sasl = "[events.sasl]\nusername = \"u\"\npassword_file = \"pw\"\n";
        let plain = |brokers: &str, flags: &str| {
            parse(&format!(
                "[events]\nkind = \"kafka\"\nbrokers = [\"{brokers}\"]\n{flags}{sasl}"
            ))
        };
        let err = plain("127.0.0.1:9092", "").unwrap_err().to_string();
        assert!(err.contains("events.sasl without events.tls"), "{err}");
        let err = plain("kafka.example:9092", "").unwrap_err().to_string();
        assert!(err.contains("events.sasl without events.tls"), "{err}");
        // The explicit opt-out is accepted for a loopback bootstrap and a remote one.
        plain("127.0.0.1:9092", "allow_plaintext = true\n").unwrap();
        plain("kafka.example:9092", "allow_plaintext = true\n").unwrap();
        // TLS needs no opt-out.
        plain("127.0.0.1:9092", "tls = true\n").unwrap();
        // No SASL, loopback, plain: still fine.
        parse("[events]\nkind = \"kafka\"\nbrokers = [\"127.0.0.1:9092\"]\n").unwrap();
    }
}
