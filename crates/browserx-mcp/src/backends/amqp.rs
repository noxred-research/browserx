//! RabbitMQ (AMQP 0-9-1) export sink, with `lapin`.
//!
//! The sink declares one durable `topic` exchange named `<exchange_prefix>audit` inside the
//! configured virtual host, and publishes every record to it with the tool name (made safe) as
//! routing key. Publisher confirms are on: a record counts as sent when the broker confirmed
//! it, and a batch holds at most [`MAX_BATCH`] unconfirmed messages. A lost connection is
//! rebuilt on the next attempt. Nothing is ever deleted, and no queue is declared or bound:
//! consumers bind their own queues. Delivery is at-least-once; `seq` and `hash` are in the
//! body and in the message id.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use browserx_core::Secret;
use lapin::options::{BasicPublishOptions, ConfirmSelectOptions, ExchangeDeclareOptions};
use lapin::protocol::BasicProperties;
use lapin::tcp::OwnedTLSConfig;
use lapin::types::FieldTable;
use lapin::uri::{AMQPAuthority, AMQPQueryString, AMQPScheme, AMQPUri, AMQPUserInfo};
use lapin::{Channel, Confirmation, Connection, ConnectionProperties, ExchangeKind};
use serde::Deserialize;
use serde_json::Value;

use super::export::{Report, SinkError, Tuning, bad, is_loopback, resolve, secret_from};
use crate::error::McpError;

/// The environment variable that holds the password when `password_file` is not set.
pub const PASSWORD_ENV: &str = "BROWSERX_EVENTS_PASSWORD";
/// Unconfirmed messages in flight; also the largest batch.
pub const MAX_BATCH: usize = 1000;

/// `[events]` with `kind = "amqp"`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AmqpSection {
    /// `amqp://host[:port]` or `amqps://host[:port]`: no credentials, no path.
    pub url: String,
    /// The broker user.
    pub username: String,
    /// File holding the password; default: the environment variable
    /// `BROWSERX_EVENTS_PASSWORD`.
    pub password_file: Option<PathBuf>,
    /// The virtual host; BrowserX declares only inside it.
    pub vhost: String,
    /// Prefix of the exchange name; the exchange is `<prefix>audit`.
    pub exchange_prefix: String,
    /// Extra root certificates (PEM) for `amqps`.
    pub tls_ca_file: Option<PathBuf>,
    /// Allow plain `amqp` to a host that is not loopback.
    pub allow_plaintext: bool,
    /// Records per publish round.
    pub batch_size: usize,
    /// How long a batch waits for more records, in milliseconds.
    pub flush_interval_ms: u64,
    /// Records buffered in memory before new ones are dropped.
    pub buffer: usize,
    /// Timeout of connecting, declaring and confirming, in milliseconds.
    pub request_timeout_ms: u64,
}

impl Default for AmqpSection {
    fn default() -> Self {
        Self {
            url: String::new(),
            username: String::new(),
            password_file: None,
            vhost: "/".into(),
            exchange_prefix: "browserx.".into(),
            tls_ca_file: None,
            allow_plaintext: false,
            batch_size: 200,
            flush_interval_ms: 1000,
            buffer: 10_000,
            request_timeout_ms: 5000,
        }
    }
}

/// An exchange name part: `[A-Za-z0-9._-]`, at most 200 characters.
fn valid_exchange_part(text: &str) -> bool {
    text.len() <= 200
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The routing key of a tool: letters, digits, `_` and `-`; anything else becomes `_`.
pub(crate) fn routing_key(tool: &str) -> String {
    let key: String = tool
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if key.is_empty() {
        "unknown".into()
    } else {
        key
    }
}

struct Target {
    tls: bool,
    host: String,
    port: u16,
}

fn parse_url(raw: &str, allow_plaintext: bool, ca: Option<&Path>) -> Result<Target, McpError> {
    let parsed = url::Url::parse(raw).map_err(|e| bad(format!("events.url: {e}")))?;
    let tls = match parsed.scheme() {
        "amqp" => false,
        "amqps" => true,
        _ => return Err(bad("events.url must be an amqp:// or amqps:// URL")),
    };
    let Some(host) = parsed.host_str() else {
        return Err(bad("events.url needs a host"));
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(bad(
            "events.url must not carry credentials: use events.username and events.password_file",
        ));
    }
    if !matches!(parsed.path(), "" | "/") || parsed.query().is_some() || parsed.fragment().is_some()
    {
        return Err(bad(
            "events.url must be only scheme, host and port: the virtual host is events.vhost",
        ));
    }
    let loopback = is_loopback(host);
    let plaintext_remote = !tls && !loopback;
    if plaintext_remote && !allow_plaintext {
        return Err(bad(
            "events.url is plain amqp to a host that is not loopback: use amqps or set allow_plaintext = true",
        ));
    }
    if allow_plaintext && !plaintext_remote {
        return Err(bad(
            "events.allow_plaintext only applies to plain amqp to a host that is not loopback",
        ));
    }
    if ca.is_some() && !tls {
        return Err(bad("events.tls_ca_file needs an amqps:// URL"));
    }
    let bare = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    Ok(Target {
        tls,
        host: bare,
        port: parsed.port().unwrap_or(if tls { 5671 } else { 5672 }),
    })
}

impl AmqpSection {
    pub(crate) fn resolve(&mut self, base: &Path) {
        if let Some(file) = &mut self.password_file {
            resolve(file, base);
        }
        if let Some(file) = &mut self.tls_ca_file {
            resolve(file, base);
        }
    }

    pub(crate) fn validate(&self) -> Result<(), McpError> {
        parse_url(&self.url, self.allow_plaintext, self.tls_ca_file.as_deref())?;
        if self.username.is_empty() || self.username.len() > 255 {
            return Err(bad("events.username must be 1..=255 characters"));
        }
        if self.vhost.is_empty()
            || self.vhost.len() > 255
            || self.vhost.chars().any(char::is_control)
        {
            return Err(bad("events.vhost must be 1..=255 printable characters"));
        }
        if !valid_exchange_part(&self.exchange_prefix) {
            return Err(bad(
                "events.exchange_prefix may hold only letters, digits, `.`, `_` and `-` (at most 200)",
            ));
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

    /// The exchange the sink publishes to.
    #[must_use]
    pub fn exchange(&self) -> String {
        format!("{}audit", self.exchange_prefix)
    }
}

/// The AMQP sink.
pub(crate) struct Amqp {
    uri: AMQPUri,
    tls: OwnedTLSConfig,
    exchange: String,
    timeout: Duration,
    link: Option<(Connection, Channel)>,
}

impl Amqp {
    pub(crate) fn build(section: &AmqpSection) -> Result<(Self, Tuning), McpError> {
        let tuning = Tuning::check(
            "events",
            section.batch_size,
            MAX_BATCH,
            section.flush_interval_ms,
            section.buffer,
            section.request_timeout_ms,
        )?;
        let target = parse_url(
            &section.url,
            section.allow_plaintext,
            section.tls_ca_file.as_deref(),
        )?;
        let password: Secret = secret_from(section.password_file.as_deref(), PASSWORD_ENV)?
            .ok_or_else(|| {
                bad(format!(
                    "events needs a password: set password_file or the environment variable {PASSWORD_ENV}"
                ))
            })?;
        let cert_chain = match &section.tls_ca_file {
            Some(path) => Some(std::fs::read_to_string(path).map_err(|e| {
                McpError::io(format!("cannot read tls_ca_file {}", path.display()), e)
            })?),
            None => None,
        };
        let timeout_ms = u64::try_from(tuning.request_timeout.as_millis()).unwrap_or(u64::MAX);
        let uri = AMQPUri {
            scheme: if target.tls {
                AMQPScheme::AMQPS
            } else {
                AMQPScheme::AMQP
            },
            authority: AMQPAuthority {
                userinfo: AMQPUserInfo {
                    username: section.username.clone(),
                    password: password.expose().to_owned(),
                },
                host: target.host,
                port: target.port,
            },
            vhost: section.vhost.clone(),
            query: AMQPQueryString {
                connection_timeout: Some(timeout_ms),
                heartbeat: Some(30),
                ..AMQPQueryString::default()
            },
        };
        Ok((
            Self {
                uri,
                tls: OwnedTLSConfig {
                    identity: None,
                    cert_chain,
                },
                exchange: section.exchange(),
                timeout: tuning.request_timeout,
                link: None,
            },
            tuning,
        ))
    }

    pub(crate) fn reset(&mut self) {
        self.link = None;
    }

    async fn connect(&self) -> Result<(Connection, Channel), SinkError> {
        let failed = |what: &str, e: lapin::Error| SinkError::Transient(format!("{what}: {e}"));
        let runtime = lapin::runtime::default_runtime().map_err(|e| failed("runtime", e))?;
        let connection = Connection::connect_uri_with_config(
            self.uri.clone(),
            ConnectionProperties::default(),
            self.tls.clone(),
            runtime,
        )
        .await
        .map_err(|e| failed("connecting", e))?;
        let channel = connection
            .create_channel()
            .await
            .map_err(|e| failed("opening a channel", e))?;
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await
            .map_err(|e| failed("enabling publisher confirms", e))?;
        channel
            .exchange_declare(
                self.exchange.as_str().into(),
                ExchangeKind::Topic,
                ExchangeDeclareOptions {
                    durable: true,
                    ..ExchangeDeclareOptions::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(|e| failed("declaring the exchange", e))?;
        Ok((connection, channel))
    }

    pub(crate) async fn ensure_ready(&mut self) -> Result<(), SinkError> {
        if let Some((connection, channel)) = &self.link
            && connection.status().connected()
            && channel.status().connected()
        {
            return Ok(());
        }
        self.link = None;
        let link = tokio::time::timeout(self.timeout.saturating_mul(3), self.connect())
            .await
            .map_err(|_| SinkError::Transient("connecting: timed out".into()))??;
        self.link = Some(link);
        Ok(())
    }

    pub(crate) async fn send(&mut self, batch: &[Arc<Value>]) -> Result<Report, SinkError> {
        let Some((_, channel)) = &self.link else {
            return Err(SinkError::Transient("not connected".into()));
        };
        let mut report = Report::default();
        let mut confirms = Vec::with_capacity(batch.len());
        for (index, record) in batch.iter().enumerate() {
            let tool = record.get("tool").and_then(Value::as_str).unwrap_or("");
            let hash = record.get("hash").and_then(Value::as_str).unwrap_or("");
            let properties = BasicProperties::default()
                .with_delivery_mode(2)
                .with_content_type("application/json".into())
                .with_message_id(hash.into());
            let published = channel
                .basic_publish(
                    self.exchange.as_str().into(),
                    routing_key(tool).into(),
                    BasicPublishOptions::default(),
                    record.to_string().as_bytes(),
                    properties,
                )
                .await;
            match published {
                Ok(confirm) => confirms.push((index, confirm)),
                Err(error) => {
                    report.retry.extend(index..batch.len());
                    report.error = Some(format!("publish failed: {error}"));
                    break;
                }
            }
        }
        let waiting = async {
            let mut nacked: Vec<(usize, String)> = Vec::new();
            for (index, confirm) in confirms {
                match confirm.await {
                    Ok(Confirmation::Ack(_) | Confirmation::NotRequested) => {}
                    Ok(Confirmation::Nack(_)) => {
                        nacked.push((index, "the broker did not confirm a message".into()));
                    }
                    Err(error) => nacked.push((index, format!("confirmation failed: {error}"))),
                }
            }
            nacked
        };
        match tokio::time::timeout(self.timeout, waiting).await {
            Ok(nacked) => {
                for (index, message) in nacked {
                    report.retry.push(index);
                    report.error = Some(message);
                }
            }
            Err(_) => {
                // Unknown which were confirmed: send all of them again (at-least-once).
                report.retry = (0..batch.len()).collect();
                report.error = Some("waiting for publisher confirms timed out".into());
            }
        }
        report.retry.sort_unstable();
        report.retry.dedup();
        if !report.retry.is_empty() {
            self.link = None;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::backends::export::EventsSection;
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
    fn routing_keys_are_safe() {
        assert_eq!(routing_key("open_page"), "open_page");
        assert_eq!(routing_key("a.b*c#d e"), "a_b_c_d_e");
        assert_eq!(routing_key(""), "unknown");
        assert_eq!(routing_key(&"x".repeat(100)).len(), 64);
    }

    #[test]
    fn valid_and_invalid_sections() {
        let ok = parse(
            "[events]\nkind = \"amqp\"\nurl = \"amqp://127.0.0.1\"\nusername = \"bx\"\npassword_file = \"pw\"\n",
        )
        .unwrap();
        let Some(EventsSection::Amqp(section)) = ok.events else {
            panic!("amqp section");
        };
        assert_eq!(
            (section.vhost.as_str(), section.exchange().as_str()),
            ("/", "browserx.audit")
        );
        for (extra, what) in [
            (
                "[events]\nkind = \"amqp\"\nurl = \"amqp://u:p@127.0.0.1\"\nusername = \"bx\"\n",
                "password in URL",
            ),
            (
                "[events]\nkind = \"amqp\"\nurl = \"amqp://127.0.0.1/vh\"\nusername = \"bx\"\n",
                "vhost in URL",
            ),
            (
                "[events]\nkind = \"amqp\"\nurl = \"amqp://rabbit\"\nusername = \"bx\"\n",
                "plain to a remote host",
            ),
            (
                "[events]\nkind = \"amqp\"\nurl = \"http://127.0.0.1\"\nusername = \"bx\"\n",
                "wrong scheme",
            ),
            (
                "[events]\nkind = \"amqp\"\nurl = \"amqp://127.0.0.1\"\n",
                "no username",
            ),
            (
                "[events]\nkind = \"amqp\"\nurl = \"amqp://127.0.0.1\"\nusername = \"bx\"\ntls_ca_file = \"ca\"\n",
                "CA for plain amqp",
            ),
            (
                "[events]\nkind = \"amqp\"\nurl = \"amqps://rabbit\"\nusername = \"bx\"\nallow_plaintext = true\n",
                "allow_plaintext on amqps",
            ),
            (
                "[events]\nkind = \"amqp\"\nurl = \"amqp://127.0.0.1\"\nusername = \"bx\"\nbrokers = [\"a:1\"]\n",
                "kafka key on amqp",
            ),
            (
                "[events]\nkind = \"amqp\"\nurl = \"amqp://127.0.0.1\"\nusername = \"bx\"\nexchange_prefix = \"a/b\"\n",
                "bad exchange prefix",
            ),
            (
                "[events]\nkind = \"amqp\"\nurl = \"amqp://127.0.0.1\"\nusername = \"bx\"\nbatch_size = 5000\n",
                "batch above the in-flight bound",
            ),
        ] {
            assert!(parse(extra).is_err(), "{what} must be refused");
        }
        assert!(parse("[events]\nkind = \"amqp\"\nurl = \"amqps://rabbit:5671\"\nusername = \"bx\"\nvhost = \"audit\"\n").is_ok());
    }
}
