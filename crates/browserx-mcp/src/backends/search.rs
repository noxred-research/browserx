//! OpenSearch and Elasticsearch export sink over the REST API subset both engines share:
//! `GET /`, composable `_index_template`, index and alias management, and `_bulk`.
//!
//! * At startup the sink asks the server which engine and version it is, and refuses a server
//!   that differs from `kind` or is older than OpenSearch 2.0 / Elasticsearch 7.10.
//! * It owns the index `<index_prefix>audit-v1`, written through the alias
//!   `<index_prefix>audit`, and the index template `<index_prefix>audit`. The mapping version
//!   is kept in the index's `_meta.browserx_schema_version`; a newer index than this build is
//!   refused. Nothing outside `index_prefix` is read, written or deleted.
//! * Documents are indexed with `_id` = the record's hash, so a record that is sent twice
//!   (at-least-once delivery) replaces itself.
//! * A bulk request answers per item: only items that failed with 429 or 5xx are sent again.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use browserx_core::Secret;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::export::{
    Extracted, MAX_BODY_BYTES, Report, SinkError, Tuning, bad, base_of, chunk_indices, http_client,
    http_url, resolve, secret_from, short,
};
use crate::error::McpError;

/// The environment variable that holds the password when `password_file` is not set.
pub const PASSWORD_ENV: &str = "BROWSERX_SEARCH_PASSWORD";
const MAX_BATCH: usize = 5000;
/// The newest mapping version this build knows.
const LATEST: u32 = 1;
const ARGUMENTS_TEXT_CHARS: usize = 16 * 1024;

/// Which engine the server must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchKind {
    /// OpenSearch 2.0 or newer.
    Opensearch,
    /// Elasticsearch 7.10 or newer.
    Elasticsearch,
}

/// `[search]`: OpenSearch or Elasticsearch.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchSection {
    /// `opensearch` or `elasticsearch`; the server is checked against it.
    pub kind: SearchKind,
    /// Base URL, for example `https://search.example.test:9200`. No credentials.
    pub url: String,
    /// Prefix of every index, alias and template name BrowserX owns.
    #[serde(default = "default_prefix")]
    pub index_prefix: String,
    /// Basic authentication user (with `password_file` or `BROWSERX_SEARCH_PASSWORD`).
    #[serde(default)]
    pub username: Option<String>,
    /// File holding the basic authentication password.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// File holding an Elasticsearch API key (the base64 `encoded` value).
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    /// Extra root certificates (PEM) for an `https` URL.
    #[serde(default)]
    pub tls_ca_file: Option<PathBuf>,
    /// Allow plain `http` to a host that is not loopback.
    #[serde(default)]
    pub allow_plaintext: bool,
    /// Documents per bulk request.
    #[serde(default = "default_batch")]
    pub batch_size: usize,
    /// How long a batch waits for more records, in milliseconds.
    #[serde(default = "default_flush")]
    pub flush_interval_ms: u64,
    /// Records buffered in memory before new ones are dropped.
    #[serde(default = "default_buffer")]
    pub buffer: usize,
    /// Timeout of one HTTP request, in milliseconds.
    #[serde(default = "default_timeout")]
    pub request_timeout_ms: u64,
}

fn default_prefix() -> String {
    "browserx-".into()
}
fn default_batch() -> usize {
    500
}
fn default_flush() -> u64 {
    1000
}
fn default_buffer() -> usize {
    10_000
}
fn default_timeout() -> u64 {
    5000
}

/// An index prefix both engines accept: lowercase letters, digits, `_`, `-`, `.`; not starting
/// with `_`, `-`, `+` or `.`.
pub(crate) fn valid_prefix(prefix: &str) -> bool {
    let mut chars = prefix.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && prefix.len() <= 100
        && prefix
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.'))
}

impl SearchSection {
    pub(crate) fn resolve(&mut self, base: &Path) {
        for file in [
            &mut self.password_file,
            &mut self.api_key_file,
            &mut self.tls_ca_file,
        ]
        .into_iter()
        .flatten()
        {
            resolve(file, base);
        }
    }

    pub(crate) fn validate(&self) -> Result<(), McpError> {
        http_url(
            "search.url",
            &self.url,
            self.allow_plaintext,
            self.tls_ca_file.as_deref(),
        )?;
        if !valid_prefix(&self.index_prefix) {
            return Err(bad(
                "search.index_prefix must be lowercase letters, digits, `_`, `-` or `.` (at most 100), and start with a letter or digit",
            ));
        }
        match (&self.username, &self.password_file, &self.api_key_file) {
            (Some(_), _, Some(_)) => {
                return Err(bad("search: use username or api_key_file, not both"));
            }
            (None, Some(_), _) => {
                return Err(bad("search.password_file needs search.username"));
            }
            (Some(name), _, None) if name.is_empty() || name.len() > 256 => {
                return Err(bad("search.username must be 1..=256 characters"));
            }
            (_, _, Some(_)) if self.kind == SearchKind::Opensearch => {
                return Err(bad(
                    "search.api_key_file is supported for kind = \"elasticsearch\" only: OpenSearch has no API keys",
                ));
            }
            _ => {}
        }
        Tuning::check(
            "search",
            self.batch_size,
            MAX_BATCH,
            self.flush_interval_ms,
            self.buffer,
            self.request_timeout_ms,
        )?;
        Ok(())
    }
}

enum Auth {
    None,
    Basic(String, Secret),
    ApiKey(HeaderValue),
}

/// The mapping properties added by each schema version.
fn mapping_properties(version: u32) -> Value {
    match version {
        1 => json!({
            "seq": {"type": "long"},
            "ts": {"type": "date"},
            "prev": {"type": "keyword"},
            "hash": {"type": "keyword"},
            "phase": {"type": "keyword"},
            "tool": {"type": "keyword"},
            "outcome": {"type": "keyword"},
            "detail": {"type": "text"},
            "duration_ms": {"type": "long"},
            "engagement": {"type": "keyword"},
            "operator": {"type": "keyword"},
            "reason": {"type": "keyword"},
            "action_class": {"type": "keyword"},
            "trace_id": {"type": "keyword"},
            "arguments_text": {"type": "text"},
            "caller": {"type": "object", "enabled": false},
            "context": {"type": "object", "enabled": false},
            "arguments": {"type": "object", "enabled": false},
        }),
        _ => json!({}),
    }
}

/// The mapping of a schema version, as the body of an index or of a mapping update.
fn mapping_body(from: u32, to: u32) -> Value {
    let mut properties = Map::new();
    for version in (from + 1)..=to {
        if let Value::Object(added) = mapping_properties(version) {
            properties.extend(added);
        }
    }
    json!({
        "dynamic": false,
        "_meta": {"browserx_schema_version": to},
        "properties": properties,
    })
}

/// The document of a record: the record itself plus the extracted, searchable fields.
pub(crate) fn document(record: &Value) -> Value {
    let extracted = Extracted::of(record);
    let mut doc = record.as_object().cloned().unwrap_or_default();
    doc.insert("engagement".into(), json!(extracted.engagement));
    doc.insert("operator".into(), json!(extracted.operator));
    doc.insert("reason".into(), json!(extracted.reason));
    doc.insert("action_class".into(), json!(extracted.action_class));
    doc.insert("trace_id".into(), json!(extracted.trace_id));
    let mut text = String::new();
    if let Some(arguments) = record.get("arguments") {
        flatten(arguments, "", &mut text);
    }
    doc.insert("arguments_text".into(), json!(text));
    Value::Object(doc)
}

/// `path=value` lines of every scalar in `value`, up to a bounded size.
fn flatten(value: &Value, path: &str, out: &mut String) {
    if out.len() >= ARGUMENTS_TEXT_CHARS {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                let next = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                flatten(inner, &next, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                flatten(item, path, out);
            }
        }
        Value::Null => {}
        scalar => {
            let text = match scalar {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(path);
            out.push('=');
            out.push_str(&text);
            if out.len() > ARGUMENTS_TEXT_CHARS {
                let mut cut = ARGUMENTS_TEXT_CHARS;
                while !out.is_char_boundary(cut) {
                    cut -= 1;
                }
                out.truncate(cut);
            }
        }
    }
}

/// `major.minor` of a version string such as `8.15.3` or `2.19.1-SNAPSHOT`.
fn version_pair(number: &str) -> Option<(u32, u32)> {
    let mut parts = number.split(['.', '-']);
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// Checks that the server answering `GET /` is the configured engine and a supported version.
fn check_engine(kind: SearchKind, info: &Value, base: &str) -> Result<(), SinkError> {
    let number = info["version"]["number"].as_str().unwrap_or("");
    let distribution = info["version"]["distribution"].as_str();
    let (engine, minimum) = match (kind, distribution) {
        (SearchKind::Opensearch, Some("opensearch")) => ("OpenSearch", (2, 0)),
        (SearchKind::Elasticsearch, None) => ("Elasticsearch", (7, 10)),
        (kind, found) => {
            return Err(SinkError::Fatal(format!(
                "search.kind is \"{}\" but the server at {base} is {} {number}",
                if kind == SearchKind::Opensearch {
                    "opensearch"
                } else {
                    "elasticsearch"
                },
                match found {
                    None => "Elasticsearch",
                    Some("opensearch") => "OpenSearch",
                    Some(other) => other,
                },
            )));
        }
    };
    let Some(found) = version_pair(number) else {
        return Err(SinkError::Fatal(format!(
            "cannot read the server version `{number}`"
        )));
    };
    if found < minimum {
        return Err(SinkError::Fatal(format!(
            "{engine} {number} is too old: BrowserX needs {engine} {}.{} or newer",
            minimum.0, minimum.1
        )));
    }
    Ok(())
}

/// The OpenSearch / Elasticsearch sink.
pub(crate) struct Search {
    http: reqwest::Client,
    base: String,
    kind: SearchKind,
    auth: Auth,
    prefix: String,
    ready: bool,
}

impl Search {
    pub(crate) fn build(section: &SearchSection) -> Result<(Self, Tuning), McpError> {
        let tuning = Tuning::check(
            "search",
            section.batch_size,
            MAX_BATCH,
            section.flush_interval_ms,
            section.buffer,
            section.request_timeout_ms,
        )?;
        let url = http_url(
            "search.url",
            &section.url,
            section.allow_plaintext,
            section.tls_ca_file.as_deref(),
        )?;
        let auth = match (&section.username, &section.api_key_file) {
            (Some(user), None) => {
                let password = secret_from(section.password_file.as_deref(), PASSWORD_ENV)?
                    .ok_or_else(|| {
                        bad(format!(
                            "search.username needs a password: set password_file or the environment variable {PASSWORD_ENV}"
                        ))
                    })?;
                Auth::Basic(user.clone(), password)
            }
            (None, Some(file)) => {
                let key = crate::config::read_secret(file)?;
                let mut value = HeaderValue::from_str(&format!("ApiKey {}", key.expose()))
                    .map_err(|_| bad("search.api_key_file does not hold a valid API key"))?;
                value.set_sensitive(true);
                Auth::ApiKey(value)
            }
            _ => Auth::None,
        };
        Ok((
            Self {
                http: http_client(section.tls_ca_file.as_deref(), tuning.request_timeout)?,
                base: base_of(&url),
                kind: section.kind,
                auth,
                prefix: section.index_prefix.clone(),
                ready: false,
            },
            tuning,
        ))
    }

    pub(crate) fn kind_name(&self) -> &'static str {
        match self.kind {
            SearchKind::Opensearch => "opensearch",
            SearchKind::Elasticsearch => "elasticsearch",
        }
    }

    fn alias(&self) -> String {
        format!("{}audit", self.prefix)
    }

    fn index(&self) -> String {
        format!("{}audit-v1", self.prefix)
    }

    /// One request; the status and the parsed JSON body (or `Null` when there is none).
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Vec<u8>>,
        content_type: &str,
    ) -> Result<(u16, Value), SinkError> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base))
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .header(reqwest::header::ACCEPT, "application/json");
        request = match &self.auth {
            Auth::None => request,
            Auth::Basic(user, password) => request.basic_auth(user, Some(password.expose())),
            Auth::ApiKey(value) => request.header(AUTHORIZATION, value.clone()),
        };
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request
            .send()
            .await
            .map_err(|e| SinkError::Transient(format!("request failed: {}", e.without_url())))?;
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }

    /// A successful JSON call, or the error class of the status.
    async fn call_ok(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, SinkError> {
        let bytes = body.map(|b| b.to_string().into_bytes());
        let (status, value) = self.call(method, path, bytes, "application/json").await?;
        if (200..300).contains(&status) {
            return Ok(value);
        }
        Err(classify(status, &value))
    }

    pub(crate) async fn ensure_ready(&mut self) -> Result<(), SinkError> {
        if self.ready {
            return Ok(());
        }
        // Engine and version.
        let info = self.call_ok(reqwest::Method::GET, "/", None).await?;
        check_engine(self.kind, &info, &self.base)?;

        let index = self.index();
        let alias = self.alias();
        // The template covers later index generations; the index below is created explicitly.
        self.call_ok(
            reqwest::Method::PUT,
            &format!("/_index_template/{alias}"),
            Some(json!({
                "index_patterns": [format!("{}audit-v*", self.prefix)],
                "priority": 200,
                "template": {
                    "settings": {"number_of_shards": 1},
                    "mappings": mapping_body(0, LATEST),
                },
                "_meta": {"owner": "browserx", "browserx_schema_version": LATEST},
            })),
        )
        .await?;

        // The index: create when missing, otherwise read the schema version from its metadata.
        let (status, existing) = self
            .call(
                reqwest::Method::GET,
                &format!("/{index}"),
                None,
                "application/json",
            )
            .await?;
        let version = match status {
            200..=299 => existing[&index]["mappings"]["_meta"]["browserx_schema_version"]
                .as_u64()
                .ok_or_else(|| {
                    SinkError::Fatal(format!(
                        "the index `{index}` exists but was not created by BrowserX: choose another search.index_prefix"
                    ))
                })?,
            404 => {
                let created = self
                    .call(
                        reqwest::Method::PUT,
                        &format!("/{index}"),
                        Some(
                            json!({
                                "settings": {"number_of_shards": 1},
                                "mappings": mapping_body(0, LATEST),
                                "aliases": {alias.clone(): {"is_write_index": true}},
                            })
                            .to_string()
                            .into_bytes(),
                        ),
                        "application/json",
                    )
                    .await?;
                let already = created.0 == 400
                    && created.1["error"]["type"] == "resource_already_exists_exception";
                if !(200..300).contains(&created.0) && !already {
                    return Err(classify(created.0, &created.1));
                }
                u64::from(LATEST)
            }
            other => return Err(classify(other, &existing)),
        };
        let version = u32::try_from(version).unwrap_or(u32::MAX);
        if version > LATEST {
            return Err(SinkError::Fatal(format!(
                "the index `{index}` has schema version {version}, but this build supports up to {LATEST}: upgrade BrowserX or use another search.index_prefix"
            )));
        }
        if version < LATEST {
            self.call_ok(
                reqwest::Method::PUT,
                &format!("/{index}/_mapping"),
                Some(mapping_body(version, LATEST)),
            )
            .await?;
        }
        // The alias: idempotent.
        let (status, answer) = self
            .call(
                reqwest::Method::PUT,
                &format!("/{index}/_alias/{alias}"),
                Some(json!({"is_write_index": true}).to_string().into_bytes()),
                "application/json",
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(if status == 400 {
                SinkError::Fatal(format!(
                    "cannot point the alias `{alias}` at `{index}`: {}",
                    error_text(&answer)
                ))
            } else {
                classify(status, &answer)
            });
        }
        self.ready = true;
        Ok(())
    }

    pub(crate) async fn send(&mut self, batch: &[Arc<Value>]) -> Result<Report, SinkError> {
        let alias = self.alias();
        let mut lines: Vec<Vec<u8>> = Vec::with_capacity(batch.len());
        for record in batch {
            let id = record.get("hash").and_then(Value::as_str).unwrap_or("");
            let mut line = json!({"index": {"_index": alias, "_id": id}})
                .to_string()
                .into_bytes();
            line.push(b'\n');
            line.extend_from_slice(document(record).to_string().as_bytes());
            line.push(b'\n');
            lines.push(line);
        }
        let sizes: Vec<usize> = lines.iter().map(Vec::len).collect();
        let (chunks, oversize) = chunk_indices(&sizes, MAX_BODY_BYTES);
        let mut report = Report {
            rejected: oversize.len(),
            ..Report::default()
        };
        if !oversize.is_empty() {
            report.error = Some("a document is larger than the request limit".into());
        }
        for chunk in chunks {
            let body: Vec<u8> = chunk
                .iter()
                .flat_map(|i| lines[*i].iter().copied())
                .collect();
            let result = self
                .call(
                    reqwest::Method::POST,
                    "/_bulk?filter_path=errors,items.*.status,items.*.error.type,items.*.error.reason",
                    Some(body),
                    "application/x-ndjson",
                )
                .await;
            let (status, answer) = match result {
                Ok(pair) => pair,
                Err(SinkError::Transient(message)) => {
                    report.retry.extend(chunk);
                    report.error = Some(message);
                    continue;
                }
                Err(other) => return Err(other),
            };
            if status == 404 {
                // The alias or index is gone (for example removed by an operator): prepare again.
                self.ready = false;
                report.retry.extend(chunk);
                report.error = Some(format!(
                    "the index `{alias}` does not exist: {}",
                    short(&error_text(&answer))
                ));
                continue;
            }
            if !(200..300).contains(&status) {
                match classify(status, &answer) {
                    SinkError::Transient(message) => {
                        report.retry.extend(chunk);
                        report.error = Some(message);
                    }
                    SinkError::Rejected(message) => {
                        report.rejected += chunk.len();
                        report.error = Some(message);
                    }
                    SinkError::Fatal(message) => return Err(SinkError::Fatal(message)),
                }
                continue;
            }
            if answer["errors"] != json!(true) {
                continue;
            }
            let items = answer["items"].as_array().cloned().unwrap_or_default();
            for (position, index) in chunk.iter().enumerate() {
                let item = items.get(position).and_then(|i| i.get("index"));
                let status = item.and_then(|i| i["status"].as_u64()).unwrap_or(500);
                if (200..300).contains(&status) {
                    continue;
                }
                let reason = item.map_or_else(String::new, |i| {
                    format!(
                        "{}: {}",
                        i["error"]["type"].as_str().unwrap_or("error"),
                        i["error"]["reason"].as_str().unwrap_or("")
                    )
                });
                if status == 429 || status >= 500 {
                    report.retry.push(*index);
                } else {
                    report.rejected += 1;
                }
                report.error = Some(format!("item failed with {status}: {}", short(&reason)));
            }
        }
        Ok(report)
    }
}

fn error_text(body: &Value) -> String {
    let error = &body["error"];
    match error {
        Value::Object(_) => format!(
            "{}: {}",
            error["type"].as_str().unwrap_or("error"),
            error["reason"].as_str().unwrap_or("")
        ),
        Value::String(text) => text.clone(),
        _ => String::new(),
    }
}

/// The class of an HTTP error status.
fn classify(status: u16, body: &Value) -> SinkError {
    let message = format!("the server answered {status}: {}", short(&error_text(body)));
    match status {
        401 | 403 => SinkError::Rejected(format!("the server refused the credentials ({status})")),
        429 | 500..=599 => SinkError::Transient(message),
        _ => SinkError::Rejected(message),
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
    fn valid_and_invalid_sections() {
        let ok = parse("[search]\nkind = \"opensearch\"\nurl = \"https://os:9200\"\nusername = \"u\"\npassword_file = \"pw\"\n").unwrap();
        let section = ok.search.unwrap();
        assert_eq!(section.index_prefix, "browserx-");
        assert_eq!(
            section.password_file.unwrap(),
            Path::new("/etc/browserx/pw")
        );
        for (extra, what) in [
            (
                "[search]\nkind = \"solr\"\nurl = \"http://127.0.0.1:9200\"\n",
                "unknown kind",
            ),
            ("[search]\nurl = \"http://127.0.0.1:9200\"\n", "no kind"),
            (
                "[search]\nkind = \"opensearch\"\nurl = \"http://127.0.0.1:9200\"\napi_key_file = \"k\"\n",
                "api key on OpenSearch",
            ),
            (
                "[search]\nkind = \"elasticsearch\"\nurl = \"http://127.0.0.1:9200\"\nusername = \"u\"\napi_key_file = \"k\"\n",
                "both auths",
            ),
            (
                "[search]\nkind = \"elasticsearch\"\nurl = \"http://127.0.0.1:9200\"\npassword_file = \"p\"\n",
                "password without user",
            ),
            (
                "[search]\nkind = \"elasticsearch\"\nurl = \"http://u:p@127.0.0.1:9200\"\n",
                "password in URL",
            ),
            (
                "[search]\nkind = \"elasticsearch\"\nurl = \"http://es:9200\"\n",
                "plain to a remote host",
            ),
            (
                "[search]\nkind = \"elasticsearch\"\nurl = \"http://127.0.0.1:9200\"\nindex_prefix = \"Bad/\"\n",
                "bad prefix",
            ),
            (
                "[search]\nkind = \"elasticsearch\"\nurl = \"http://127.0.0.1:9200\"\nindex_prefix = \"_x\"\n",
                "prefix starting with _",
            ),
            (
                "[search]\nkind = \"elasticsearch\"\nurl = \"http://127.0.0.1:9200\"\nindices = 3\n",
                "unknown key",
            ),
        ] {
            assert!(parse(extra).is_err(), "{what} must be refused");
        }
        assert!(parse("[search]\nkind = \"elasticsearch\"\nurl = \"https://es:9200\"\napi_key_file = \"k\"\n").is_ok());
    }

    #[test]
    fn documents_extract_fields_and_flatten_arguments() {
        let record = json!({"seq": 1, "ts": "2026-01-01T00:00:00Z", "hash": "h", "tool": "open_page",
            "arguments": {"url": "https://app.example.test/a", "opts": {"retries": 2}, "tags": ["x", "y"]},
            "context": {"engagement": "E1", "reason": "out_of_scope"}});
        let doc = document(&record);
        assert_eq!(doc["engagement"], "E1");
        assert_eq!(doc["reason"], "out_of_scope");
        assert_eq!(doc["seq"], 1);
        let text = doc["arguments_text"].as_str().unwrap();
        assert!(text.contains("url=https://app.example.test/a") && text.contains("opts.retries=2"));
        assert!(text.contains("tags=x") && text.contains("tags=y"));
        let big = json!({"arguments": {"blob": "é".repeat(40_000)}});
        assert!(document(&big)["arguments_text"].as_str().unwrap().len() <= ARGUMENTS_TEXT_CHARS);
    }

    #[test]
    fn versions_and_mappings() {
        assert_eq!(version_pair("8.15.3"), Some((8, 15)));
        assert_eq!(version_pair("2.19.1-SNAPSHOT"), Some((2, 19)));
        assert_eq!(version_pair("x"), None);
        let body = mapping_body(0, LATEST);
        assert_eq!(body["_meta"]["browserx_schema_version"], LATEST);
        assert_eq!(body["properties"]["hash"]["type"], "keyword");
        assert_eq!(body["properties"]["seq"]["type"], "long");
        assert_eq!(body["properties"]["ts"]["type"], "date");
        assert_eq!(body["properties"]["detail"]["type"], "text");
        assert_eq!(mapping_body(LATEST, LATEST)["properties"], json!({}));
    }

    #[test]
    fn engine_and_version_are_checked() {
        let os = |n: &str| json!({"version": {"number": n, "distribution": "opensearch"}});
        let es = |n: &str| json!({"version": {"number": n, "build_flavor": "default"}});
        let ok = |kind, info: Value| check_engine(kind, &info, "http://x").is_ok();
        assert!(ok(SearchKind::Opensearch, os("2.0.0")));
        assert!(ok(SearchKind::Opensearch, os("2.19.1")));
        assert!(ok(SearchKind::Elasticsearch, es("7.10.2")));
        assert!(ok(SearchKind::Elasticsearch, es("8.15.3")));
        assert!(!ok(SearchKind::Opensearch, os("1.3.14")));
        assert!(!ok(SearchKind::Elasticsearch, es("7.9.3")));
        assert!(!ok(SearchKind::Elasticsearch, os("2.19.1")));
        assert!(!ok(SearchKind::Opensearch, es("8.15.3")));
        assert!(!ok(
            SearchKind::Opensearch,
            json!({"version": {"number": "2.1.0", "distribution": "other"}})
        ));
        assert!(!ok(SearchKind::Elasticsearch, json!({})));
        let error = check_engine(SearchKind::Opensearch, &es("8.15.3"), "http://x").unwrap_err();
        assert!(error.to_string().contains("search.kind"), "{error}");
    }

    #[test]
    fn error_classes() {
        assert!(matches!(
            classify(503, &Value::Null),
            SinkError::Transient(_)
        ));
        assert!(matches!(
            classify(429, &Value::Null),
            SinkError::Transient(_)
        ));
        assert!(matches!(
            classify(401, &Value::Null),
            SinkError::Rejected(_)
        ));
        assert!(matches!(
            classify(400, &Value::Null),
            SinkError::Rejected(_)
        ));
    }
}
