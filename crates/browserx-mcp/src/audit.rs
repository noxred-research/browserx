//! The append-only audit log: one JSON object per line for every tool call.
//!
//! Each entry carries the caller, the engagement context (operator, authorization note,
//! engagement id), the arguments (secrets redacted), the outcome and the SHA-256 hash of the
//! previous entry, so a deleted or edited line breaks the chain and [`verify`] finds it. A call
//! that changes something is recorded twice: an `intent` entry before it runs (the call is
//! refused when that write fails) and a `result` entry after. The file is created with mode
//! `0600` and opened in append mode; each record locks the file while it reads the tail and
//! appends, so independent processes share one chain. For stronger guarantees set the
//! append-only attribute (`chattr +a`).

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead as _, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use std::sync::Arc;

use crate::backends::export::Exporter;
use crate::redact::Redactor;

/// The hash of the entry before the first one.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Who made a call.
#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct Caller {
    /// `stdio` or `http`.
    pub transport: &'static str,
    /// Client name from `initialize`, when known.
    pub client_name: Option<String>,
    /// The peer address of an HTTP call.
    pub remote: Option<String>,
    /// The authenticated principal (`stdio`, or `http:` and a digest prefix of the token).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
}

/// The accountability fields recorded in every entry.
#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct Context {
    /// Engagement identifier.
    pub engagement: Option<String>,
    /// The accountable operator.
    pub operator: Option<String>,
    /// Why the testing is authorized.
    pub authorization_note: Option<String>,
    /// SHA-256 of the signed engagement manifest in force.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_digest: Option<String>,
    /// SHA-256 of the scope grant in force.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_digest: Option<String>,
}

/// The kind of audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Written before a call changes anything.
    Intent,
    /// The final outcome of a call.
    Result,
}

impl Phase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Result => "result",
        }
    }
}

/// One audit record to write.
pub struct Entry<'a> {
    /// Intent or result.
    pub phase: Phase,
    /// Who called.
    pub caller: &'a Caller,
    /// Tool name.
    pub tool: &'a str,
    /// Arguments as received (redacted before writing).
    pub arguments: &'a Value,
    /// `ok`, `error`, `refused`, `intent`.
    pub outcome: &'a str,
    /// Short note (error message, refusal reason).
    pub detail: Option<&'a str>,
    /// Wall time of the call in milliseconds.
    pub duration_ms: Option<u64>,
    /// Per-call facts recorded with the context: the ledger flags `{A,B,C}`, the action class,
    /// the reason code of a refusal, the trace id. Merged into the entry's `context`, so the
    /// hash chain covers them.
    pub extra: Option<&'a Value>,
}

/// The audit log writer.
pub struct Audit {
    path: PathBuf,
    context: Context,
    redactor: Redactor,
    exporter: Option<Arc<Exporter>>,
}

impl std::fmt::Debug for Audit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Audit").field("path", &self.path).finish()
    }
}

/// `value` as JSON text with object keys sorted at every level.
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    fn render(value: &Value, out: &mut String) {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&Value::String(key.clone()).to_string());
                    out.push(':');
                    render(&map[key], out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    render(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut out = String::new();
    render(value, &mut out);
    out
}

/// Hex SHA-256 of `text`.
#[must_use]
pub fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// The hash of an entry given its fields. Fixed field order, so it does not depend on how a
/// JSON library orders object keys.
struct HashInput<'a> {
    seq: u64,
    ts: &'a str,
    prev: &'a str,
    phase: &'a str,
    tool: &'a str,
    outcome: &'a str,
    detail: &'a str,
    duration_ms: u64,
    arguments: &'a Value,
    caller: &'a Value,
    context: &'a Value,
}

impl HashInput<'_> {
    fn hash(&self) -> String {
        let material = [
            self.seq.to_string(),
            self.ts.to_owned(),
            self.prev.to_owned(),
            self.phase.to_owned(),
            self.tool.to_owned(),
            self.outcome.to_owned(),
            self.detail.to_owned(),
            self.duration_ms.to_string(),
            sha256_hex(&canonical_json(self.arguments)),
            sha256_hex(&canonical_json(self.caller)),
            sha256_hex(&canonical_json(self.context)),
        ]
        .join("\u{1f}");
        sha256_hex(&material)
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

impl Audit {
    /// Opens (creating it) the log at `path` and continues its hash chain.
    ///
    /// # Errors
    /// When the file or its directory cannot be created, the file cannot be locked or the
    /// existing tail cannot be read.
    pub fn open(path: &Path, context: Context, redactor: Redactor) -> io::Result<Self> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        let mut file = Self::locked_file(path)?;
        Self::tail_state(&mut file)?;
        Ok(Self {
            path: path.to_path_buf(),
            context,
            redactor,
            exporter: None,
        })
    }

    /// Copies every record written from now on to the export sinks. Exporting never fails or
    /// slows a write: the local chain stays authoritative.
    #[must_use]
    pub fn with_exporter(mut self, exporter: Arc<Exporter>) -> Self {
        self.exporter = Some(exporter);
        self
    }

    /// The export fan-out, when sinks are configured.
    #[must_use]
    pub fn exporter(&self) -> Option<&Arc<Exporter>> {
        self.exporter.as_ref()
    }

    /// Opens an independent handle; dropping it releases the exclusive lock.
    fn locked_file(path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.create(true).read(true).append(true);
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        file.lock()?;
        Ok(file)
    }

    /// The sequence number and hash of the last entry, read while holding the file lock.
    fn tail_state(file: &mut File) -> io::Result<(u64, String)> {
        let length = file.metadata()?.len();
        let window = length.min(1024 * 1024);
        file.seek(SeekFrom::Start(length - window))?;
        let mut tail = Vec::new();
        std::io::Read::take(&mut *file, window).read_to_end(&mut tail)?;
        let text = String::from_utf8_lossy(&tail);
        let Some(last) = text.lines().rev().find(|line| !line.trim().is_empty()) else {
            return Ok((0, GENESIS.to_owned()));
        };
        let value: Value = serde_json::from_str(last)
            .map_err(|_| io::Error::other("the audit log's last line is not valid JSON"))?;
        let seq = value["seq"]
            .as_u64()
            .ok_or_else(|| io::Error::other("the audit log's last line has no sequence number"))?;
        let hash = value["hash"]
            .as_str()
            .ok_or_else(|| io::Error::other("the audit log's last line has no hash"))?
            .to_owned();
        Ok((seq, hash))
    }

    /// The log's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one entry and returns its sequence number.
    ///
    /// # Errors
    /// When opening, locking, reading the tail or writing fails. A broken tail is not reset.
    pub fn record(&self, entry: &Entry<'_>) -> io::Result<u64> {
        let arguments = self.redactor.redacted(entry.arguments);
        let caller = serde_json::to_value(entry.caller).unwrap_or(Value::Null);
        let mut context = serde_json::to_value(&self.context).unwrap_or(Value::Null);
        if let (Some(map), Some(Value::Object(extra))) = (context.as_object_mut(), entry.extra) {
            for (key, value) in extra {
                map.insert(key.clone(), self.redactor.redacted(value));
            }
        }
        let detail = self.redactor.text(entry.detail.unwrap_or(""));
        let mut file = Self::locked_file(&self.path)?;
        let (last_seq, prev) = Self::tail_state(&mut file)?;
        let seq = last_seq
            .checked_add(1)
            .ok_or_else(|| io::Error::other("the audit log's sequence number is exhausted"))?;
        let ts = now_rfc3339();
        let duration_ms = entry.duration_ms.unwrap_or(0);
        let hash = HashInput {
            seq,
            ts: &ts,
            prev: &prev,
            phase: entry.phase.as_str(),
            tool: entry.tool,
            outcome: entry.outcome,
            detail: &detail,
            duration_ms,
            arguments: &arguments,
            caller: &caller,
            context: &context,
        }
        .hash();
        let line = json!({
            "seq": seq,
            "ts": ts,
            "prev": prev,
            "hash": hash,
            "phase": entry.phase.as_str(),
            "caller": caller,
            "context": context,
            "tool": entry.tool,
            "arguments": arguments,
            "outcome": entry.outcome,
            "detail": detail,
            "duration_ms": duration_ms,
        });
        let mut bytes = serde_json::to_vec(&line).map_err(io::Error::other)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        file.flush()?;
        if let Some(exporter) = &self.exporter {
            exporter.offer(&line);
        }
        Ok(seq)
    }

    /// The last `count` entries, oldest first.
    #[must_use]
    pub fn tail(&self, count: usize) -> Vec<Value> {
        let Ok(file) = File::open(&self.path) else {
            return Vec::new();
        };
        let mut lines: std::collections::VecDeque<Value> = std::collections::VecDeque::new();
        for line in io::BufReader::new(file).lines().map_while(Result::ok) {
            if let Ok(value) = serde_json::from_str::<Value>(&line) {
                lines.push_back(value);
                if lines.len() > count {
                    lines.pop_front();
                }
            }
        }
        lines.into()
    }
}

/// The result of checking a log's hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verification {
    /// Entries that verified before the first break (all of them when intact).
    pub entries: u64,
    /// The first line that breaks the chain, with the reason.
    pub broken: Option<(u64, String)>,
    /// Hash of the last verified entry. Store it somewhere the log's writer cannot reach: the
    /// chain alone cannot show that entries were cut off the end.
    pub last_hash: String,
}

/// Recomputes every hash of the log at `path` and checks the links.
///
/// # Errors
/// When the file cannot be read.
pub fn verify(path: &Path) -> io::Result<Verification> {
    let file = File::open(path)?;
    let mut prev = GENESIS.to_owned();
    let mut expected_seq = 0_u64;
    let mut entries = 0_u64;
    for (index, line) in io::BufReader::new(file).lines().enumerate() {
        let line_no = index as u64 + 1;
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let broken = |reason: &str| {
            Ok(Verification {
                entries,
                broken: Some((line_no, reason.to_owned())),
                last_hash: prev.clone(),
            })
        };
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            return broken("not valid JSON");
        };
        expected_seq += 1;
        if value["seq"].as_u64() != Some(expected_seq) {
            return broken("sequence number out of order (a line is missing or moved)");
        }
        if value["prev"].as_str() != Some(prev.as_str()) {
            return broken("does not link to the previous entry");
        }
        let text = |key: &str| value[key].as_str().unwrap_or("");
        let recomputed = HashInput {
            seq: expected_seq,
            ts: text("ts"),
            prev: &prev,
            phase: text("phase"),
            tool: text("tool"),
            outcome: text("outcome"),
            detail: text("detail"),
            duration_ms: value["duration_ms"].as_u64().unwrap_or(0),
            arguments: &value["arguments"],
            caller: &value["caller"],
            context: &value["context"],
        }
        .hash();
        if value["hash"].as_str() != Some(recomputed.as_str()) {
            return broken("the entry's hash does not match its content (edited)");
        }
        prev = recomputed;
        entries += 1;
    }
    Ok(Verification {
        entries,
        broken: None,
        last_hash: prev,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn caller() -> Caller {
        Caller {
            transport: "stdio",
            client_name: Some("tester".into()),
            remote: None,
            principal: None,
        }
    }

    fn context() -> Context {
        Context {
            engagement: Some("ENG-1".into()),
            operator: Some("alice".into()),
            authorization_note: Some("ticket 7".into()),
            manifest_digest: None,
            grant_digest: None,
        }
    }

    fn record(audit: &Audit, tool: &str, outcome: &str, arguments: &Value) -> u64 {
        audit
            .record(&Entry {
                phase: Phase::Result,
                caller: &caller(),
                tool,
                arguments,
                outcome,
                detail: Some("backend answered 503"),
                duration_ms: Some(3),
                extra: None,
            })
            .unwrap()
    }

    #[test]
    fn chain_verifies_survives_reopen_redacts_and_detects_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let redactor = Redactor::new(["synthetic-api-key-value".to_owned()]);
        let args = json!({"url": "https://app.example.test", "password": "hunter2hunter2",
                          "note": "synthetic-api-key-value and bxt_0123456789abcdef0123"});
        {
            let audit = Audit::open(&path, context(), redactor.clone()).unwrap();
            record(&audit, "open_page", "ok", &args);
            record(&audit, "click", "error", &args);
        }
        {
            let audit = Audit::open(&path, context(), redactor).unwrap();
            assert_eq!(record(&audit, "health", "ok", &json!({})), 3);
            assert_eq!(audit.tail(2).len(), 2);
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for leaked in ["hunter2", "synthetic-api-key-value", "bxt_0123"] {
            assert!(!text.contains(leaked), "{leaked} leaked into the log");
        }
        assert!(text.contains("alice") && text.contains("ticket 7") && text.contains("ENG-1"));
        let report = verify(&path).unwrap();
        assert_eq!((report.entries, report.broken.clone()), (3, None));

        let edited = text.replacen("\"outcome\":\"error\"", "\"outcome\":\"ok\"", 1);
        std::fs::write(&path, edited).unwrap();
        assert_eq!(verify(&path).unwrap().broken.map(|(line, _)| line), Some(2));

        let forged = text.replacen("\"operator\":\"alice\"", "\"operator\":\"mallory\"", 1);
        std::fs::write(&path, forged).unwrap();
        assert_eq!(verify(&path).unwrap().broken.map(|(line, _)| line), Some(1));
    }

    #[test]
    fn deleted_and_reordered_lines_break_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Audit::open(&path, context(), Redactor::default()).unwrap();
        for _ in 0..3 {
            record(&audit, "health", "ok", &json!({}));
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let without_second = format!("{}\n{}\n", lines[0], lines[2]);
        std::fs::write(&path, without_second).unwrap();
        assert_eq!(verify(&path).unwrap().broken.map(|(line, _)| line), Some(2));
        let swapped = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[1]);
        std::fs::write(&path, swapped).unwrap();
        assert!(verify(&path).unwrap().broken.is_some());
        // Cutting entries off the end leaves a valid chain; only an externally stored last
        // hash reveals it.
        let truncated_tail = format!("{}\n{}\n", lines[0], lines[1]);
        std::fs::write(&path, truncated_tail).unwrap();
        let after_cut = verify(&path).unwrap();
        assert_eq!(after_cut.broken, None);
        assert_eq!(after_cut.entries, 2);
    }

    #[test]
    fn independent_writers_share_the_latest_chain_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let first = Audit::open(&path, context(), Redactor::default()).unwrap();
        let second = Audit::open(&path, context(), Redactor::default()).unwrap();
        for (index, audit) in [&first, &second, &first, &second].into_iter().enumerate() {
            assert_eq!(record(audit, "health", "ok", &json!({})), index as u64 + 1);
        }
        let report = verify(&path).unwrap();
        assert_eq!((report.entries, report.broken), (4, None));
    }

    #[test]
    fn broken_tail_refuses_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Audit::open(&path, context(), Redactor::default()).unwrap();
        for broken in ["not-json\n", "{}\n", "{\"seq\":1}\n"] {
            std::fs::write(&path, broken).unwrap();
            let result = audit.record(&Entry {
                phase: Phase::Intent,
                caller: &caller(),
                tool: "click",
                arguments: &json!({}),
                outcome: "intent",
                detail: None,
                duration_ms: None,
                extra: None,
            });
            assert!(result.is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), broken);
        }
    }

    #[test]
    fn canonical_json_ignores_key_order() {
        assert_eq!(
            canonical_json(&json!({"b": 1, "a": {"d": [2, {"y": 1, "x": 2}], "c": null}})),
            canonical_json(&json!({"a": {"c": null, "d": [2, {"x": 2, "y": 1}]}, "b": 1}))
        );
    }

    #[test]
    fn log_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        Audit::open(&path, context(), Redactor::default()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }
}
