//! The signed engagement manifest: the operator's rules of engagement as one document.
//!
//! `engagement.toml` holds who is testing, under which authorization and in which window, which
//! hosts may be attacked, only visited or never touched, which requests are protected, the
//! impact ceiling, limits and recurring time windows. A detached signature
//! (`engagement.toml.sig`, one line `key_id:hex`) is the HMAC-SHA256 of the exact file bytes
//! under the operator key, domain separated by [`DOMAIN`]. The check is offline: editing a
//! single byte (for example `not_after`) invalidates it.
//!
//! An unsigned, tampered or unknown-key manifest is inert: it widens nothing, and the server
//! unlists the tools that change pages. Text in the manifest never widens the scope the
//! configuration allows; hard limits are fields, not prose.

use std::path::Path;

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, Weekday};

use crate::crypto::{CryptoError, OperatorKeys};

/// Domain separation of the manifest signature.
pub const DOMAIN: &[u8] = b"browserx/engagement-manifest/v1\0";

/// Why a manifest could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// The cause.
        #[source]
        source: std::io::Error,
    },
    /// The TOML is malformed or has unknown keys.
    #[error("invalid manifest: {0}")]
    Parse(String),
    /// A value is out of range or inconsistent.
    #[error("invalid manifest: {0}")]
    Invalid(String),
}

fn invalid(message: impl Into<String>) -> ManifestError {
    ManifestError::Invalid(message.into())
}

/// What an operator allows on a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostMode {
    /// Observe, probe and demonstrate (within the impact level).
    Attack,
    /// Load and read; never submit forms or change anything.
    Visit,
    /// Never touched.
    Blocked,
}

impl HostMode {
    /// The name used in configuration and output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Attack => "attack",
            Self::Visit => "visit",
            Self::Blocked => "blocked",
        }
    }
}

/// The impact ceiling of the engagement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    /// Read only.
    Observe,
    /// Interact without destructive or externally visible effects.
    Probe,
    /// Everything the profile and approvals allow.
    Demonstrate,
}

impl Impact {
    /// The name used in configuration and output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Probe => "probe",
            Self::Demonstrate => "demonstrate",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EngagementMeta {
    id: String,
    operator: String,
    authorization_note: String,
    not_before: Option<String>,
    not_after: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeEntry {
    host: String,
    mode: HostMode,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedEntry {
    pattern: String,
    mode: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ImpactSection {
    level: Option<Impact>,
}

/// `[limits]`.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Tool calls per second across the server.
    pub rps: Option<u32>,
    /// Tool calls that touch pages, in total.
    pub max_calls: Option<u64>,
    /// Model spend ceiling in US dollars (recorded; enforced where a model is used).
    pub max_cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct WindowsSection {
    #[serde(default)]
    allow: Vec<String>,
}

/// `[stop]`: breaker settings (read and reported; reserved for the loop breakers).
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Stop {
    /// Pause when the target keeps failing.
    pub on_target_unhealthy: Option<bool>,
    /// Refusals before a handle is suspended.
    pub blocked_proposals_before_suspend: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    engagement: EngagementMeta,
    #[serde(default)]
    scope: Vec<ScopeEntry>,
    #[serde(default)]
    protected: Vec<ProtectedEntry>,
    #[serde(default)]
    impact: ImpactSection,
    #[serde(default)]
    limits: Limits,
    #[serde(default)]
    windows: WindowsSection,
    #[serde(default)]
    stop: Stop,
}

/// A host pattern: `host`, `host:port` or `*.suffix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern {
    host: String,
    port: Option<u16>,
    wildcard: bool,
}

impl HostPattern {
    fn parse(text: &str) -> Result<Self, ManifestError> {
        let lowered = text.trim().to_ascii_lowercase();
        let (name, port) = match lowered.rsplit_once(':') {
            Some((name, port)) if !name.ends_with(']') || name.starts_with('[') => {
                let port: u16 = port
                    .parse()
                    .map_err(|_| invalid(format!("scope host {text:?}: bad port")))?;
                (name.to_owned(), Some(port))
            }
            _ => (lowered.clone(), None),
        };
        let (wildcard, host) = match name.strip_prefix("*.") {
            Some(rest) => (true, rest.to_owned()),
            None => (false, name),
        };
        if host.is_empty()
            || host.contains("://")
            || host.contains('/')
            || host.contains('*')
            || host.chars().any(char::is_whitespace)
        {
            return Err(invalid(format!(
                "scope host {text:?} must be a host name, `host:port` or `*.suffix` (no scheme or path)"
            )));
        }
        Ok(Self {
            host,
            port,
            wildcard,
        })
    }

    fn matches(&self, host: &str, port: Option<u16>) -> bool {
        if let Some(wanted) = self.port
            && Some(wanted) != port
        {
            return false;
        }
        if self.wildcard {
            host.len() > self.host.len()
                && host.ends_with(&self.host)
                && host.as_bytes()[host.len() - self.host.len() - 1] == b'.'
        } else {
            host == self.host
        }
    }
}

/// A protected request pattern: `METHOD glob`; `*` in the glob matches any text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedRule {
    /// Upper-case method, or `None` for any.
    pub method: Option<String>,
    /// The glob matched against the full URL and, when it starts with `/`, the path.
    pub glob: String,
}

impl ProtectedRule {
    fn parse(text: &str) -> Result<Self, ManifestError> {
        let (method, glob) = text
            .trim()
            .split_once(char::is_whitespace)
            .ok_or_else(|| invalid(format!("protected pattern {text:?} must be `METHOD glob`")))?;
        let glob = glob.trim();
        if glob.is_empty() || glob.len() > 512 {
            return Err(invalid(format!("protected pattern {text:?}: bad glob")));
        }
        let method = match method {
            "*" => None,
            m if m.chars().all(|c| c.is_ascii_alphabetic()) => Some(m.to_ascii_uppercase()),
            _ => {
                return Err(invalid(format!(
                    "protected pattern {text:?}: the method must be letters or `*`"
                )));
            }
        };
        Ok(Self {
            method,
            glob: glob.to_owned(),
        })
    }

    /// Whether the request is protected by this rule.
    #[must_use]
    pub fn matches(&self, method: &str, url: &url::Url) -> bool {
        if let Some(wanted) = &self.method
            && !wanted.eq_ignore_ascii_case(method)
        {
            return false;
        }
        let full = url.as_str();
        let mut path = url.path().to_owned();
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        glob_match(&self.glob, full)
            || (self.glob.starts_with('/') && glob_match(&self.glob, &path))
    }
}

/// Matches `text` against `pattern`, where `*` matches any run of characters.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// A recurring window such as `Mon-Fri 09:00-17:00 UTC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowRule {
    days: [bool; 7],
    start: u16,
    end: u16,
}

fn weekday_index(day: Weekday) -> usize {
    usize::from(day.number_days_from_monday())
}

fn day_number(name: &str) -> Option<usize> {
    ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
        .iter()
        .position(|d| name.eq_ignore_ascii_case(d))
}

impl WindowRule {
    fn parse(text: &str) -> Result<Self, ManifestError> {
        let bad = || {
            invalid(format!(
                "window {text:?} must look like `Mon-Fri 09:00-17:00 UTC`"
            ))
        };
        let mut parts = text.split_whitespace();
        let days_text = parts.next().ok_or_else(bad)?;
        let times = parts.next().ok_or_else(bad)?;
        if parts.next() != Some("UTC") || parts.next().is_some() {
            return Err(invalid(format!(
                "window {text:?}: only UTC windows are supported"
            )));
        }
        let mut days = [false; 7];
        for item in days_text.split(',') {
            match item.split_once('-') {
                Some((from, to)) => {
                    let (from, to) = (
                        day_number(from).ok_or_else(bad)?,
                        day_number(to).ok_or_else(bad)?,
                    );
                    let mut day = from;
                    loop {
                        days[day] = true;
                        if day == to {
                            break;
                        }
                        day = (day + 1) % 7;
                    }
                }
                None => days[day_number(item).ok_or_else(bad)?] = true,
            }
        }
        let minute = |hhmm: &str| -> Result<u16, ManifestError> {
            let (h, m) = hhmm.split_once(':').ok_or_else(bad)?;
            let (h, m): (u16, u16) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
            if h > 24 || m > 59 || (h == 24 && m != 0) {
                return Err(bad());
            }
            Ok(h * 60 + m)
        };
        let (from, to) = times.split_once('-').ok_or_else(bad)?;
        let (start, end) = (minute(from)?, minute(to)?);
        if end <= start {
            return Err(invalid(format!(
                "window {text:?}: the end must be after the start"
            )));
        }
        Ok(Self { days, start, end })
    }

    fn contains(&self, at: OffsetDateTime) -> bool {
        let at = at.to_offset(time::UtcOffset::UTC);
        let minute = u16::from(at.hour()) * 60 + u16::from(at.minute());
        self.days[weekday_index(at.weekday())] && (self.start..self.end).contains(&minute)
    }
}

/// A parsed, validated manifest.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Engagement identifier written into every audit entry.
    pub id: String,
    /// The accountable operator.
    pub operator: String,
    /// Why the testing is authorized.
    pub authorization_note: String,
    /// Earliest permitted time.
    pub not_before: Option<OffsetDateTime>,
    /// Latest permitted time.
    pub not_after: Option<OffsetDateTime>,
    /// Impact ceiling.
    pub impact: Impact,
    /// Limits.
    pub limits: Limits,
    /// Breaker settings.
    pub stop: Stop,
    scope: Vec<(HostPattern, HostMode)>,
    protected: Vec<ProtectedRule>,
    windows: Vec<WindowRule>,
}

fn parse_time(name: &str, raw: Option<&String>) -> Result<Option<OffsetDateTime>, ManifestError> {
    raw.map(|text| {
        OffsetDateTime::parse(text, &Rfc3339)
            .map_err(|e| invalid(format!("engagement.{name}: {e} (use RFC 3339)")))
    })
    .transpose()
}

impl Manifest {
    /// Parses and validates manifest text.
    ///
    /// # Errors
    /// When the TOML is malformed or a value is out of range.
    pub fn parse(text: &str) -> Result<Self, ManifestError> {
        let raw: Raw = toml::from_str(text).map_err(|e| ManifestError::Parse(e.to_string()))?;
        let meta = raw.engagement;
        for (name, value) in [
            ("id", &meta.id),
            ("operator", &meta.operator),
            ("authorization_note", &meta.authorization_note),
        ] {
            if value.trim().is_empty() {
                return Err(invalid(format!("engagement.{name} must not be empty")));
            }
        }
        let not_before = parse_time("not_before", meta.not_before.as_ref())?;
        let not_after = parse_time("not_after", meta.not_after.as_ref())?;
        if let (Some(from), Some(to)) = (not_before, not_after)
            && from >= to
        {
            return Err(invalid(
                "engagement.not_before must be earlier than not_after",
            ));
        }
        let scope = raw
            .scope
            .iter()
            .map(|entry| Ok((HostPattern::parse(&entry.host)?, entry.mode)))
            .collect::<Result<Vec<_>, ManifestError>>()?;
        let protected = raw
            .protected
            .iter()
            .map(|entry| {
                if entry.mode.as_deref().is_some_and(|mode| mode != "blocked") {
                    return Err(invalid("protected entries support only mode = \"blocked\""));
                }
                ProtectedRule::parse(&entry.pattern)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let windows = raw
            .windows
            .allow
            .iter()
            .map(|w| WindowRule::parse(w))
            .collect::<Result<Vec<_>, _>>()?;
        if raw.limits.rps == Some(0) || raw.limits.max_calls == Some(0) {
            return Err(invalid("limits.rps and limits.max_calls must be positive"));
        }
        if scope.len() > 256 || protected.len() > 256 {
            return Err(invalid("at most 256 scope and 256 protected entries"));
        }
        Ok(Self {
            id: meta.id,
            operator: meta.operator,
            authorization_note: meta.authorization_note,
            not_before,
            not_after,
            impact: raw.impact.level.unwrap_or(Impact::Observe),
            limits: raw.limits,
            stop: raw.stop,
            scope,
            protected,
            windows,
        })
    }

    /// The mode of `url`'s host: blocked wins over visit, visit over attack; `None` when no
    /// entry names the host (out of scope).
    #[must_use]
    pub fn host_mode(&self, url: &url::Url) -> Option<HostMode> {
        let host = url.host_str()?.to_ascii_lowercase();
        let port = url.port_or_known_default();
        let mut found: Option<HostMode> = None;
        for (pattern, mode) in &self.scope {
            if pattern.matches(&host, port) {
                found = Some(match (found, *mode) {
                    (Some(HostMode::Blocked), _) | (_, HostMode::Blocked) => HostMode::Blocked,
                    (Some(HostMode::Visit), _) | (_, HostMode::Visit) => HostMode::Visit,
                    _ => HostMode::Attack,
                });
            }
        }
        found
    }

    /// Whether a protected pattern blocks `method url`.
    #[must_use]
    pub fn is_protected(&self, method: &str, url: &url::Url) -> bool {
        self.protected.iter().any(|rule| rule.matches(method, url))
    }

    /// Whether `url`'s host may be reached at all (attack or visit).
    #[must_use]
    pub fn host_allowed(&self, url: &url::Url) -> bool {
        matches!(
            self.host_mode(url),
            Some(HostMode::Attack | HostMode::Visit)
        )
    }

    /// The hosts with their modes, for display.
    #[must_use]
    pub fn scope_summary(&self) -> Vec<(String, HostMode)> {
        self.scope
            .iter()
            .map(|(pattern, mode)| {
                let mut host = String::new();
                if pattern.wildcard {
                    host.push_str("*.");
                }
                host.push_str(&pattern.host);
                if let Some(port) = pattern.port {
                    host.push(':');
                    host.push_str(&port.to_string());
                }
                (host, *mode)
            })
            .collect()
    }

    /// Whether `now` is inside the recurring windows (always true when none are set).
    #[must_use]
    pub fn in_windows(&self, now: OffsetDateTime) -> bool {
        self.windows.is_empty() || self.windows.iter().any(|w| w.contains(now))
    }
}

/// How the signature stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// Verified; the key id that signed.
    Valid(String),
    /// No signature file.
    Missing,
    /// The signature did not verify.
    Invalid(String),
}

/// The state of a manifest at a moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Signed, inside its window.
    Active,
    /// Signed but `not_before` is in the future.
    NotStarted(OffsetDateTime),
    /// Signed but `not_after` has passed.
    Expired(OffsetDateTime),
    /// Signed, inside its dates, outside the recurring windows.
    OutsideWindows,
    /// No signature.
    Unsigned,
    /// The signature failed.
    Invalid(String),
}

impl Status {
    /// Stable machine-readable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::NotStarted(_) => "not_started",
            Self::Expired(_) => "expired",
            Self::OutsideWindows => "outside_windows",
            Self::Unsigned => "unsigned",
            Self::Invalid(_) => "invalid_signature",
        }
    }

    /// The shared reason code of a refusal caused by this status.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Active => "ok",
            Self::NotStarted(_) | Self::Expired(_) | Self::OutsideWindows => "window_closed",
            Self::Unsigned | Self::Invalid(_) => "unsigned_manifest",
        }
    }
}

/// A manifest with its signature state and content digest.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The parsed manifest. Meaningful only when [`Loaded::trusted`].
    pub manifest: Manifest,
    /// SHA-256 of the file bytes, recorded in the audit log.
    pub digest: String,
    /// The signature state.
    pub signature: Signature,
}

/// The default signature path: the manifest path plus `.sig`.
#[must_use]
pub fn default_signature_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".sig");
    name.into()
}

impl Loaded {
    /// Reads, parses and verifies a manifest and its detached signature.
    ///
    /// # Errors
    /// When the manifest cannot be read or parsed. A missing or failing signature is not an
    /// error: it is reported by [`Loaded::signature`] and makes the manifest inert.
    pub fn load(
        path: &Path,
        signature_path: &Path,
        keys: &OperatorKeys,
    ) -> Result<Self, ManifestError> {
        let bytes = std::fs::read(path).map_err(|source| ManifestError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ManifestError::Parse("the manifest is not UTF-8".into()))?;
        let manifest = Manifest::parse(text)?;
        let signature = match std::fs::read_to_string(signature_path) {
            Ok(line) => match keys.verify(&line, DOMAIN, &bytes) {
                Ok(key_id) => Signature::Valid(key_id),
                Err(CryptoError::Mismatch) => {
                    Signature::Invalid("the signature does not match the manifest".into())
                }
                Err(other) => Signature::Invalid(other.to_string()),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Signature::Missing,
            Err(e) => Signature::Invalid(format!(
                "cannot read the signature {}: {e}",
                signature_path.display()
            )),
        };
        Ok(Self {
            manifest,
            digest: hex::encode(Sha256::digest(&bytes)),
            signature,
        })
    }

    /// Whether the signature verified.
    #[must_use]
    pub fn trusted(&self) -> bool {
        matches!(self.signature, Signature::Valid(_))
    }

    /// The state at `now`.
    #[must_use]
    pub fn status(&self, now: OffsetDateTime) -> Status {
        match &self.signature {
            Signature::Missing => return Status::Unsigned,
            Signature::Invalid(why) => return Status::Invalid(why.clone()),
            Signature::Valid(_) => {}
        }
        if let Some(from) = self.manifest.not_before
            && now < from
        {
            return Status::NotStarted(from);
        }
        if let Some(to) = self.manifest.not_after
            && now > to
        {
            return Status::Expired(to);
        }
        if !self.manifest.in_windows(now) {
            return Status::OutsideWindows;
        }
        Status::Active
    }
}

/// Signs manifest text under `key_id`.
///
/// # Errors
/// When the key id is unknown.
pub fn sign(keys: &OperatorKeys, key_id: &str, bytes: &[u8]) -> Result<String, CryptoError> {
    keys.sign(key_id, DOMAIN, bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    pub(crate) const SAMPLE: &str = r#"
[engagement]
id = "eng-2026-11-a"
operator = "alice"
authorization_note = "ticket 1234"
not_before = "2026-01-01T00:00:00Z"
not_after = "2026-12-31T00:00:00Z"

[[scope]]
host = "app.example.test"
mode = "attack"

[[scope]]
host = "cdn.example.test"
mode = "visit"

[[scope]]
host = "*.payments.test"
mode = "blocked"

[[protected]]
pattern = "POST */logout"
mode = "blocked"

[[protected]]
pattern = "* /account/delete*"
mode = "blocked"

[impact]
level = "probe"

[limits]
rps = 20
max_calls = 400

[windows]
allow = ["Mon-Fri 09:00-17:00 UTC"]

[stop]
on_target_unhealthy = true
blocked_proposals_before_suspend = 5
"#;

    fn keys() -> OperatorKeys {
        let mut keys = OperatorKeys::new();
        keys.insert("op1", vec![3; 32]).unwrap();
        keys
    }

    fn url(text: &str) -> url::Url {
        url::Url::parse(text).unwrap()
    }

    fn at(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &Rfc3339).unwrap()
    }

    fn files(manifest: &str, signed: bool) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement.toml");
        std::fs::write(&path, manifest).unwrap();
        if signed {
            let line = sign(&keys(), "op1", manifest.as_bytes()).unwrap();
            std::fs::write(default_signature_path(&path), line).unwrap();
        }
        (dir, path)
    }

    #[test]
    fn modes_and_protected_patterns_decide_hosts_and_requests() {
        let manifest = Manifest::parse(SAMPLE).unwrap();
        assert_eq!(manifest.impact, Impact::Probe);
        assert_eq!(
            manifest.host_mode(&url("https://app.example.test/x")),
            Some(HostMode::Attack)
        );
        assert_eq!(
            manifest.host_mode(&url("https://cdn.example.test/")),
            Some(HostMode::Visit)
        );
        assert_eq!(
            manifest.host_mode(&url("https://shop.payments.test/")),
            Some(HostMode::Blocked)
        );
        assert_eq!(manifest.host_mode(&url("https://payments.test/")), None);
        assert_eq!(manifest.host_mode(&url("https://evil.test/")), None);
        assert!(manifest.is_protected("POST", &url("https://app.example.test/logout")));
        assert!(!manifest.is_protected("GET", &url("https://app.example.test/logout")));
        assert!(manifest.is_protected("GET", &url("https://app.example.test/account/delete?id=1")));
        assert!(!manifest.is_protected("GET", &url("https://app.example.test/account")));
    }

    #[test]
    fn blocked_beats_visit_beats_attack_and_ports_are_respected() {
        let text = SAMPLE.replace(
            "[impact]",
            "[[scope]]\nhost = \"app.example.test:8443\"\nmode = \"blocked\"\n\n[impact]",
        );
        let manifest = Manifest::parse(&text).unwrap();
        assert_eq!(
            manifest.host_mode(&url("https://app.example.test:8443/")),
            Some(HostMode::Blocked)
        );
        assert_eq!(
            manifest.host_mode(&url("https://app.example.test/")),
            Some(HostMode::Attack)
        );
    }

    #[test]
    fn windows_and_dates_decide_the_status() {
        let (_dir, path) = files(SAMPLE, true);
        let loaded = Loaded::load(&path, &default_signature_path(&path), &keys()).unwrap();
        assert!(loaded.trusted());
        // 2026-06-03 is a Wednesday.
        assert_eq!(loaded.status(at("2026-06-03T10:00:00Z")), Status::Active);
        assert_eq!(
            loaded.status(at("2026-06-03T18:00:00Z")),
            Status::OutsideWindows
        );
        assert_eq!(
            loaded.status(at("2026-06-06T10:00:00Z")),
            Status::OutsideWindows
        );
        assert!(matches!(
            loaded.status(at("2025-06-03T10:00:00Z")),
            Status::NotStarted(_)
        ));
        let expired = loaded.status(at("2027-06-03T10:00:00Z"));
        assert!(matches!(expired, Status::Expired(_)));
        assert_eq!(expired.reason_code(), "window_closed");
    }

    #[test]
    fn a_tampered_or_unsigned_manifest_is_inert() {
        let (_dir, path) = files(SAMPLE, true);
        let sig = default_signature_path(&path);
        let tampered = SAMPLE.replace("2026-12-31", "2099-12-31");
        std::fs::write(&path, tampered).unwrap();
        let loaded = Loaded::load(&path, &sig, &keys()).unwrap();
        assert!(!loaded.trusted());
        let status = loaded.status(at("2026-06-03T10:00:00Z"));
        assert!(matches!(status, Status::Invalid(_)));
        assert_eq!(status.reason_code(), "unsigned_manifest");

        let (_dir2, unsigned) = files(SAMPLE, false);
        let loaded = Loaded::load(&unsigned, &default_signature_path(&unsigned), &keys()).unwrap();
        assert_eq!(loaded.status(at("2026-06-03T10:00:00Z")), Status::Unsigned);

        // A signature by an unknown key does not verify either.
        let (_dir3, other) = files(SAMPLE, true);
        let mut foreign = OperatorKeys::new();
        foreign.insert("other", vec![9; 32]).unwrap();
        let loaded = Loaded::load(&other, &default_signature_path(&other), &foreign).unwrap();
        assert!(!loaded.trusted());
    }

    #[test]
    fn malformed_manifests_are_rejected() {
        for bad in [
            SAMPLE.replace("mode = \"attack\"", "mode = \"everything\""),
            SAMPLE.replace("app.example.test", "https://app.example.test"),
            SAMPLE.replace("POST */logout", "logout"),
            SAMPLE.replace("Mon-Fri 09:00-17:00 UTC", "Mon-Fri 09:00-17:00 CET"),
            SAMPLE.replace("rps = 20", "rps = 0"),
            SAMPLE.replace("2026-12-31T00:00:00Z", "2025-12-31T00:00:00Z"),
            SAMPLE.replace("[stop]", "[unknown]"),
            SAMPLE.replace("id = \"eng-2026-11-a\"", "id = \" \""),
        ] {
            assert!(Manifest::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn globs_match_anywhere_a_star_stands() {
        assert!(glob_match("*/logout", "https://a.test/logout"));
        assert!(glob_match("/account/delete*", "/account/delete?x=1"));
        assert!(!glob_match("/account/delete*", "/account"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("a*b", "ac"));
    }
}
