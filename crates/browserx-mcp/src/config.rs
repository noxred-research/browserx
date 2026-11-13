//! The MCP server configuration (TOML, `deny_unknown_fields`).
//!
//! Secrets are never inline: the BrowserX API key, the model key, proxy passwords and adopted
//! session tokens are read from files named here, and the HTTP transport's bearer token is
//! stored only as a SHA-256 digest. Relative paths are resolved against the directory that holds
//! the configuration file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use browserx_core::Secret;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::McpError;

/// What an operator can switch on. Everything not listed is off: the server is read-only until
/// capabilities are enabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Create, renew, snapshot and release sessions.
    Sessions,
    /// Rotate a session's controller token (needs `sessions`).
    Handoff,
    /// Navigate and observe pages of sessions this server controls.
    Browse,
    /// Click, type, scroll and press keys (needs `browse`).
    Interact,
    /// Run JavaScript in a page (needs `browse`; off by default).
    Evaluate,
}

impl Capability {
    /// The name used in configuration and output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sessions => "sessions",
            Self::Handoff => "handoff",
            Self::Browse => "browse",
            Self::Interact => "interact",
            Self::Evaluate => "evaluate",
        }
    }
}

/// The whole configuration file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The BrowserX server to talk to.
    pub server: ServerSection,
    /// Transport and capability settings.
    #[serde(default)]
    pub mcp: McpSection,
    /// Browsing scope and bounds.
    #[serde(default)]
    pub browse: BrowseSection,
    /// Who is testing, under which authorization, and when.
    #[serde(default)]
    pub engagement: EngagementSection,
    /// Session creation defaults and caps.
    #[serde(default)]
    pub sessions: SessionsSection,
    /// The audit log.
    pub audit: AuditSection,
    /// Rate limits and sampling.
    #[serde(default)]
    pub limits: LimitsSection,
    /// Optional chat-completions compatible endpoint for the advisory tools.
    #[serde(default)]
    pub ai: Option<AiSection>,
    /// Named upstream proxy routes a model may choose by name.
    #[serde(default)]
    pub proxy_routes: BTreeMap<String, ProxyRouteConfig>,
    /// Existing sessions this server may browse, with the file that holds each token.
    #[serde(default)]
    pub adopt: Vec<AdoptConfig>,
}

/// `[server]`: the BrowserX server.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Base URL of the BrowserX API listener.
    pub url: String,
    /// Base URL of the operations listener (`/healthz`, `/readyz`, `/metrics`).
    #[serde(default)]
    pub ops_url: Option<String>,
    /// File holding the BrowserX API key (`bxk_...`).
    pub api_key_file: PathBuf,
    /// Per-request timeout towards the BrowserX API, in seconds.
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
}

fn default_request_timeout() -> u64 {
    30
}

/// `[mcp]`: capabilities and transports.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct McpSection {
    /// Enabled capabilities; empty means read-only monitoring.
    pub capabilities: Vec<Capability>,
    /// Show lease tokens and CDP URLs to the model. Off by default: the server drives the
    /// browser itself and the model never needs them.
    pub reveal_endpoints: bool,
    /// Requests served at once.
    pub max_in_flight: usize,
    /// Largest tool result text, in bytes.
    pub max_result_bytes: usize,
    /// Release the sessions this server created when it stops.
    pub release_on_exit: bool,
    /// Streamable HTTP transport settings.
    pub http: HttpSection,
}

impl Default for McpSection {
    fn default() -> Self {
        Self {
            capabilities: Vec::new(),
            reveal_endpoints: false,
            max_in_flight: 8,
            max_result_bytes: 256 * 1024,
            release_on_exit: true,
            http: HttpSection::default(),
        }
    }
}

/// `[mcp.http]`: the streamable HTTP transport.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HttpSection {
    /// Listen address when `--http` is given without a value elsewhere.
    pub listen: String,
    /// Lowercase hex SHA-256 of the bearer token clients must present.
    pub token_sha256: Option<String>,
    /// Extra `Origin` values accepted besides loopback origins.
    pub allowed_origins: Vec<String>,
    /// URL path of the endpoint.
    pub path: String,
    /// Largest request body, in bytes (at most 4 MiB, the largest message the server accepts).
    pub max_body_bytes: usize,
}

impl Default for HttpSection {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7692".into(),
            token_sha256: None,
            allowed_origins: Vec::new(),
            path: "/mcp".into(),
            max_body_bytes: 4 * 1024 * 1024,
        }
    }
}

/// `[browse]`: scope and bounds of browsing.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BrowseSection {
    /// Exact origins (`https://app.example.test`) the browser may navigate to.
    pub allowed_origins: Vec<String>,
    /// Refuse browsing unless scope, operator and authorization note are all configured.
    pub require_scope: bool,
    /// Open tabs per session.
    pub max_tabs: usize,
    /// Default character budget of snapshots, page text and script results.
    pub default_max_chars: usize,
    /// Largest character budget a call may ask for.
    pub max_chars_cap: usize,
    /// Per-command CDP timeout, in seconds.
    pub command_timeout_secs: u64,
    /// How long a navigation or a click may wait for the page to settle, in seconds.
    pub navigation_timeout_secs: u64,
    /// Network log entries kept per tab.
    pub network_log_entries: usize,
    /// Console messages kept per tab.
    pub console_log_entries: usize,
}

impl Default for BrowseSection {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            require_scope: true,
            max_tabs: 8,
            default_max_chars: 12_000,
            max_chars_cap: 60_000,
            command_timeout_secs: 20,
            navigation_timeout_secs: 30,
            network_log_entries: 500,
            console_log_entries: 200,
        }
    }
}

/// `[engagement]`: accountability for browsing.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EngagementSection {
    /// Free-form engagement identifier recorded in the audit log.
    pub id: Option<String>,
    /// The accountable operator.
    pub operator: Option<String>,
    /// Why this testing is authorized (ticket, contract reference, scope document).
    pub authorization_note: Option<String>,
    /// RFC 3339 time before which browsing is refused.
    pub not_before: Option<String>,
    /// RFC 3339 time after which browsing is refused.
    pub not_after: Option<String>,
}

/// `[sessions]`: what a model may create.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SessionsSection {
    /// Sessions this server controls at once.
    pub max_tracked: usize,
    /// Lease TTL when the model names none, in seconds.
    pub default_ttl_secs: u64,
    /// Longest lease TTL a model may ask for, in seconds.
    pub max_ttl_secs: u64,
}

impl Default for SessionsSection {
    fn default() -> Self {
        Self {
            max_tracked: 4,
            default_ttl_secs: 900,
            max_ttl_secs: 3600,
        }
    }
}

/// `[audit]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    /// Path of the hash-chained JSONL audit log (created with mode `0600`).
    pub path: PathBuf,
}

/// `[limits]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsSection {
    /// Seconds between metrics samples taken in the background.
    pub sample_interval_secs: u64,
    /// Calls per minute by tool name, overriding the built-in defaults.
    pub per_minute: BTreeMap<String, u32>,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            sample_interval_secs: 15,
            per_minute: BTreeMap::new(),
        }
    }
}

/// `[ai]`: a chat-completions compatible endpoint.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiSection {
    /// Base URL; `/chat/completions` is appended when missing.
    pub base_url: String,
    /// Model name sent with each request.
    pub model: String,
    /// File holding the bearer key, when the endpoint needs one.
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    /// Request timeout in seconds.
    #[serde(default = "default_ai_timeout")]
    pub timeout_secs: u64,
    /// Maximum tokens of an answer.
    #[serde(default = "default_ai_tokens")]
    pub max_tokens: u32,
    /// Longest page content, in characters, put into a prompt.
    #[serde(default = "default_ai_input")]
    pub max_input_chars: usize,
}

fn default_ai_timeout() -> u64 {
    60
}
fn default_ai_tokens() -> u32 {
    1024
}
fn default_ai_input() -> usize {
    24_000
}

/// `[proxy_routes.<name>]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRouteConfig {
    /// `http://`, `https://`, `socks5://` or `socks5h://` upstream.
    pub url: String,
    /// Optional username (`{session}` and `{generation}` are substituted by BrowserX).
    #[serde(default)]
    pub username: Option<String>,
    /// File holding the proxy password.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
}

/// `[[adopt]]`: an existing session this server may browse.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptConfig {
    /// Session id (`ses_...`).
    pub session_id: String,
    /// File holding the session's controller token (`bxt_...`).
    pub token_file: PathBuf,
}

/// The parsed engagement window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    /// Earliest permitted time.
    pub not_before: Option<OffsetDateTime>,
    /// Latest permitted time.
    pub not_after: Option<OffsetDateTime>,
}

fn bad(message: impl Into<String>) -> McpError {
    McpError::Config(message.into())
}

/// Normalizes an origin (`scheme://host[:port]`, no path, query or credentials).
///
/// # Errors
/// When the text is not an `http`/`https` origin.
pub fn normalize_origin(raw: &str) -> Result<String, McpError> {
    let url = url::Url::parse(raw).map_err(|e| bad(format!("origin {raw:?}: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(bad(format!(
            "origin {raw:?}: only http and https are allowed"
        )));
    }
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(bad(format!(
            "origin {raw:?} must look like https://host[:port] (no path, query or credentials)"
        )));
    }
    Ok(url.origin().ascii_serialization())
}

fn parse_time(name: &str, raw: &Option<String>) -> Result<Option<OffsetDateTime>, McpError> {
    raw.as_deref()
        .map(|text| {
            OffsetDateTime::parse(text, &Rfc3339).map_err(|e| {
                bad(format!(
                    "engagement.{name}: {e} (use RFC 3339, e.g. 2026-01-31T18:00:00Z)"
                ))
            })
        })
        .transpose()
}

/// Reads a secret file: the trimmed contents.
///
/// # Errors
/// When the file is unreadable or empty.
pub fn read_secret(path: &Path) -> Result<Secret, McpError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| McpError::io(format!("cannot read secret file {}", path.display()), e))?;
    let value = text.trim();
    if value.is_empty() {
        return Err(bad(format!("secret file {} is empty", path.display())));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = std::fs::metadata(path)
            && meta.permissions().mode() & 0o077 != 0
        {
            tracing::warn!(
                path = %path.display(),
                "secret file is accessible by group or others; run chmod 600"
            );
        }
    }
    Ok(Secret::new(value))
}

impl Config {
    /// Loads and validates a configuration file.
    ///
    /// # Errors
    /// When the file cannot be read, parsed or validated.
    pub fn load(path: &Path) -> Result<Self, McpError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| McpError::io(format!("cannot read {}", path.display()), e))?;
        let base = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        Self::parse(&text, base)
    }

    /// Parses and validates configuration text; relative paths resolve against `base`.
    ///
    /// # Errors
    /// When the text is malformed or inconsistent.
    pub fn parse(text: &str, base: &Path) -> Result<Self, McpError> {
        let mut config: Self =
            toml::from_str(text).map_err(|e| bad(format!("invalid TOML: {e}")))?;
        config.resolve_paths(base);
        config.validate()?;
        Ok(config)
    }

    fn resolve_paths(&mut self, base: &Path) {
        let fix = |path: &mut PathBuf| {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        };
        fix(&mut self.server.api_key_file);
        fix(&mut self.audit.path);
        if let Some(ai) = &mut self.ai
            && let Some(file) = &mut ai.api_key_file
        {
            fix(file);
        }
        for route in self.proxy_routes.values_mut() {
            if let Some(file) = &mut route.password_file {
                fix(file);
            }
        }
        for adopt in &mut self.adopt {
            fix(&mut adopt.token_file);
        }
    }

    /// Whether `capability` is enabled.
    #[must_use]
    pub fn has(&self, capability: Capability) -> bool {
        self.mcp.capabilities.contains(&capability)
    }

    /// The engagement window.
    ///
    /// # Errors
    /// When a bound is not RFC 3339 or the window is empty.
    pub fn window(&self) -> Result<Window, McpError> {
        let window = Window {
            not_before: parse_time("not_before", &self.engagement.not_before)?,
            not_after: parse_time("not_after", &self.engagement.not_after)?,
        };
        if let (Some(from), Some(to)) = (window.not_before, window.not_after)
            && from >= to
        {
            return Err(bad(
                "engagement.not_before must be earlier than engagement.not_after",
            ));
        }
        Ok(window)
    }

    /// The configured origins, normalized.
    ///
    /// # Errors
    /// When an entry is not an origin.
    pub fn origins(&self) -> Result<Vec<String>, McpError> {
        self.browse
            .allowed_origins
            .iter()
            .map(|origin| normalize_origin(origin))
            .collect()
    }

    fn validate(&self) -> Result<(), McpError> {
        for (url, name) in [
            (Some(&self.server.url), "server.url"),
            (self.server.ops_url.as_ref(), "server.ops_url"),
            (self.ai.as_ref().map(|ai| &ai.base_url), "ai.base_url"),
        ] {
            if let Some(url) = url {
                let parsed = url::Url::parse(url).map_err(|e| bad(format!("{name}: {e}")))?;
                if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                    return Err(bad(format!("{name} must be an http(s) URL")));
                }
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    return Err(bad(format!("{name} must not carry credentials")));
                }
            }
        }
        if self.server.request_timeout_secs == 0 || self.server.request_timeout_secs > 600 {
            return Err(bad("server.request_timeout_secs must be 1..=600"));
        }
        let mcp = &self.mcp;
        if !(1..=64).contains(&mcp.max_in_flight) {
            return Err(bad("mcp.max_in_flight must be 1..=64"));
        }
        if !(4096..=4 * 1024 * 1024).contains(&mcp.max_result_bytes) {
            return Err(bad("mcp.max_result_bytes must be 4096..=4194304"));
        }
        self.validate_capabilities()?;
        self.validate_http()?;
        self.validate_browse()?;
        self.window()?;
        let sessions = &self.sessions;
        if !(1..=64).contains(&sessions.max_tracked)
            || sessions.default_ttl_secs == 0
            || sessions.default_ttl_secs > sessions.max_ttl_secs
        {
            return Err(bad(
                "sessions: max_tracked must be 1..=64 and 0 < default_ttl_secs <= max_ttl_secs",
            ));
        }
        if self.limits.sample_interval_secs == 0 {
            return Err(bad("limits.sample_interval_secs must be positive"));
        }
        for (tool, limit) in &self.limits.per_minute {
            if *limit == 0 || *limit > 100_000 {
                return Err(bad(format!("limits.per_minute.{tool} must be 1..=100000")));
            }
        }
        if let Some(ai) = &self.ai
            && (ai.model.trim().is_empty()
                || ai.timeout_secs == 0
                || ai.max_tokens == 0
                || ai.max_input_chars < 1000)
        {
            return Err(bad(
                "ai: model must be set, timeout_secs and max_tokens positive, max_input_chars >= 1000",
            ));
        }
        for (name, route) in &self.proxy_routes {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
            {
                return Err(bad(format!(
                    "proxy_routes.{name}: names are 1..=64 of [A-Za-z0-9_-]"
                )));
            }
            browserx_core::ProxyRoute {
                url: route.url.clone(),
                username: route.username.clone(),
                password: None,
            }
            .validate()
            .map_err(|e| bad(format!("proxy_routes.{name}: {e}")))?;
        }
        for adopt in &self.adopt {
            browserx_core::SessionId::parse(&adopt.session_id)
                .map_err(|e| bad(format!("adopt.session_id {}: {e}", adopt.session_id)))?;
        }
        if !self.adopt.is_empty() && !self.has(Capability::Browse) {
            return Err(bad("[[adopt]] needs the `browse` capability"));
        }
        Ok(())
    }

    fn validate_capabilities(&self) -> Result<(), McpError> {
        if self.has(Capability::Handoff) && !self.has(Capability::Sessions) {
            return Err(bad("capability `handoff` needs `sessions`"));
        }
        for capability in [Capability::Interact, Capability::Evaluate] {
            if self.has(capability) && !self.has(Capability::Browse) {
                return Err(bad(format!(
                    "capability `{}` needs `browse`",
                    capability.name()
                )));
            }
        }
        Ok(())
    }

    fn validate_http(&self) -> Result<(), McpError> {
        let http = &self.mcp.http;
        if let Some(digest) = &http.token_sha256
            && (digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(bad("mcp.http.token_sha256 must be 64 hex characters"));
        }
        if !http.path.starts_with('/') || http.path.len() > 128 {
            return Err(bad("mcp.http.path must start with `/`"));
        }
        if !(1024..=4 * 1024 * 1024).contains(&http.max_body_bytes) {
            return Err(bad("mcp.http.max_body_bytes must be 1024..=4194304"));
        }
        for origin in &http.allowed_origins {
            normalize_origin(origin)?;
        }
        http.listen
            .parse::<std::net::SocketAddr>()
            .map_err(|e| bad(format!("mcp.http.listen: {e}")))?;
        Ok(())
    }

    fn validate_browse(&self) -> Result<(), McpError> {
        let browse = &self.browse;
        self.origins()?;
        if !(1..=64).contains(&browse.max_tabs)
            || browse.default_max_chars < 500
            || browse.max_chars_cap < browse.default_max_chars
            || browse.max_chars_cap > 1_000_000
            || !(1..=300).contains(&browse.command_timeout_secs)
            || !(1..=300).contains(&browse.navigation_timeout_secs)
            || !(10..=10_000).contains(&browse.network_log_entries)
            || !(10..=10_000).contains(&browse.console_log_entries)
        {
            return Err(bad(
                "browse: check max_tabs (1..=64), default_max_chars (>=500) <= max_chars_cap (<=1000000), \
                 timeouts (1..=300 s) and log sizes (10..=10000)",
            ));
        }
        if self.has(Capability::Browse) && browse.require_scope {
            let blank =
                |value: &Option<String>| value.as_deref().is_none_or(|v| v.trim().is_empty());
            if browse.allowed_origins.is_empty() {
                return Err(bad(
                    "browse.require_scope is true: list the permitted origins in browse.allowed_origins \
                     (or set require_scope = false to browse any http(s) origin)",
                ));
            }
            if blank(&self.engagement.operator) || blank(&self.engagement.authorization_note) {
                return Err(bad(
                    "browse.require_scope is true: set engagement.operator and engagement.authorization_note \
                     so every audit entry records who is testing and under which authorization",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const MINIMAL: &str = r#"
[server]
url = "http://127.0.0.1:7690"
api_key_file = "key"
[audit]
path = "audit.jsonl"
"#;

    fn parse(extra: &str) -> Result<Config, McpError> {
        Config::parse(&format!("{MINIMAL}{extra}"), Path::new("/etc/browserx"))
    }

    #[test]
    fn minimal_config_is_read_only_and_resolves_paths() {
        let config = parse("").unwrap();
        assert!(config.mcp.capabilities.is_empty());
        assert_eq!(config.server.api_key_file, Path::new("/etc/browserx/key"));
        assert_eq!(config.audit.path, Path::new("/etc/browserx/audit.jsonl"));
    }

    #[test]
    fn the_shipped_example_is_valid() {
        let config = Config::parse(
            include_str!("../../../examples/mcp.toml"),
            Path::new("/etc/browserx"),
        )
        .unwrap();
        assert!(config.has(Capability::Browse) && !config.has(Capability::Evaluate));
        assert!(!config.origins().unwrap().is_empty());
        assert!(config.ai.is_some() && config.proxy_routes.contains_key("eu_exit"));
    }

    #[test]
    fn unknown_keys_are_refused() {
        assert!(parse("[mcp]\ncapabilites = []\n").is_err());
    }

    #[test]
    fn capability_dependencies_are_enforced() {
        assert!(parse("[mcp]\ncapabilities = [\"handoff\"]\n").is_err());
        assert!(
            parse("[mcp]\ncapabilities = [\"interact\"]\n[browse]\nrequire_scope = false\n")
                .is_err()
        );
    }

    #[test]
    fn required_scope_needs_origins_operator_and_note() {
        let browse = "[mcp]\ncapabilities = [\"browse\"]\n";
        assert!(parse(browse).is_err());
        let origins =
            format!("{browse}[browse]\nallowed_origins = [\"https://App.Example.test:443\"]\n");
        assert!(parse(&origins).is_err());
        let full = format!(
            "{origins}[engagement]\noperator = \"alice\"\nauthorization_note = \"ticket 1\"\n"
        );
        let config = parse(&full).unwrap();
        assert_eq!(
            config.origins().unwrap(),
            vec!["https://app.example.test".to_owned()]
        );
        assert!(parse(&format!("{browse}[browse]\nrequire_scope = false\n")).is_ok());
    }

    #[test]
    fn origins_reject_paths_and_credentials() {
        for bad in [
            "https://u:p@h.test",
            "https://h.test/path",
            "ftp://h.test",
            "h.test",
        ] {
            assert!(normalize_origin(bad).is_err(), "{bad}");
        }
        assert_eq!(
            normalize_origin("http://127.0.0.1:8080/").unwrap(),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn engagement_window_is_validated() {
        let ok = parse(
            "[engagement]\nnot_before = \"2026-01-01T00:00:00Z\"\nnot_after = \"2026-02-01T00:00:00Z\"\n",
        );
        assert!(ok.unwrap().window().unwrap().not_after.is_some());
        let reversed = parse(
            "[engagement]\nnot_before = \"2026-03-01T00:00:00Z\"\nnot_after = \"2026-02-01T00:00:00Z\"\n",
        );
        assert!(reversed.is_err());
        assert!(parse("[engagement]\nnot_after = \"tomorrow\"\n").is_err());
    }

    #[test]
    fn proxy_routes_never_carry_credentials_in_the_url() {
        let route = "[proxy_routes.eu]\nurl = \"http://user:pw@gw.test:8080\"\n";
        assert!(parse(route).is_err());
        assert!(
            parse("[proxy_routes.eu]\nurl = \"http://gw.test:8080\"\npassword_file = \"pw\"\n")
                .is_ok()
        );
    }
}
