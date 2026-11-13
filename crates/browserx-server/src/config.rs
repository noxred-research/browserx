//! Server configuration (TOML). Unknown keys are errors so typos never silently
//! fall back to defaults.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use browserx_core::{Error, Result};
use browserx_egress::EgressPolicy;
use browserx_pool::PoolConfig;
use browserx_runtime::RuntimeConfig;
use serde::{Deserialize, Serialize};

/// Whole-process configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Listeners and public URL.
    pub server: ServerSection,
    /// API credentials.
    pub auth: AuthSection,
    /// Scheduler capacity.
    pub pool: PoolSection,
    /// Session lifetime defaults and bounds.
    pub session: SessionSection,
    /// On-disk state.
    pub storage: StorageSection,
    /// Browser health monitoring.
    pub health: HealthSection,
    /// Destination policy for browser traffic.
    pub egress: EgressPolicy,
    /// Browser launch profiles.
    pub runtime: RuntimeConfig,
}

/// `[server]`
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerSection {
    /// Address of the API and CDP relay listener.
    pub listen: String,
    /// Address of the operations listener (health, readiness, metrics).
    pub ops_listen: String,
    /// Base URL clients use to reach `listen`; the `cdp_url` handed to clients is derived from it.
    pub public_base_url: String,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7690".into(),
            ops_listen: "127.0.0.1:7691".into(),
            public_base_url: "http://127.0.0.1:7690".into(),
        }
    }
}

/// `[auth]`
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthSection {
    /// Accepted API keys (stored only as SHA-256 digests).
    pub api_keys: Vec<ApiKeyConfig>,
}

/// One `[[auth.api_keys]]` entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyConfig {
    /// Owner name: sessions created with this key belong to it.
    pub name: String,
    /// Lowercase hex SHA-256 of the key.
    pub sha256: String,
    /// Cap on this owner's concurrent (non-terminal) sessions.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
}

fn default_max_sessions() -> usize {
    16
}

/// `[pool]`
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct PoolSection {
    /// Maximum browser processes.
    pub max_browsers: usize,
    /// Maximum contexts per shared browser.
    pub max_contexts_per_browser: usize,
    /// Idle shared browsers kept warm.
    pub warm_shared_browsers: usize,
    /// Maximum admissions waiting for capacity.
    pub queue_capacity: usize,
    /// Seconds an admission may wait.
    pub queue_timeout_secs: u64,
    /// Seconds before a shared browser stops taking new contexts.
    pub browser_max_age_secs: u64,
    /// Contexts a shared browser may serve before it retires.
    pub browser_max_contexts_served: u64,
}

impl Default for PoolSection {
    fn default() -> Self {
        let d = PoolConfig::default();
        Self {
            max_browsers: d.max_browsers,
            max_contexts_per_browser: d.max_contexts_per_browser,
            warm_shared_browsers: d.warm_shared_browsers,
            queue_capacity: d.queue_capacity,
            queue_timeout_secs: d.queue_timeout.as_secs(),
            browser_max_age_secs: d.browser_max_age.as_secs(),
            browser_max_contexts_served: d.browser_max_contexts_served,
        }
    }
}

/// `[session]`
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SessionSection {
    /// TTL when a request names none (seconds).
    pub default_ttl_secs: u64,
    /// Largest TTL a request or renewal may ask for.
    pub max_ttl_secs: u64,
    /// Absolute lifetime cap (and default).
    pub max_lifetime_secs: u64,
    /// Idle timeout when a request names none.
    pub default_idle_timeout_secs: u64,
    /// Seconds between periodic snapshots.
    pub snapshot_interval_secs: u64,
    /// Snapshot versions kept per profile.
    pub snapshot_keep: usize,
    /// Seconds terminal leases stay queryable.
    pub terminal_retention_secs: u64,
}

impl Default for SessionSection {
    fn default() -> Self {
        let d = PoolConfig::default();
        Self {
            default_ttl_secs: d.default_ttl.as_secs(),
            max_ttl_secs: d.max_ttl.as_secs(),
            max_lifetime_secs: d.max_lifetime.as_secs(),
            default_idle_timeout_secs: d.default_idle_timeout.as_secs(),
            snapshot_interval_secs: d.snapshot_interval.as_secs(),
            snapshot_keep: d.snapshot_keep,
            terminal_retention_secs: d.terminal_retention.as_secs(),
        }
    }
}

/// `[storage]`
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageSection {
    /// Root of all on-disk state.
    pub state_dir: PathBuf,
    /// Active snapshot encryption key file (create with `browserx snapshot-key new`).
    pub snapshot_key_file: PathBuf,
    /// Previous key files that may only open old snapshots (key rotation).
    pub retired_snapshot_key_files: Vec<PathBuf>,
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from("./.browserx"),
            snapshot_key_file: PathBuf::from("./.browserx/snapshot.key"),
            retired_snapshot_key_files: Vec::new(),
        }
    }
}

impl StorageSection {
    /// SQLite lease database.
    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        self.state_dir.join("browserx.db")
    }
    /// Encrypted snapshot directory.
    #[must_use]
    pub fn snapshots_dir(&self) -> PathBuf {
        self.state_dir.join("snapshots")
    }
    /// Profile directories (profile persistence).
    #[must_use]
    pub fn profiles_dir(&self) -> PathBuf {
        self.state_dir.join("profiles")
    }
    /// Scratch space for temporary browser profiles.
    #[must_use]
    pub fn temp_dir(&self) -> PathBuf {
        self.state_dir.join("tmp")
    }
}

/// `[health]`
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct HealthSection {
    /// Seconds between probes.
    pub probe_interval_secs: u64,
    /// Milliseconds one probe may take.
    pub probe_timeout_ms: u64,
    /// Consecutive failures before a browser counts as lost.
    pub unresponsive_strikes: u32,
}

impl Default for HealthSection {
    fn default() -> Self {
        let d = PoolConfig::default();
        Self {
            probe_interval_secs: d.probe_interval.as_secs(),
            probe_timeout_ms: u64::try_from(d.probe_timeout.as_millis()).unwrap_or(3000),
            unresponsive_strikes: d.unresponsive_strikes,
        }
    }
}

impl Config {
    /// Parses TOML text and validates the result.
    pub fn from_toml(text: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(text)
            .map_err(|e| Error::InvalidRequest(format!("configuration: {e}")))?;
        cfg.validated()
    }

    /// Reads, parses and validates a configuration file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::InvalidRequest(format!("cannot read {}: {e}", path.display())))?;
        Self::from_toml(&text)
    }

    /// Checks cross-field rules and normalizes the runtime section.
    pub fn validated(mut self) -> Result<Self> {
        let bad = |msg: String| Err(Error::InvalidRequest(format!("configuration: {msg}")));
        self.listen_addr()?;
        self.ops_addr()?;
        let base = url::Url::parse(&self.server.public_base_url)
            .map_err(|e| Error::InvalidRequest(format!("configuration: public_base_url: {e}")))?;
        if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
            return bad("public_base_url must be an http:// or https:// URL".into());
        }
        if self.auth.api_keys.is_empty() {
            return bad(
                "at least one [[auth.api_keys]] entry is required (create one with `browserx keys new <name>`)"
                    .into(),
            );
        }
        let mut names = std::collections::BTreeSet::new();
        for key in &self.auth.api_keys {
            if key.name.is_empty() || key.name.len() > 64 || key.name.chars().any(char::is_control)
            {
                return bad(format!(
                    "api key name {:?} is empty, too long or has control characters",
                    key.name
                ));
            }
            if key.sha256.len() != 64
                || !key
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return bad(format!(
                    "api key `{}`: sha256 must be 64 lowercase hex characters",
                    key.name
                ));
            }
            if key.max_sessions == 0 {
                return bad(format!(
                    "api key `{}`: max_sessions must be positive",
                    key.name
                ));
            }
            if !names.insert(key.name.clone()) {
                return bad(format!("duplicate api key name `{}`", key.name));
            }
        }
        self.egress.validate()?;
        self.runtime = self.runtime.validated()?;
        self.pool_config()?;
        Ok(self)
    }

    /// The API listener address.
    pub fn listen_addr(&self) -> Result<SocketAddr> {
        self.server.listen.parse().map_err(|e| {
            Error::InvalidRequest(format!(
                "configuration: server.listen {:?}: {e}",
                self.server.listen
            ))
        })
    }

    /// The operations listener address.
    pub fn ops_addr(&self) -> Result<SocketAddr> {
        self.server.ops_listen.parse().map_err(|e| {
            Error::InvalidRequest(format!(
                "configuration: server.ops_listen {:?}: {e}",
                self.server.ops_listen
            ))
        })
    }

    /// The scheduler configuration derived from this file.
    pub fn pool_config(&self) -> Result<PoolConfig> {
        let secs = Duration::from_secs;
        let quotas: BTreeMap<String, usize> = self
            .auth
            .api_keys
            .iter()
            .map(|k| (k.name.clone(), k.max_sessions))
            .collect();
        let cfg = PoolConfig {
            max_browsers: self.pool.max_browsers,
            max_contexts_per_browser: self.pool.max_contexts_per_browser,
            warm_shared_browsers: self.pool.warm_shared_browsers,
            queue_capacity: self.pool.queue_capacity,
            queue_timeout: secs(self.pool.queue_timeout_secs),
            browser_max_age: secs(self.pool.browser_max_age_secs),
            browser_max_contexts_served: self.pool.browser_max_contexts_served,
            default_ttl: secs(self.session.default_ttl_secs),
            max_ttl: secs(self.session.max_ttl_secs),
            max_lifetime: secs(self.session.max_lifetime_secs),
            default_idle_timeout: secs(self.session.default_idle_timeout_secs),
            snapshot_interval: secs(self.session.snapshot_interval_secs),
            snapshot_keep: self.session.snapshot_keep,
            terminal_retention: secs(self.session.terminal_retention_secs),
            probe_interval: secs(self.health.probe_interval_secs),
            probe_timeout: Duration::from_millis(self.health.probe_timeout_ms),
            unresponsive_strikes: self.health.unresponsive_strikes,
            owner_quotas: quotas,
            ..PoolConfig::default()
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const KEY: &str = "[[auth.api_keys]]\nname = \"dev\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n";

    #[test]
    fn minimal_config_gets_defaults() {
        let cfg = Config::from_toml(KEY).unwrap();
        assert_eq!(cfg.server.listen, "127.0.0.1:7690");
        assert_eq!(cfg.pool.max_browsers, 8);
        assert_eq!(cfg.auth.api_keys[0].max_sessions, 16);
        assert!(cfg.runtime.launch_profiles.contains_key("default"));
        assert_eq!(cfg.pool_config().unwrap().owner_quotas["dev"], 16);
    }

    #[test]
    fn unknown_keys_and_bad_values_are_rejected() {
        assert!(Config::from_toml(&format!("{KEY}[pool]\nmax_browser = 3\n")).is_err());
        assert!(Config::from_toml(&format!("{KEY}[server]\nlisten = \"nope\"\n")).is_err());
        assert!(
            Config::from_toml(&format!("{KEY}[server]\npublic_base_url = \"ftp://x\"\n")).is_err()
        );
        assert!(Config::from_toml(&format!("{KEY}[pool]\nmax_browsers = 0\n")).is_err());
        assert!(Config::from_toml("").is_err(), "an API key is required");
        assert!(
            Config::from_toml(&KEY.replace(
                "0000000000000000000000000000000000000000000000000000000000000000",
                "ABC"
            ))
            .is_err()
        );
        assert!(
            Config::from_toml(&format!("{KEY}{KEY}")).is_err(),
            "duplicate names"
        );
    }

    #[test]
    fn launch_profiles_and_egress_parse() {
        let text = format!(
            "{KEY}[egress]\nblock_private = true\nallow_cidrs = [\"10.1.0.0/16\"]\n\
             [runtime]\ndefault_launch_profile = \"x\"\n[runtime.launch_profiles.x]\nargs = [\"--lang=de-DE\"]\n"
        );
        let cfg = Config::from_toml(&text).unwrap();
        assert_eq!(cfg.egress.allow_cidrs, vec!["10.1.0.0/16".to_owned()]);
        assert_eq!(
            cfg.runtime.launch_profiles["x"].args,
            vec!["--lang=de-DE".to_owned()]
        );
        assert!(Config::from_toml(&format!("{KEY}[egress]\nallow_cidrs = [\"nope\"]\n")).is_err());
        assert!(
            Config::from_toml(&format!(
                "{KEY}[runtime.launch_profiles.default]\nargs = [\"--user-data-dir=/x\"]\n"
            ))
            .is_err()
        );
    }
}
