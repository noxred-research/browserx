//! Launch profiles and runtime configuration.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use browserx_core::{Error, Result};
use serde::{Deserialize, Serialize};

/// Flag name prefixes and names the runtime owns. A launch profile may not set them.
const MANAGED_PREFIXES: &[&str] = &["remote-debugging-"];
const MANAGED_FLAGS: &[&str] = &[
    "user-data-dir",
    "proxy-server",
    "proxy-bypass-list",
    "proxy-pac-url",
    "proxy-auto-detect",
    "no-proxy-server",
    "headless",
    "force-webrtc-ip-handling-policy",
    "webrtc-ip-handling-policy",
];

/// Longest startup timeout accepted; keeps deadline arithmetic far from overflow
/// and a stuck launch from holding a warm-pool slot for hours.
pub const MAX_STARTUP_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Smallest and largest accepted `cdp_max_message_bytes`.
const MIN_CDP_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_CDP_MESSAGE_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_CDP_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// How to start one flavour of browser.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LaunchProfile {
    /// Browser executable. `None` = [`crate::discover_chromium`].
    pub executable: Option<PathBuf>,
    /// Run without a display (`--headless=new`). Default `true`.
    pub headless: bool,
    /// Extra command-line flags. Managed flags (remote debugging, user-data-dir,
    /// proxy, headless, WebRTC IP handling) are rejected.
    pub args: Vec<String>,
    /// Extra environment variables for the browser process.
    pub env: BTreeMap<String, String>,
}

impl Default for LaunchProfile {
    fn default() -> Self {
        Self {
            executable: None,
            headless: true,
            args: Vec::new(),
            env: BTreeMap::new(),
        }
    }
}

impl LaunchProfile {
    /// Rejects profiles that would override flags the runtime manages, or whose
    /// environment cannot be passed to a process.
    pub fn validate(&self, name: &str) -> Result<()> {
        for arg in &self.args {
            if let Some(flag) = managed_flag(arg) {
                return Err(Error::InvalidRequest(format!(
                    "launch profile `{name}`: `--{flag}` is managed by the runtime and cannot be set"
                )));
            }
            if arg.contains('\0') {
                return Err(Error::InvalidRequest(format!(
                    "launch profile `{name}`: argument contains a NUL byte"
                )));
            }
        }
        for (key, value) in &self.env {
            if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
                return Err(Error::InvalidRequest(format!(
                    "launch profile `{name}`: invalid environment variable `{key}`"
                )));
            }
        }
        Ok(())
    }
}

/// Returns the managed flag name when `arg` sets one.
fn managed_flag(arg: &str) -> Option<&str> {
    let body = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-'))?;
    let name = body.split('=').next().unwrap_or(body);
    let managed = MANAGED_FLAGS.contains(&name)
        || MANAGED_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix));
    managed.then_some(name)
}

/// Runtime configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuntimeConfig {
    /// Launch profile used when a request names none. Default `"default"`.
    pub default_launch_profile: String,
    /// Named launch profiles. When empty, a `default` profile is added.
    pub launch_profiles: BTreeMap<String, LaunchProfile>,
    /// How long a launch may take before the process is killed. Default 30 s,
    /// at most [`MAX_STARTUP_TIMEOUT`] (10 minutes).
    /// Serialized as whole seconds under `startup_timeout_secs`.
    #[serde(rename = "startup_timeout_secs", with = "secs")]
    pub startup_timeout: Duration,
    /// Parent directory for temporary user-data directories and for the
    /// per-browser records that let [`crate::ChromiumRuntime::sweep_orphans`]
    /// clean up after a crashed worker.
    pub temp_root: PathBuf,
    /// Largest single reply the runtime's own DevTools connection to a browser
    /// accepts. A bigger reply (a page cannot normally cause one) drops that
    /// connection; the runtime reconnects on the next call. Default 64 MiB,
    /// between 1 MiB and 256 MiB.
    pub cdp_max_message_bytes: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            default_launch_profile: "default".to_owned(),
            launch_profiles: BTreeMap::new(),
            startup_timeout: Duration::from_secs(30),
            temp_root: std::env::temp_dir().join("browserx"),
            cdp_max_message_bytes: DEFAULT_CDP_MESSAGE_BYTES,
        }
    }
}

impl RuntimeConfig {
    /// Validates every profile and returns the config with the default profile
    /// materialized.
    pub fn validated(mut self) -> Result<Self> {
        if self.launch_profiles.is_empty() {
            self.launch_profiles.insert(
                self.default_launch_profile.clone(),
                LaunchProfile::default(),
            );
        }
        if !self
            .launch_profiles
            .contains_key(&self.default_launch_profile)
        {
            return Err(Error::InvalidRequest(format!(
                "default launch profile `{}` is not defined",
                self.default_launch_profile
            )));
        }
        for (name, profile) in &self.launch_profiles {
            profile.validate(name)?;
        }
        if self.startup_timeout.is_zero() {
            return Err(Error::InvalidRequest(
                "startup timeout must be positive".into(),
            ));
        }
        if self.startup_timeout > MAX_STARTUP_TIMEOUT {
            return Err(Error::InvalidRequest(format!(
                "startup timeout must be at most {} seconds",
                MAX_STARTUP_TIMEOUT.as_secs()
            )));
        }
        if !(MIN_CDP_MESSAGE_BYTES..=MAX_CDP_MESSAGE_BYTES).contains(&self.cdp_max_message_bytes) {
            return Err(Error::InvalidRequest(format!(
                "cdp_max_message_bytes must be between {MIN_CDP_MESSAGE_BYTES} and {MAX_CDP_MESSAGE_BYTES}"
            )));
        }
        Ok(self)
    }
}

mod secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(value.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        u64::deserialize(d).map(Duration::from_secs)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn profile(args: &[&str]) -> LaunchProfile {
        LaunchProfile {
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn managed_flags_are_rejected() {
        for arg in [
            "--remote-debugging-port=9222",
            "--remote-debugging-address=0.0.0.0",
            "--remote-debugging-pipe",
            "--user-data-dir=/x",
            "--proxy-server=http://p:1",
            "--proxy-bypass-list=*",
            "--proxy-pac-url=http://x/pac",
            "--no-proxy-server",
            "--force-webrtc-ip-handling-policy=default",
            "--webrtc-ip-handling-policy=default",
            "--headless=old",
            "-user-data-dir=/x",
        ] {
            assert!(
                profile(&[arg]).validate("p").is_err(),
                "{arg} should be rejected"
            );
        }
    }

    #[test]
    fn ordinary_flags_pass() {
        let ok = profile(&[
            "--no-sandbox",
            "--lang=de-DE",
            "--window-size=1280,720",
            "--headless-ish",
        ]);
        assert!(ok.validate("p").is_ok());
    }

    #[test]
    fn bad_environment_is_rejected() {
        let mut p = LaunchProfile::default();
        p.env.insert("A=B".into(), "x".into());
        assert!(p.validate("p").is_err());
    }

    #[test]
    fn unknown_fields_are_refused() {
        let parsed: std::result::Result<LaunchProfile, _> =
            serde_json::from_str(r#"{"headless": true, "sandbox": false}"#);
        assert!(parsed.is_err());
        let parsed: std::result::Result<RuntimeConfig, _> =
            serde_json::from_str(r#"{"startup_timeout": 5}"#);
        assert!(parsed.is_err());
    }

    #[test]
    fn defaults_deserialize_from_empty_and_materialize_default_profile() {
        let cfg: RuntimeConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.startup_timeout, Duration::from_secs(30));
        let cfg = cfg.validated().unwrap();
        assert!(cfg.launch_profiles["default"].headless);
    }

    #[test]
    fn missing_default_profile_is_an_error() {
        let mut cfg = RuntimeConfig::default();
        cfg.launch_profiles
            .insert("other".into(), LaunchProfile::default());
        assert!(cfg.validated().is_err());
    }

    #[test]
    fn startup_timeout_is_bounded() {
        let ok = RuntimeConfig {
            startup_timeout: MAX_STARTUP_TIMEOUT,
            ..RuntimeConfig::default()
        };
        assert!(ok.validated().is_ok());
        for secs in [MAX_STARTUP_TIMEOUT.as_secs() + 1, u64::MAX] {
            let cfg = RuntimeConfig {
                startup_timeout: Duration::from_secs(secs),
                ..RuntimeConfig::default()
            };
            assert!(
                matches!(cfg.validated(), Err(Error::InvalidRequest(_))),
                "{secs} s must be refused"
            );
        }
        let huge: RuntimeConfig =
            serde_json::from_str(&format!(r#"{{"startup_timeout_secs": {}}}"#, u64::MAX)).unwrap();
        assert!(huge.validated().is_err());
    }

    #[test]
    fn cdp_message_limit_is_bounded() {
        for bytes in [0, 1024, 257 * 1024 * 1024] {
            let cfg = RuntimeConfig {
                cdp_max_message_bytes: bytes,
                ..RuntimeConfig::default()
            };
            assert!(cfg.validated().is_err(), "{bytes}");
        }
        assert!(RuntimeConfig::default().validated().is_ok());
    }

    #[test]
    fn startup_timeout_round_trips_as_seconds() {
        let cfg: RuntimeConfig = serde_json::from_str(r#"{"startup_timeout_secs": 7}"#).unwrap();
        assert_eq!(cfg.startup_timeout, Duration::from_secs(7));
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["startup_timeout_secs"], 7);
    }
}
