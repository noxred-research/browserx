//! What a client asks for when it creates a session, and the explicit contracts
//! for persistence, isolation, egress and recovery.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::ids::ProfileId;
use crate::secret::Secret;

/// Exactly which state outlives the browser process. There is deliberately no
/// boolean "persistent" flag: each mode is a different engineering contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceMode {
    /// Nothing survives the browser. Recovery starts a fresh, empty browser.
    #[default]
    Ephemeral,
    /// Cookies and per-origin storage are captured into encrypted, versioned
    /// snapshots (on demand, periodically and before release) and replayed into a
    /// new browser on recovery. Portable across workers; does not carry the
    /// JavaScript heap, open sockets, service-worker runtime or cache.
    Snapshot,
    /// A dedicated user-data directory under an exclusive lock. Highest
    /// persistence fidelity on one worker; not portable; one browser at a time.
    Profile,
}

/// How strongly a session is separated from others.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// An isolated browser context inside a shared, warm browser process.
    /// Cheap and fast, but one crashed browser takes down every context in it,
    /// and browser-level CDP access could reach sibling contexts. Callers only
    /// ever receive a context-scoped relay, never the browser-level endpoint.
    SharedBrowser,
    /// A browser process of its own. Required for `Profile` persistence and for
    /// untrusted tenants.
    #[default]
    DedicatedBrowser,
}

/// What the scheduler may do when the browser behind a session is lost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPolicy {
    /// Never replace the browser. A lost browser ends the session (`lost`).
    None,
    /// Relaunch and restore whatever the persistence mode keeps.
    #[default]
    Restore,
}

/// Result of attaching to (or recovering) a session. Reported on every attach so
/// a controller never assumes in-memory page state survived when it did not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOutcome {
    /// The same browser process is alive: open pages, JavaScript heaps and
    /// sockets are intact. Only the controller changed.
    ResumedSameProcess,
    /// A new browser process was launched and the profile directory reused.
    RestoredFromProfile,
    /// A new browser process was launched and a state snapshot replayed
    /// (cookies and origin storage only).
    RestoredFromSnapshot,
    /// A new, empty browser process. Nothing was restored.
    FreshProcess,
}

/// Upstream egress for one session's browser traffic. The browser always talks
/// to a loopback forwarder owned by the worker; the forwarder dials this route.
/// Credentials never reach browser flags or logs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRoute {
    /// `http://host:port`, `https://host:port` or `socks5://host:port`.
    /// The forwarder converts plain-HTTP requests into CONNECT tunnels, so
    /// CONNECT-only upstream gateways work for `http://` pages too.
    pub url: String,
    /// Optional username. `{session}` and `{generation}` are substituted with an
    /// opaque per-session sticky key and the lease generation, so an upstream
    /// pool that pins exits by username keeps one exit per session.
    #[serde(default)]
    pub username: Option<String>,
    /// Optional password.
    #[serde(default)]
    pub password: Option<Secret>,
}

impl ProxyRoute {
    /// Validates scheme and shape without resolving anything.
    pub fn validate(&self) -> Result<()> {
        let scheme = self
            .url
            .split_once("://")
            .map(|(s, _)| s.to_ascii_lowercase())
            .ok_or_else(|| Error::InvalidRequest("proxy url needs a scheme".into()))?;
        if !matches!(scheme.as_str(), "http" | "https" | "socks5" | "socks5h") {
            return Err(Error::InvalidRequest(format!(
                "unsupported proxy scheme {scheme}"
            )));
        }
        if self.url.contains('@') {
            return Err(Error::InvalidRequest(
                "put proxy credentials in username/password, not in the url".into(),
            ));
        }
        Ok(())
    }

    /// The username with `{session}` / `{generation}` substituted.
    #[must_use]
    pub fn render_username(&self, sticky_key: &str, generation: u64) -> Option<String> {
        self.username.as_ref().map(|u| {
            u.replace("{session}", sticky_key)
                .replace("{generation}", &generation.to_string())
        })
    }
}

/// Reads the optional `profile_id` request field in either form: the prefixed
/// form the API emits (`prf_` followed by the UUID) or the bare UUID.
fn deserialize_profile_id<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<ProfileId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|raw| ProfileId::parse(&raw).map_err(serde::de::Error::custom))
        .transpose()
}

/// A request for a new session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSpec {
    /// Named launch profile from the server configuration (browser executable,
    /// flags, headless mode). `None` selects the configured default.
    #[serde(default)]
    pub launch_profile: Option<String>,
    /// What survives the browser process.
    #[serde(default)]
    pub persistence: PersistenceMode,
    /// Process isolation.
    #[serde(default)]
    pub isolation: Isolation,
    /// Persistent identity to reuse (profile directory and/or snapshots). A new
    /// one is created when absent and persistence is not `ephemeral`.
    #[serde(default, deserialize_with = "deserialize_profile_id")]
    pub profile_id: Option<ProfileId>,
    /// Upstream egress. `None` means direct egress from the worker.
    #[serde(default)]
    pub proxy: Option<ProxyRoute>,
    /// Lease time-to-live in seconds; renewals extend it. Bounded by server limits.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Hard cap on total session lifetime regardless of renewals.
    #[serde(default)]
    pub max_lifetime_secs: Option<u64>,
    /// Release the session after this long without an attached controller.
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    /// Recovery behavior when the browser is lost.
    #[serde(default)]
    pub recovery: RecoveryPolicy,
    /// Free-form labels for the caller's bookkeeping (bounded, not interpreted).
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl Default for SessionSpec {
    fn default() -> Self {
        Self {
            launch_profile: None,
            persistence: PersistenceMode::Ephemeral,
            isolation: Isolation::DedicatedBrowser,
            profile_id: None,
            proxy: None,
            ttl_secs: None,
            max_lifetime_secs: None,
            idle_timeout_secs: None,
            recovery: RecoveryPolicy::Restore,
            labels: BTreeMap::new(),
        }
    }
}

/// Maximum number of labels and their byte sizes.
pub const MAX_LABELS: usize = 32;
/// Maximum label key or value length in bytes.
pub const MAX_LABEL_BYTES: usize = 256;

impl SessionSpec {
    /// Rejects contradictory or oversized specifications at admission.
    pub fn validate(&self) -> Result<()> {
        if self.persistence == PersistenceMode::Profile
            && self.isolation == Isolation::SharedBrowser
        {
            return Err(Error::InvalidRequest(
                "profile persistence needs isolation=dedicated_browser: a profile directory \
                 belongs to exactly one browser process"
                    .into(),
            ));
        }
        if self.isolation == Isolation::SharedBrowser && self.proxy.is_some() {
            // Chromium applies proxy settings per browser context, but the
            // forwarder is per browser process; keep egress identity unambiguous.
            return Err(Error::InvalidRequest(
                "a per-session proxy needs isolation=dedicated_browser".into(),
            ));
        }
        if let Some(p) = &self.proxy {
            p.validate()?;
        }
        if self.labels.len() > MAX_LABELS
            || self
                .labels
                .iter()
                .any(|(k, v)| k.len() > MAX_LABEL_BYTES || v.len() > MAX_LABEL_BYTES)
        {
            return Err(Error::InvalidRequest("too many or too long labels".into()));
        }
        for v in [
            self.ttl_secs,
            self.max_lifetime_secs,
            self.idle_timeout_secs,
        ]
        .into_iter()
        .flatten()
        {
            if v == 0 {
                return Err(Error::InvalidRequest("durations must be positive".into()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_needs_dedicated_browser() {
        let spec = SessionSpec {
            persistence: PersistenceMode::Profile,
            isolation: Isolation::SharedBrowser,
            ..SessionSpec::default()
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn proxy_credentials_must_not_be_in_url() {
        let route = ProxyRoute {
            url: "http://user:pw@proxy.test:8080".into(),
            username: None,
            password: None,
        };
        assert!(route.validate().is_err());
    }

    #[test]
    fn username_template_substitution() {
        let route = ProxyRoute {
            url: "socks5://proxy.test:1080".into(),
            username: Some("pool-sid-{session}-g{generation}".into()),
            password: None,
        };
        assert_eq!(
            route.render_username("abc", 3).as_deref(),
            Some("pool-sid-abc-g3")
        );
    }

    #[test]
    fn unknown_fields_are_refused() {
        let parsed: std::result::Result<SessionSpec, _> =
            serde_json::from_str(r#"{"persistent": true}"#);
        assert!(parsed.is_err());
    }

    #[test]
    fn profile_id_accepts_prefixed_and_bare_forms() -> std::result::Result<(), serde_json::Error> {
        let id = ProfileId::new();
        for text in [id.prefixed(), id.0.to_string(), id.0.simple().to_string()] {
            let spec: SessionSpec =
                serde_json::from_value(serde_json::json!({ "profile_id": text }))?;
            assert_eq!(spec.profile_id, Some(id), "{text}");
        }
        let none: SessionSpec = serde_json::from_str("{}")?;
        assert_eq!(none.profile_id, None);
        let null: SessionSpec = serde_json::from_str(r#"{"profile_id": null}"#)?;
        assert_eq!(null.profile_id, None);
        Ok(())
    }

    #[test]
    fn profile_id_rejects_malformed_values() {
        for bad in [
            r#"{"profile_id": "prf_nope"}"#,
            r#"{"profile_id": "ses_0"}"#,
            r#"{"profile_id": 7}"#,
        ] {
            assert!(serde_json::from_str::<SessionSpec>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_proxy_fields_are_refused() {
        let parsed: std::result::Result<SessionSpec, _> =
            serde_json::from_str(r#"{"proxy": {"url": "http://proxy.test:8080", "usrname": "u"}}"#);
        assert!(parsed.is_err());
        let ok: SessionSpec = serde_json::from_str(
            r#"{"proxy": {"url": "http://proxy.test:8080", "username": "u", "password": "p"}}"#,
        )
        .unwrap();
        assert!(ok.proxy.is_some());
    }
}
