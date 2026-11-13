//! Opaque identifiers and the fencing generation.

use std::fmt;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// A fresh random identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// The textual form with its type prefix, for logs and URLs.
            #[must_use]
            pub fn prefixed(&self) -> String {
                format!(concat!($prefix, "_{}"), self.0.simple())
            }

            /// Parses either the bare UUID or the prefixed form.
            pub fn parse(s: &str) -> Result<Self, crate::Error> {
                let raw = s.strip_prefix(concat!($prefix, "_")).unwrap_or(s);
                Uuid::parse_str(raw)
                    .map(Self)
                    .map_err(|_| crate::Error::InvalidRequest(format!(
                        concat!("malformed ", stringify!($name), ": {}"), s
                    )))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.prefixed())
            }
        }
    };
}

uuid_id!(
    /// Public, stable identity of a logical session. Survives browser replacement.
    SessionId,
    "ses"
);
uuid_id!(
    /// One browser process (or remote browser) instance. Changes on relaunch.
    BrowserId,
    "brw"
);
uuid_id!(
    /// A worker: one supervisor process that owns browsers.
    WorkerId,
    "wrk"
);
uuid_id!(
    /// A persistent identity: a profile directory and/or its state snapshots.
    ProfileId,
    "prf"
);

/// A CDP browser-context identifier as reported by the browser.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContextId(pub String);

/// Monotonic fencing counter of a lease. Every ownership change (allocation,
/// recovery onto a new browser, handoff to a new controller) increments it.
/// Stores apply updates with compare-and-swap on the expected generation.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Generation(pub u64);

impl Generation {
    /// The next generation.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for Generation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "g{}", self.0)
    }
}

/// A bearer credential that authorizes attaching to one session generation.
///
/// Only its SHA-256 digest is stored; the plaintext is returned once to the
/// controller. The token is bound to a generation: a handoff issues a new token
/// and the previous one stops working.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LeaseToken(String);

impl LeaseToken {
    /// 32 random bytes, hex encoded, with a recognizable prefix for secret scanners.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self(format!("bxt_{}", hex::encode(bytes)))
    }

    /// Wraps a token received from a client.
    #[must_use]
    pub fn from_client(raw: String) -> Self {
        Self(raw)
    }

    /// The plaintext. Only ever sent to the controller that owns the lease.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Hex SHA-256 digest: the only form that is persisted.
    #[must_use]
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.0.as_bytes()))
    }
}

impl fmt::Debug for LeaseToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LeaseToken(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_ids_round_trip() {
        let id = SessionId::new();
        assert_eq!(SessionId::parse(&id.prefixed()).ok(), Some(id));
        assert_eq!(SessionId::parse(&id.0.to_string()).ok(), Some(id));
        assert!(SessionId::parse("ses_nope").is_err());
    }

    #[test]
    fn token_digest_is_stable_and_debug_redacts() {
        let t = LeaseToken::from_client("bxt_abc".into());
        assert_eq!(
            t.digest(),
            LeaseToken::from_client("bxt_abc".into()).digest()
        );
        assert!(!format!("{t:?}").contains("abc"));
        assert!(LeaseToken::generate().expose().starts_with("bxt_"));
    }
}
