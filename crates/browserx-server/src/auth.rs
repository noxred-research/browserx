//! API key authentication: keys are compared by SHA-256 digest in constant time.

use browserx_core::{Error, Result};
use sha2::{Digest, Sha256};

use crate::config::ApiKeyConfig;

/// The set of accepted API keys.
#[derive(Clone, Debug)]
pub struct Authenticator {
    keys: Vec<(String, [u8; 32])>,
}

impl Authenticator {
    /// Builds the authenticator from configured digests.
    pub fn new(keys: &[ApiKeyConfig]) -> Result<Self> {
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let mut digest = [0u8; 32];
            hex::decode_to_slice(&key.sha256, &mut digest).map_err(|_| {
                Error::InvalidRequest(format!(
                    "api key `{}`: sha256 is not 64 hex characters",
                    key.name
                ))
            })?;
            out.push((key.name.clone(), digest));
        }
        Ok(Self { keys: out })
    }

    /// Returns the owner name of the matching key. Every configured digest is
    /// compared, so timing does not reveal which key (if any) matched.
    #[must_use]
    pub fn authenticate(&self, presented: &str) -> Option<&str> {
        let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        let mut found = None;
        for (name, expected) in &self.keys {
            let diff = expected
                .iter()
                .zip(digest.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b));
            if diff == 0 && found.is_none() {
                found = Some(name.as_str());
            }
        }
        found
    }
}

/// Hex SHA-256 of an API key, as stored in the configuration file.
#[must_use]
pub fn key_digest(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn matches_only_the_right_key() {
        let keys = vec![
            ApiKeyConfig {
                name: "a".into(),
                sha256: key_digest("bxk_alpha"),
                max_sessions: 1,
            },
            ApiKeyConfig {
                name: "b".into(),
                sha256: key_digest("bxk_beta"),
                max_sessions: 1,
            },
        ];
        let auth = Authenticator::new(&keys).unwrap();
        assert_eq!(auth.authenticate("bxk_beta"), Some("b"));
        assert_eq!(auth.authenticate("bxk_alpha"), Some("a"));
        assert_eq!(auth.authenticate("bxk_gamma"), None);
        assert_eq!(auth.authenticate(""), None);
    }
}
