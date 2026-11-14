//! A string that never appears in `Debug`, `Display` or serialized logs.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// Credential material (proxy passwords, API keys). `Debug` prints a placeholder;
/// serialization writes the value because configuration and storage need it, so
/// never log a structure containing a `Secret` through `serde_json`.
///
/// The plaintext is overwritten with zeros when the value is dropped. Clones
/// are independent copies and are zeroized on their own drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps a value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The plaintext, for the one call site that needs it.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn is_zeroized_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}

    #[test]
    fn debug_is_redacted_and_value_round_trips() {
        let secret = Secret::new("synthetic-secret");
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert_eq!(secret.expose(), "synthetic-secret");
        let json = serde_json::to_string(&secret).unwrap();
        assert_eq!(json, "\"synthetic-secret\"");
        let back: Secret = serde_json::from_str(&json).unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn plaintext_is_held_in_a_zeroize_on_drop_buffer() {
        let secret = Secret::new("synthetic-secret");
        is_zeroized_on_drop(&secret.0);
        assert_eq!(secret.clone().expose(), secret.expose());
    }
}
