//! Secret redaction for audit entries, tool output and model prompts.
//!
//! Two mechanisms work together: members whose *name* says they hold a secret are replaced
//! wholesale, and *text* is scrubbed of the exact secret values this server knows (API key,
//! HTTP token, model key, proxy passwords) and of recognizable credential shapes (BrowserX
//! lease tokens and keys, `Bearer` values, URL user information, `sk-` keys).

use serde_json::Value;

/// The replacement text.
pub const REDACTED: &str = "[redacted]";

/// Shortest known secret that is scrubbed by value; shorter values would match too much text.
const MIN_SECRET_LEN: usize = 8;

const SECRET_NAMES: [&str; 12] = [
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "credentials",
    "cookie",
    "cdp_url",
];
const SAFE_SUFFIXES: [&str; 8] = [
    "_sha256",
    "_digest",
    "_ref",
    "_file",
    "_path",
    "_present",
    "_configured",
    "_count",
];

/// True when a member with this name must not be shown.
#[must_use]
pub fn is_secret_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase().replace('-', "_");
    if SAFE_SUFFIXES.iter().any(|suffix| lower.ends_with(suffix)) {
        return false;
    }
    SECRET_NAMES
        .iter()
        .any(|secret| lower == *secret || lower.ends_with(&format!("_{secret}")))
}

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'~' | b'+' | b'/' | b'=')
}

/// Replaces `prefix` followed by at least `min_tail` token characters.
fn replace_prefixed(text: &str, prefix: &str, min_tail: usize, replacement: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while let Some(found) = text[index..].find(prefix) {
        let start = index + found;
        let boundary_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let tail_start = start + prefix.len();
        let tail_len = bytes[tail_start..]
            .iter()
            .take_while(|byte| is_token_char(**byte))
            .count();
        out.push_str(&text[index..start]);
        if boundary_ok && tail_len >= min_tail {
            out.push_str(replacement);
            index = tail_start + tail_len;
        } else {
            out.push_str(prefix);
            index = tail_start;
        }
    }
    out.push_str(&text[index..]);
    out
}

/// Replaces `scheme://user:password@` (and `scheme://token@`) user information.
fn replace_userinfo(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(found) = rest.find("://") {
        let (head, tail) = rest.split_at(found + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
            .unwrap_or(tail.len());
        let authority = &tail[..end];
        match authority.rfind('@') {
            Some(at) if at > 0 => {
                out.push_str(REDACTED);
                out.push_str(&authority[at..]);
            }
            _ => out.push_str(authority),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// `text` with credential shapes replaced.
#[must_use]
pub fn redact_text(text: &str) -> String {
    let mut out = replace_prefixed(text, "bxt_", 16, REDACTED);
    out = replace_prefixed(&out, "bxk_", 8, REDACTED);
    out = replace_prefixed(&out, "sk-", 16, REDACTED);
    out = replace_prefixed(&out, "Bearer ", 8, "Bearer [redacted]");
    out = replace_prefixed(&out, "bearer ", 8, "bearer [redacted]");
    replace_userinfo(&out)
}

/// Scrubs exact secret values and credential shapes from text and JSON.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    /// A redactor that also scrubs each of `secrets` (values shorter than eight characters are
    /// ignored: they would match ordinary text).
    #[must_use]
    pub fn new(secrets: impl IntoIterator<Item = String>) -> Self {
        let mut secrets: Vec<String> = secrets
            .into_iter()
            .filter(|secret| secret.len() >= MIN_SECRET_LEN)
            .collect();
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets.dedup();
        Self { secrets }
    }

    /// `text` with known secrets and credential shapes replaced.
    #[must_use]
    pub fn text(&self, text: &str) -> String {
        #[cfg(feature = "fault-injection")]
        if crate::faults::active(crate::faults::Fault::Redaction) {
            return text.to_owned();
        }
        let mut out = text.to_owned();
        for secret in &self.secrets {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), REDACTED);
            }
        }
        redact_text(&out)
    }

    /// Redacts a JSON value in place: secret-named members are replaced, strings are scrubbed.
    pub fn value(&self, value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (name, member) in map.iter_mut() {
                    if is_secret_name(name) && !member.is_null() && !member.is_boolean() {
                        *member = Value::String(REDACTED.to_owned());
                    } else {
                        self.value(member);
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|item| self.value(item)),
            Value::String(text) => {
                let scrubbed = self.text(text);
                if scrubbed != *text {
                    *text = scrubbed;
                }
            }
            _ => {}
        }
    }

    /// A redacted copy of `value`.
    #[must_use]
    pub fn redacted(&self, value: &Value) -> Value {
        let mut copy = value.clone();
        self.value(&mut copy);
        copy
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use serde_json::json;

    use super::*;

    #[test]
    fn secret_names_are_recognized_but_references_are_not() {
        for name in [
            "password",
            "api_key",
            "proxy_password",
            "Authorization",
            "cdp_url",
        ] {
            assert!(is_secret_name(name), "{name}");
        }
        for name in [
            "token_sha256",
            "password_file",
            "session_id",
            "tokens_count",
            "label",
        ] {
            assert!(!is_secret_name(name), "{name}");
        }
    }

    #[test]
    fn shapes_are_scrubbed_from_text() {
        let text = "ws://127.0.0.1:7690/cdp/ses_abc/bxt_0123456789abcdef0123 and \
                    Authorization: Bearer abcdefghijkl key bxk_test_alpha_x and \
                    http://user:pw@host.test/x and sk-0123456789abcdefghij";
        let out = redact_text(text);
        for leaked in ["bxt_0123", "abcdefghijkl", "bxk_test", "user:pw", "sk-0123"] {
            assert!(!out.contains(leaked), "{leaked} leaked: {out}");
        }
        assert!(out.contains("host.test/x"));
        assert_eq!(redact_text("plain bxt_ and sk-"), "plain bxt_ and sk-");
    }

    #[test]
    fn known_values_and_named_members_are_scrubbed() {
        let redactor = Redactor::new(["synthetic-api-key-value".to_owned(), "short".to_owned()]);
        let mut value = json!({
            "note": "key is synthetic-api-key-value, short stays",
            "password": "hunter2hunter2",
            "nested": [{"token": "x", "label": "ok", "cdp_url": "ws://x/cdp/a/b"}],
            "flag": {"cookie": true}
        });
        redactor.value(&mut value);
        assert_eq!(value["note"], "key is [redacted], short stays");
        assert_eq!(value["password"], REDACTED);
        assert_eq!(value["nested"][0]["token"], REDACTED);
        assert_eq!(value["nested"][0]["cdp_url"], REDACTED);
        assert_eq!(value["nested"][0]["label"], "ok");
        assert_eq!(value["flag"]["cookie"], true);
    }
}
