//! A small bounded store of recent screenshots, served as resources so a result can carry a
//! `resource_link` instead of an inline image.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use rand::Rng as _;

/// Most screenshots kept.
const MAX_SHOTS: usize = 16;
/// Most base64 characters kept in total.
const MAX_BYTES: usize = 24 * 1024 * 1024;

/// URI scheme prefix of stored screenshots.
pub const URI_PREFIX: &str = "browserx://screenshots/";

#[derive(Debug, Default)]
struct Inner {
    items: VecDeque<(String, String)>,
    bytes: usize,
}

/// The store.
#[derive(Debug, Default)]
pub struct Shots {
    inner: Mutex<Inner>,
}

impl Shots {
    /// Keeps a base64 PNG and returns its resource URI. Older screenshots are dropped first
    /// when a bound is exceeded.
    pub fn put(&self, base64_png: &str) -> String {
        let mut bytes = [0_u8; 8];
        rand::rng().fill_bytes(&mut bytes);
        let id = format!("shot_{}", hex::encode(bytes));
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.bytes += base64_png.len();
        inner.items.push_back((id.clone(), base64_png.to_owned()));
        while inner.items.len() > MAX_SHOTS || (inner.bytes > MAX_BYTES && inner.items.len() > 1) {
            if let Some((_, old)) = inner.items.pop_front() {
                inner.bytes = inner.bytes.saturating_sub(old.len());
            }
        }
        format!("{URI_PREFIX}{id}")
    }

    /// The base64 PNG behind a resource URI.
    #[must_use]
    pub fn get(&self, uri: &str) -> Option<String> {
        let id = uri.strip_prefix(URI_PREFIX)?;
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .items
            .iter()
            .find(|(stored, _)| stored == id)
            .map(|(_, data)| data.clone())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn screenshots_are_served_by_uri_and_bounded() {
        let shots = Shots::default();
        let first = shots.put("AAAA");
        assert_eq!(shots.get(&first).as_deref(), Some("AAAA"));
        assert!(shots.get("browserx://screenshots/nope").is_none());
        assert!(shots.get("other://x").is_none());
        for _ in 0..MAX_SHOTS {
            let _ = shots.put("BBBB");
        }
        assert!(shots.get(&first).is_none(), "the oldest was dropped");
    }
}
