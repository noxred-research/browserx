//! The sessions this server controls: the ones it created and the ones it was configured to
//! adopt. Only controlled sessions can be browsed, renewed or snapshotted, because only they
//! have a token the server holds. Tokens live here and nowhere else.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use browserx_core::Secret;

/// A controlled session.
#[derive(Clone)]
pub struct Managed {
    /// Session id (`ses_...`).
    pub id: String,
    /// The controller token.
    pub token: Secret,
    /// Configured with `[[adopt]]` rather than created by this server.
    pub adopted: bool,
}

impl std::fmt::Debug for Managed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Managed")
            .field("id", &self.id)
            .field("adopted", &self.adopted)
            .finish_non_exhaustive()
    }
}

/// The table of controlled sessions.
#[derive(Debug, Default)]
pub struct Registry {
    inner: Mutex<BTreeMap<String, Managed>>,
}

impl Registry {
    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Managed>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds or replaces a session.
    pub fn insert(&self, managed: Managed) {
        self.map().insert(managed.id.clone(), managed);
    }

    /// The controlled session `id`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<Managed> {
        self.map().get(id).cloned()
    }

    /// Stops controlling `id`.
    pub fn remove(&self, id: &str) -> Option<Managed> {
        self.map().remove(id)
    }

    /// Ids of every controlled session.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        self.map().keys().cloned().collect()
    }

    /// Sessions this server created (not adopted).
    #[must_use]
    pub fn created(&self) -> Vec<Managed> {
        self.map()
            .values()
            .filter(|m| !m.adopted)
            .cloned()
            .collect()
    }

    /// Number of controlled sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map().len()
    }

    /// Whether no session is controlled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map().is_empty()
    }
}
