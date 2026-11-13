//! Storage backends for BrowserX.
//!
//! * [`MemoryLeaseStore`] and [`SqliteLeaseStore`] implement
//!   [`browserx_core::LeaseStore`]: the lease registry, fenced by generation.
//! * [`MemorySnapshotStore`] and [`FileSnapshotStore`] implement
//!   [`browserx_core::SnapshotStore`]: versioned, already-encrypted snapshots.
//! * [`Sealer`] encrypts [`browserx_core::StateSnapshot`] values with
//!   AES-256-GCM before they reach any snapshot store, binding the ciphertext to
//!   its metadata so that stored bytes cannot be swapped between profiles,
//!   sessions, versions or generations.
//!
//! All backends pass the same conformance suite (see `tests/`).

mod common;
mod lease_memory;
mod lease_sqlite;
mod sealer;
mod snapshot_file;
mod snapshot_memory;

pub use lease_memory::MemoryLeaseStore;
pub use lease_sqlite::SqliteLeaseStore;
pub use sealer::Sealer;
pub use snapshot_file::FileSnapshotStore;
pub use snapshot_memory::MemorySnapshotStore;
pub use zeroize::Zeroizing;

/// Largest sealed snapshot (nonce, ciphertext and tag) a snapshot store accepts.
pub const MAX_SEALED_BYTES: usize = 64 * 1024 * 1024;
