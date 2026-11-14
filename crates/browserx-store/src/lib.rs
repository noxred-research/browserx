//! Storage backends for BrowserX.
//!
//! * [`MemoryLeaseStore`] and [`SqliteLeaseStore`] implement
//!   [`browserx_core::LeaseStore`]: the lease registry, fenced by generation.
//! * [`MemorySnapshotStore`] and [`FileSnapshotStore`] implement
//!   [`browserx_core::SnapshotStore`]: versioned, already-encrypted snapshots.
//! * [`S3SnapshotStore`] implements the same trait on an S3-API object store (profiles `standard`,
//!   `edge`, `self-hosted`, `compatible`) through [`ObjectStore`], a SigV4 client without a cloud SDK.
//! * [`Sealer`] encrypts [`browserx_core::StateSnapshot`] values with
//!   AES-256-GCM before they reach any snapshot store, binding the ciphertext to
//!   its metadata so that stored bytes cannot be swapped between profiles,
//!   sessions, versions or generations.
//!
//! All backends pass the same conformance suite (see `tests/`).

mod common;
mod lease_mariadb;
mod lease_memory;
mod lease_postgres;
mod lease_sqlite;
mod object;
mod relational;
mod sealer;
mod snapshot_file;
mod snapshot_memory;
mod snapshot_s3;

pub use lease_mariadb::MariaDbLeaseStore;
pub use lease_memory::MemoryLeaseStore;
pub use lease_postgres::PostgresLeaseStore;
pub use lease_sqlite::SqliteLeaseStore;
pub use object::{ObjectError, ObjectHead, ObjectStore, ObjectStoreConfig, Profile, Sse, sigv4};
pub use relational::{DEFAULT_SCHEMA, DatabaseConfig, Engine, PASSWORD_ENV, TlsMode};
pub use sealer::Sealer;
pub use snapshot_file::FileSnapshotStore;
pub use snapshot_memory::MemorySnapshotStore;
pub use snapshot_s3::S3SnapshotStore;
pub use zeroize::Zeroizing;

/// Largest sealed snapshot (nonce, ciphertext and tag) a snapshot store accepts.
pub const MAX_SEALED_BYTES: usize = 64 * 1024 * 1024;
