//! One conformance suite, run against every store implementation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use browserx_core::clock::ManualClock;
use browserx_store::{FileSnapshotStore, MemoryLeaseStore, MemorySnapshotStore, SqliteLeaseStore};

#[tokio::test]
async fn memory_lease_store_conforms() {
    let clock = Arc::new(ManualClock::new(common::epoch()));
    let store = Arc::new(MemoryLeaseStore::with_clock(clock.clone()));
    common::lease_store_conformance(store, clock).await;
}

#[tokio::test]
async fn sqlite_lease_store_conforms() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(common::epoch()));
    let store = Arc::new(
        SqliteLeaseStore::open_with_clock(&dir.path().join("leases.db"), clock.clone()).unwrap(),
    );
    common::lease_store_conformance(store, clock).await;
}

#[tokio::test]
async fn memory_snapshot_store_conforms() {
    common::snapshot_store_conformance(Arc::new(MemorySnapshotStore::new())).await;
}

#[tokio::test]
async fn file_snapshot_store_conforms() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileSnapshotStore::new(dir.path().join("snapshots")).unwrap();
    common::snapshot_store_conformance(Arc::new(store)).await;
}
