//! SQLite-specific behavior: durability, migrations, file mode.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use browserx_core::clock::ManualClock;
use browserx_core::{Error, Generation, LeaseStore, SessionStatus};
use browserx_store::SqliteLeaseStore;

#[tokio::test]
async fn leases_survive_reopen_and_use_wal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("leases.db");
    let l = common::lease("alice", SessionStatus::Active, common::epoch());
    {
        let store = SqliteLeaseStore::open(&path).unwrap();
        store.ping().await.unwrap();
        store.insert(&l).await.unwrap();
        let mut next = l.clone();
        next.generation = Generation(2);
        store.compare_and_swap(Generation(1), &next).await.unwrap();
    }
    let reopened = SqliteLeaseStore::open(&path).unwrap();
    let got = reopened.get(l.session_id).await.unwrap().unwrap();
    assert_eq!(got.generation, Generation(2));

    let conn = rusqlite::Connection::open(&path).unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode.to_lowercase(), "wal");
    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(version, 1);
}

#[cfg(unix)]
#[test]
fn database_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    let _store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    drop(SqliteLeaseStore::open(&path).unwrap());
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "INSERT INTO schema_migrations (version, applied_at_us) VALUES (99, 0)",
        [],
    )
    .unwrap();
    drop(conn);
    match SqliteLeaseStore::open(&path) {
        Err(Error::Storage(m)) => assert!(m.contains("newer"), "{m}"),
        Err(other) => panic!("unexpected error {other:?}"),
        Ok(_) => panic!("opened a database from the future"),
    }
}

#[tokio::test]
async fn terminal_age_uses_write_time_not_creation_time() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(common::epoch()));
    let store = SqliteLeaseStore::open_with_clock(&dir.path().join("l.db"), clock.clone()).unwrap();
    let mut l = common::lease("alice", SessionStatus::Active, common::epoch());
    store.insert(&l).await.unwrap();
    clock.advance(time::Duration::hours(5));
    l.status = SessionStatus::Draining;
    store.compare_and_swap(Generation(1), &l).await.unwrap();
    l.status = SessionStatus::Closed;
    store.compare_and_swap(Generation(1), &l).await.unwrap();
    // created five hours ago, but became terminal just now
    let cutoff = common::epoch() + time::Duration::hours(1);
    assert_eq!(store.purge_terminal(cutoff).await.unwrap(), 0);
}

const PASSWORD: &str = "synthetic-disk-password-4f1c";

fn proxied_lease(status: SessionStatus) -> browserx_core::SessionLease {
    let mut l = common::lease("alice", status, common::epoch());
    l.spec.proxy = Some(browserx_core::ProxyRoute {
        url: "http://proxy.invalid:3128".into(),
        username: Some("user".into()),
        password: Some(browserx_core::Secret::new(PASSWORD)),
    });
    l
}

fn file_contains(path: &std::path::Path, needle: &str) -> bool {
    std::fs::read(path).is_ok_and(|bytes| {
        bytes
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    })
}

fn any_file_contains(db: &std::path::Path, needle: &str) -> bool {
    ["", "-wal", "-shm"].iter().any(|suffix| {
        let mut name = db.as_os_str().to_owned();
        name.push(suffix);
        file_contains(std::path::Path::new(&name), needle)
    })
}

#[tokio::test]
async fn terminal_lease_password_is_gone_from_the_database_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    {
        let store = SqliteLeaseStore::open(&path).unwrap();
        let mut l = proxied_lease(SessionStatus::Draining);
        // a large record that shrinks on the transition leaves freed space
        // behind the live row; only `secure_delete` wipes it
        l.reason = Some("padding ".repeat(400));
        store.insert(&l).await.unwrap();
        assert!(
            any_file_contains(&path, PASSWORD),
            "a recoverable lease stores its password"
        );
        l.status = SessionStatus::Closed;
        l.reason = None;
        store.compare_and_swap(Generation(1), &l).await.unwrap();
        let got = store.get(l.session_id).await.unwrap().unwrap();
        assert_eq!(got.spec.proxy.unwrap().password, None);
    }
    // dropping the last connection checkpoints and removes the WAL
    assert!(
        !any_file_contains(&path, PASSWORD),
        "the password survived the terminal transition on disk"
    );
}

#[test]
fn legacy_terminal_rows_are_scrubbed_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    let l = proxied_lease(SessionStatus::Closed);
    drop(SqliteLeaseStore::open(&path).unwrap());
    {
        // as an older build wrote it: terminal, password intact
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO leases (id, owner, status, generation, created_at_us, updated_at_us, lease_json)
             VALUES (?1, 'alice', 'closed', 1, 0, 0, ?2)",
            rusqlite::params![l.session_id.to_string(), serde_json::to_string(&l).unwrap()],
        )
        .unwrap();
    }
    assert!(any_file_contains(&path, PASSWORD));
    drop(SqliteLeaseStore::open(&path).unwrap());
    assert!(!any_file_contains(&path, PASSWORD));
}

#[cfg(unix)]
#[test]
fn existing_wide_database_is_narrowed_to_private_on_open() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    drop(SqliteLeaseStore::open(&path).unwrap());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
