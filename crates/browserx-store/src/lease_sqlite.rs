//! Durable lease registry on SQLite (WAL mode).

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserx_core::{
    Clock, Error, Generation, LeaseStore, Result, SessionId, SessionLease, SessionStatus,
    SystemClock,
};
use rusqlite::{Connection, ErrorCode, OptionalExtension, TransactionBehavior, params};
use time::OffsetDateTime;

use crate::common::{check_cas, micros, scrubbed_if_terminal};

/// Ordered schema migrations. Never edit an applied entry; append a new one.
const MIGRATIONS: &[(i64, &str)] = &[(
    1,
    "CREATE TABLE leases (
         id            TEXT PRIMARY KEY NOT NULL,
         owner         TEXT NOT NULL,
         status        TEXT NOT NULL,
         generation    INTEGER NOT NULL,
         created_at_us INTEGER NOT NULL,
         updated_at_us INTEGER NOT NULL,
         lease_json    TEXT NOT NULL
     ) WITHOUT ROWID;
     CREATE INDEX leases_owner ON leases (owner);
     CREATE INDEX leases_status_updated ON leases (status, updated_at_us);",
)];

fn latest_schema() -> i64 {
    MIGRATIONS.last().map_or(0, |m| m.0)
}

fn db_err(e: &rusqlite::Error) -> Error {
    Error::Storage(format!("sqlite: {e}"))
}

fn status_str(s: SessionStatus) -> &'static str {
    match s {
        SessionStatus::Queued => "queued",
        SessionStatus::Allocating => "allocating",
        SessionStatus::Active => "active",
        SessionStatus::Idle => "idle",
        SessionStatus::Recovering => "recovering",
        SessionStatus::Draining => "draining",
        SessionStatus::Lost => "lost",
        SessionStatus::Closed => "closed",
    }
}

fn generation_i64(g: Generation) -> Result<i64> {
    i64::try_from(g.0).map_err(|_| Error::InvalidRequest("generation exceeds i64 range".into()))
}

fn decode(id: &str, json: &str) -> Result<SessionLease> {
    serde_json::from_str(json)
        .map_err(|e| Error::Storage(format!("corrupt lease record {id}: {e}")))
}

/// A [`SessionLease`] registry persisted in a SQLite database.
///
/// Each lease is one row: the full record as JSON plus indexed columns (`id`,
/// `owner`, `status`, `generation`, `updated_at`). Calls run on the blocking
/// pool; the connection is serialized behind a mutex that is never held across
/// an `.await`. The journal runs in WAL mode with `synchronous=FULL`.
///
/// **Sensitive content:** a lease embeds its session spec, including any
/// upstream proxy password, because recovery must relaunch the forwarder. The
/// password is removed when a lease turns terminal (`lost`, `closed`), and
/// `secure_delete` makes SQLite overwrite freed content so the old value does
/// not linger in the file. The database file (and its WAL/shared-memory
/// siblings) are forced to mode `0600` on every open; keep the state directory
/// private.
#[derive(Clone)]
pub struct SqliteLeaseStore {
    conn: Arc<Mutex<Connection>>,
    clock: Arc<dyn Clock>,
}

impl SqliteLeaseStore {
    /// Opens (creating if needed) the database at `path`, enables WAL and applies
    /// pending migrations. Refuses a database written by a newer schema.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_clock(path, Arc::new(SystemClock))
    }

    /// Like [`Self::open`] with an injected clock for `updated_at` bookkeeping.
    pub fn open_with_clock(path: &Path, clock: Arc<dyn Clock>) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Storage(format!("create database directory: {e}")))?;
        }
        create_private_file(path)?;
        let mut conn = Connection::open(path).map_err(|e| db_err(&e))?;
        conn.pragma_update(None, "secure_delete", "ON")
            .map_err(|e| db_err(&e))?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|e| db_err(&e))?;
        let mode: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))
            .map_err(|e| db_err(&e))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(Error::Storage(format!(
                "could not enable WAL journaling (got {mode})"
            )));
        }
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| db_err(&e))?;
        migrate(&mut conn, micros(clock.now()))?;
        scrub_stored_terminal_leases(&mut conn)?;
        restrict_sidecar_files(path)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            clock,
        })
    }

    /// Verifies the database answers queries; for readiness probes.
    pub async fn ping(&self) -> Result<()> {
        self.run(|conn, _| {
            conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))
                .map_err(|e| db_err(&e))?;
            Ok(())
        })
        .await
    }

    async fn run<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection, i64) -> Result<T> + Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        let now = micros(self.clock.now());
        tokio::task::spawn_blocking(move || {
            let mut guard = conn
                .lock()
                .map_err(|_| Error::Internal("lease database lock poisoned".into()))?;
            f(&mut guard, now)
        })
        .await
        .map_err(|e| Error::Internal(format!("storage task failed: {e}")))?
    }
}

/// Creates the database file with mode `0600`, or narrows an existing one to
/// `0600` (the creation mode alone would leave a pre-existing wider file alone).
fn create_private_file(path: &Path) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts
        .open(path)
        .map_err(|e| Error::Storage(format!("create database file: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Storage(format!("restrict database file mode: {e}")))?;
    }
    drop(file);
    Ok(())
}

/// SQLite creates the `-wal` and `-shm` files with the main file's mode; narrow
/// any that already exist from an earlier, wider-moded run.
fn restrict_sidecar_files(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["-wal", "-shm"] {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            match std::fs::set_permissions(&name, std::fs::Permissions::from_mode(0o600)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(Error::Storage(format!(
                        "restrict database sidecar file mode: {e}"
                    )));
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Removes proxy passwords from terminal leases written by a build that kept
/// them (a lease turns terminal at most once, so this normally finds nothing).
fn scrub_stored_terminal_leases(conn: &mut Connection) -> Result<()> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| db_err(&e))?;
    let rows: Vec<(String, String)> = {
        let mut stmt = tx
            .prepare(
                "SELECT id, lease_json FROM leases
                  WHERE status IN ('lost', 'closed') AND lease_json LIKE '%\"password\":\"%'",
            )
            .map_err(|e| db_err(&e))?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| db_err(&e))?;
        mapped
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| db_err(&e))?
    };
    for (id, json) in rows {
        let lease = decode(&id, &json)?;
        if let Some(clean) = scrubbed_if_terminal(&lease) {
            let json = serde_json::to_string(&clean)
                .map_err(|e| Error::Internal(format!("encode lease: {e}")))?;
            tx.execute(
                "UPDATE leases SET lease_json = ?1 WHERE id = ?2",
                params![json, id],
            )
            .map_err(|e| db_err(&e))?;
        }
    }
    tx.commit().map_err(|e| db_err(&e))
}

fn migrate(conn: &mut Connection, now_us: i64) -> Result<()> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| db_err(&e))?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version       INTEGER PRIMARY KEY NOT NULL,
             applied_at_us INTEGER NOT NULL
         )",
    )
    .map_err(|e| db_err(&e))?;
    let current: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )
        .map_err(|e| db_err(&e))?;
    if current > latest_schema() {
        return Err(Error::Storage(format!(
            "database schema v{current} is newer than this build supports (v{}); upgrade BrowserX",
            latest_schema()
        )));
    }
    for (version, sql) in MIGRATIONS.iter().filter(|(v, _)| *v > current) {
        tx.execute_batch(sql).map_err(|e| db_err(&e))?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at_us) VALUES (?1, ?2)",
            params![version, now_us],
        )
        .map_err(|e| db_err(&e))?;
    }
    tx.commit().map_err(|e| db_err(&e))
}

#[async_trait]
impl LeaseStore for SqliteLeaseStore {
    async fn insert(&self, lease: &SessionLease) -> Result<()> {
        let id = lease.session_id.to_string();
        let owner = lease.owner.clone();
        let status = status_str(lease.status);
        let generation = generation_i64(lease.generation)?;
        let created = micros(lease.created_at);
        let scrubbed = scrubbed_if_terminal(lease);
        let json = serde_json::to_string(scrubbed.as_ref().unwrap_or(lease))
            .map_err(|e| Error::Internal(format!("encode lease: {e}")))?;
        self.run(move |conn, now| {
            conn.execute(
                "INSERT INTO leases (id, owner, status, generation, created_at_us, updated_at_us, lease_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![id, owner, status, generation, created, now, json],
            )
            .map(|_| ())
            .map_err(|e| match &e {
                rusqlite::Error::SqliteFailure(f, _) if f.code == ErrorCode::ConstraintViolation => {
                    Error::Conflict(format!("lease {id} already exists"))
                }
                _ => db_err(&e),
            })
        })
        .await
    }

    async fn get(&self, id: SessionId) -> Result<Option<SessionLease>> {
        let key = id.to_string();
        self.run(move |conn, _| {
            let json: Option<String> = conn
                .query_row("SELECT lease_json FROM leases WHERE id = ?1", [&key], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(|e| db_err(&e))?;
            json.map(|j| decode(&key, &j)).transpose()
        })
        .await
    }

    async fn compare_and_swap(&self, expected: Generation, lease: &SessionLease) -> Result<()> {
        if lease.generation != expected && lease.generation != expected.next() {
            return Err(Error::InvalidRequest(format!(
                "lease generation must stay {expected} or advance to {}, got {}",
                expected.next(),
                lease.generation
            )));
        }
        let id = lease.session_id.to_string();
        let owner = lease.owner.clone();
        let status = status_str(lease.status);
        let expected_i = generation_i64(expected)?;
        let new_i = generation_i64(lease.generation)?;
        let scrubbed = scrubbed_if_terminal(lease);
        let json = serde_json::to_string(scrubbed.as_ref().unwrap_or(lease))
            .map_err(|e| Error::Internal(format!("encode lease: {e}")))?;
        let candidate = lease.clone();
        self.run(move |conn, now| {
            let changed = conn
                .execute(
                    "UPDATE leases
                        SET owner = ?1, status = ?2, generation = ?3, updated_at_us = ?4, lease_json = ?5
                      WHERE id = ?6 AND generation = ?7",
                    params![owner, status, new_i, now, json, id, expected_i],
                )
                .map_err(|e| db_err(&e))?;
            if changed == 1 {
                return Ok(());
            }
            let stored: Option<i64> = conn
                .query_row("SELECT generation FROM leases WHERE id = ?1", [&id], |r| r.get(0))
                .optional()
                .map_err(|e| db_err(&e))?;
            match stored {
                None => Err(Error::NotFound(format!("lease {id}"))),
                Some(found) => {
                    let found = Generation(u64::try_from(found).unwrap_or(u64::MAX));
                    check_cas(found, expected, &candidate)?;
                    Err(Error::Internal("compare-and-swap affected no row".into()))
                }
            }
        })
        .await
    }

    async fn list(
        &self,
        owner: Option<&str>,
        statuses: Option<&[SessionStatus]>,
    ) -> Result<Vec<SessionLease>> {
        let owner = owner.map(str::to_owned);
        let statuses: Option<Vec<&'static str>> =
            statuses.map(|s| s.iter().copied().map(status_str).collect());
        self.run(move |conn, _| {
            let mut sql = String::from("SELECT id, lease_json FROM leases");
            let mut clauses = Vec::new();
            let mut args: Vec<String> = Vec::new();
            if let Some(o) = owner {
                args.push(o);
                clauses.push(format!("owner = ?{}", args.len()));
            }
            if let Some(list) = statuses {
                if list.is_empty() {
                    return Ok(Vec::new());
                }
                let marks: Vec<String> = list
                    .iter()
                    .map(|s| {
                        args.push((*s).to_owned());
                        format!("?{}", args.len())
                    })
                    .collect();
                clauses.push(format!("status IN ({})", marks.join(", ")));
            }
            if !clauses.is_empty() {
                sql.push_str(" WHERE ");
                sql.push_str(&clauses.join(" AND "));
            }
            sql.push_str(" ORDER BY created_at_us, id");
            let mut stmt = conn.prepare(&sql).map_err(|e| db_err(&e))?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(|e| db_err(&e))?;
            let mut out = Vec::new();
            for row in rows {
                let (id, json) = row.map_err(|e| db_err(&e))?;
                out.push(decode(&id, &json)?);
            }
            Ok(out)
        })
        .await
    }

    async fn purge_terminal(&self, older_than: OffsetDateTime) -> Result<u64> {
        let cutoff = micros(older_than);
        self.run(move |conn, _| {
            let n = conn
                .execute(
                    "DELETE FROM leases WHERE status IN ('lost', 'closed') AND updated_at_us < ?1",
                    [cutoff],
                )
                .map_err(|e| db_err(&e))?;
            Ok(u64::try_from(n).unwrap_or(u64::MAX))
        })
        .await
    }
}
