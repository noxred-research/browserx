//! Durable lease registry on MariaDB.

use std::path::PathBuf;
use std::sync::{Arc, Once};
use std::time::Duration;

use async_trait::async_trait;
use browserx_core::{
    Clock, Error, Generation, LeaseStore, Result, SessionId, SessionLease, SessionStatus,
};
use mysql_async::prelude::Queryable;
use mysql_async::{
    Conn, Opts, OptsBuilder, Params, Pool, PoolConstraints, PoolOpts, SslOpts, TxOpts, Value,
};
use time::OffsetDateTime;

use crate::common::micros;
use crate::relational::{
    DatabaseConfig, Engine, LeaseRow, MIGRATION_TIMEOUT, OPERATION_TIMEOUT, STATEMENT_TIMEOUT,
    Target, TlsPlan, cas_failure, chain, check_cas_request, check_not_newer, decode,
    generation_i64, lock_digest, scrub_json, status_str, within,
};

/// Ordered schema migrations: statements per version, `{schema}` is the quoted database. MariaDB
/// commits DDL implicitly, so a migration must be idempotent (`IF NOT EXISTS`) and a table must
/// be created with its indexes in one statement. Never edit an applied entry; append a new one.
const MIGRATIONS: &[(i64, &[&str])] = &[(
    1,
    &["CREATE TABLE IF NOT EXISTS {schema}.leases (
         id            VARCHAR(64) NOT NULL,
         node          VARCHAR(64) NOT NULL,
         owner         TEXT        NOT NULL,
         status        VARCHAR(16) NOT NULL,
         generation    BIGINT      NOT NULL,
         created_at_us BIGINT      NOT NULL,
         updated_at_us BIGINT      NOT NULL,
         lease_json    LONGTEXT    NOT NULL,
         PRIMARY KEY (node, id),
         KEY leases_node_owner (node, owner(191)),
         KEY leases_node_status_updated (node, status, updated_at_us)
     ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_nopad_bin"],
)];

/// Seconds a starter waits for the migration lock of its namespace.
const LOCK_WAIT_SECS: u64 = 60;
/// MariaDB error number of a duplicate key.
const ER_DUP_ENTRY: u16 = 1062;

fn latest_schema() -> i64 {
    MIGRATIONS.last().map_or(0, |m| m.0)
}

fn my_err(e: &mysql_async::Error) -> Error {
    Error::Storage(format!("mariadb: {}", chain(e)))
}

/// mysql_async builds its TLS config with the process default crypto provider, so one must be
/// installed; this crate uses `ring`.
fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Err means another component installed a provider first, which is just as good.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

struct Sql {
    schema: String,
    insert: String,
    get: String,
    cas: String,
    stored_generation: String,
    purge: String,
}

impl Sql {
    fn new(schema: &str) -> Self {
        let q = format!("`{schema}`");
        Self {
            schema: q.clone(),
            insert: format!(
                "INSERT INTO {q}.leases (id, node, owner, status, generation, created_at_us, updated_at_us, lease_json)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            ),
            get: format!("SELECT lease_json FROM {q}.leases WHERE id = ? AND node = ?"),
            cas: format!(
                "UPDATE {q}.leases
                    SET owner = ?, status = ?, generation = ?, updated_at_us = ?, lease_json = ?
                  WHERE id = ? AND node = ? AND generation = ?"
            ),
            stored_generation: format!(
                "SELECT generation FROM {q}.leases WHERE id = ? AND node = ?"
            ),
            purge: format!(
                "DELETE FROM {q}.leases
                  WHERE node = ? AND status IN ('lost', 'closed') AND updated_at_us < ?"
            ),
        }
    }
}

/// A [`SessionLease`] registry persisted in a MariaDB database.
///
/// One row per lease in `<database>.leases`, keyed by `(node, id)`; every statement filters by
/// the store's node, so workers that share a database (and other products that share the
/// server) never read or change each other's rows. The compare-and-swap is one `UPDATE ...
/// WHERE generation = ?` statement counted with `CLIENT_FOUND_ROWS`, so a swap that rewrites an
/// identical row still counts as a match. Connections come from a bounded pool and every
/// operation has a timeout.
///
/// **Sensitive content:** as with the SQLite store, a lease embeds its session spec including an
/// upstream proxy password until it turns terminal; protect the database like the state
/// directory (TLS, a dedicated account, no public access).
#[derive(Clone)]
pub struct MariaDbLeaseStore {
    pool: Pool,
    sql: Arc<Sql>,
    node: Arc<str>,
    clock: Arc<dyn Clock>,
}

impl MariaDbLeaseStore {
    /// Connects, creates the database if it is missing, applies pending migrations (guarded
    /// against concurrent starters) and scrubs terminal leases of this node.
    pub async fn connect(cfg: &DatabaseConfig, clock: Arc<dyn Clock>) -> Result<Self> {
        install_crypto_provider();
        let target = cfg.resolve(Engine::MariaDb)?;
        let tls = choose_tls(&target).await?;
        within(
            "database migration",
            MIGRATION_TIMEOUT,
            migrate(&target, tls, micros(clock.now())),
        )
        .await?;
        let pool = Pool::new(opts(&target, tls, true));
        let store = Self {
            pool,
            sql: Arc::new(Sql::new(&target.schema)),
            node: Arc::from(target.node.as_str()),
            clock,
        };
        store.ping().await?;
        Ok(store)
    }

    /// Verifies the database answers queries; for readiness probes.
    pub async fn ping(&self) -> Result<()> {
        within("database ping", OPERATION_TIMEOUT, async {
            let mut conn = self.conn().await?;
            conn.query_drop("SELECT 1").await.map_err(|e| my_err(&e))
        })
        .await
    }

    async fn conn(&self) -> Result<Conn> {
        self.pool.get_conn().await.map_err(|e| my_err(&e))
    }
}

/// Whether to use TLS. `Opportunistic` (loopback only) tries TLS and falls back to plain text.
async fn choose_tls(target: &Target) -> Result<bool> {
    match target.tls {
        TlsPlan::Plain => Ok(false),
        TlsPlan::Required => Ok(true),
        TlsPlan::Opportunistic => match open(target, true).await {
            Ok(conn) => {
                drop(conn);
                Ok(true)
            }
            Err(first) => match open(target, false).await {
                Ok(conn) => {
                    drop(conn);
                    Ok(false)
                }
                Err(_) => Err(first),
            },
        },
    }
}

/// Connection options. `with_database` selects the namespace; the bootstrap connection that
/// creates it cannot.
fn opts(target: &Target, tls: bool, with_database: bool) -> Opts {
    let session = vec![
        "SET SESSION sql_mode = 'STRICT_ALL_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'"
            .to_owned(),
        format!("SET SESSION max_statement_time = {}", STATEMENT_TIMEOUT.as_secs()),
    ];
    let mut builder = OptsBuilder::default()
        .ip_or_hostname(target.host.clone())
        .tcp_port(target.port)
        .user(target.user.clone())
        .pass(target.password.as_ref().map(|p| p.expose().to_owned()))
        .db_name(with_database.then(|| target.schema.clone()))
        .client_found_rows(true)
        .prefer_socket(false)
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .init(session)
        .stmt_cache_size(16)
        .pool_opts(
            PoolOpts::default()
                .with_constraints(PoolConstraints::new(0, target.pool_size).unwrap_or_default()),
        );
    if tls {
        let mut ssl = SslOpts::default();
        if let Some(path) = &target.tls_ca_file {
            ssl = ssl.with_root_certs(vec![PathBuf::from(path).into()]);
        }
        builder = builder.ssl_opts(ssl);
    }
    builder.into()
}

/// One connection, bounded by the connect timeout.
async fn open(target: &Target, tls: bool) -> Result<Conn> {
    open_with(target, tls, false).await
}

async fn open_with(target: &Target, tls: bool, with_database: bool) -> Result<Conn> {
    tokio::time::timeout(
        target.connect_timeout,
        Conn::new(opts(target, tls, with_database)),
    )
    .await
    .map_err(|_| Error::Timeout("connecting to the database".into()))?
    .map_err(|e| my_err(&e))
}

/// Creates the database if missing and applies pending migrations while holding a server-wide
/// named lock, so concurrent starters of one namespace run one at a time.
async fn migrate(target: &Target, tls: bool, now_us: i64) -> Result<()> {
    let mut conn = open_with(target, tls, false).await?;
    let digest = lock_digest(&target.schema);
    let lock = format!("bx_mig_{}", hex::encode(&digest[..12]));
    let got: Option<i64> = conn
        .exec_first("SELECT GET_LOCK(?, ?)", (lock.as_str(), LOCK_WAIT_SECS))
        .await
        .map_err(|e| my_err(&e))?
        .flatten();
    if got != Some(1) {
        return Err(Error::Timeout(
            "waiting for another starter to finish the database migration".into(),
        ));
    }
    let result = apply_migrations(&mut conn, target, now_us).await;
    // The lock also ends with the connection; release it explicitly so a failed run does not
    // keep other starters waiting while this connection lingers.
    let released = conn
        .exec_drop("SELECT RELEASE_LOCK(?)", (lock.as_str(),))
        .await;
    result?;
    released.map_err(|e| my_err(&e))?;
    scrub_terminal(target, tls).await
}

async fn apply_migrations(conn: &mut Conn, target: &Target, now_us: i64) -> Result<()> {
    let schema = target.schema.as_str();
    let q = format!("`{schema}`");
    let database_exists = conn
        .exec_first::<i64, _, _>(
            "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?",
            (schema,),
        )
        .await
        .map_err(|e| my_err(&e))?
        .is_some();
    if !database_exists {
        conn.query_drop(format!(
            "CREATE DATABASE IF NOT EXISTS {q} CHARACTER SET utf8mb4 COLLATE utf8mb4_nopad_bin"
        ))
        .await
        .map_err(|e| my_err(&e))?;
    }
    let table_exists = conn
        .exec_first::<i64, _, _>(
            "SELECT 1 FROM information_schema.TABLES
              WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'schema_migrations'",
            (schema,),
        )
        .await
        .map_err(|e| my_err(&e))?
        .is_some();
    let table = format!("{q}.schema_migrations");
    if !table_exists {
        conn.query_drop(format!(
            "CREATE TABLE IF NOT EXISTS {table} (
                 version       BIGINT NOT NULL PRIMARY KEY,
                 applied_at_us BIGINT NOT NULL
             ) ENGINE = InnoDB"
        ))
        .await
        .map_err(|e| my_err(&e))?;
    }
    let current: i64 = conn
        .query_first(format!("SELECT COALESCE(MAX(version), 0) FROM {table}"))
        .await
        .map_err(|e| my_err(&e))?
        .unwrap_or(0);
    check_not_newer(current, latest_schema())?;
    for (version, statements) in MIGRATIONS.iter().filter(|(v, _)| *v > current) {
        for statement in *statements {
            conn.query_drop(statement.replace("{schema}", &q))
                .await
                .map_err(|e| my_err(&e))?;
        }
        conn.exec_drop(
            format!("INSERT IGNORE INTO {table} (version, applied_at_us) VALUES (?, ?)"),
            (*version, now_us),
        )
        .await
        .map_err(|e| my_err(&e))?;
    }
    Ok(())
}

/// Removes proxy passwords from terminal leases of this node written by a build that kept them
/// (a lease turns terminal at most once, so this normally finds nothing).
async fn scrub_terminal(target: &Target, tls: bool) -> Result<()> {
    let q = format!("`{}`", target.schema);
    let mut conn = open_with(target, tls, true).await?;
    let mut tx = conn
        .start_transaction(TxOpts::default())
        .await
        .map_err(|e| my_err(&e))?;
    let rows: Vec<(String, String)> = tx
        .exec(
            format!(
                "SELECT id, lease_json FROM {q}.leases
                  WHERE node = ? AND status IN ('lost', 'closed')
                    AND lease_json LIKE '%\"password\":\"%' FOR UPDATE"
            ),
            (target.node.as_str(),),
        )
        .await
        .map_err(|e| my_err(&e))?;
    for (id, json) in rows {
        if let Some(clean) = scrub_json(&id, &json)? {
            tx.exec_drop(
                format!("UPDATE {q}.leases SET lease_json = ? WHERE id = ? AND node = ?"),
                (clean, id, target.node.as_str()),
            )
            .await
            .map_err(|e| my_err(&e))?;
        }
    }
    tx.commit().await.map_err(|e| my_err(&e))
}

fn text(s: &str) -> Value {
    Value::from(s)
}

#[async_trait]
impl LeaseStore for MariaDbLeaseStore {
    async fn insert(&self, lease: &SessionLease) -> Result<()> {
        let row = LeaseRow::of(lease)?;
        let now = micros(self.clock.now());
        within("lease insert", OPERATION_TIMEOUT, async {
            let mut conn = self.conn().await?;
            let params = Params::Positional(vec![
                text(&row.id),
                text(&self.node),
                text(&row.owner),
                text(row.status),
                Value::from(row.generation),
                Value::from(row.created_us),
                Value::from(now),
                text(&row.json),
            ]);
            match conn.exec_drop(self.sql.insert.as_str(), params).await {
                Ok(()) => Ok(()),
                Err(mysql_async::Error::Server(e)) if e.code == ER_DUP_ENTRY => {
                    Err(Error::Conflict(format!("lease {} already exists", row.id)))
                }
                Err(e) => Err(my_err(&e)),
            }
        })
        .await
    }

    async fn get(&self, id: SessionId) -> Result<Option<SessionLease>> {
        let key = id.to_string();
        within("lease get", OPERATION_TIMEOUT, async {
            let mut conn = self.conn().await?;
            let json: Option<String> = conn
                .exec_first(self.sql.get.as_str(), (key.as_str(), &*self.node))
                .await
                .map_err(|e| my_err(&e))?;
            json.map(|j| decode(&key, &j)).transpose()
        })
        .await
    }

    async fn compare_and_swap(&self, expected: Generation, lease: &SessionLease) -> Result<()> {
        check_cas_request(expected, lease)?;
        let row = LeaseRow::of(lease)?;
        let expected_i = generation_i64(expected)?;
        let now = micros(self.clock.now());
        within("lease compare-and-swap", OPERATION_TIMEOUT, async {
            let mut conn = self.conn().await?;
            let params = Params::Positional(vec![
                text(&row.owner),
                text(row.status),
                Value::from(row.generation),
                Value::from(now),
                text(&row.json),
                text(&row.id),
                text(&self.node),
                Value::from(expected_i),
            ]);
            conn.exec_drop(self.sql.cas.as_str(), params)
                .await
                .map_err(|e| my_err(&e))?;
            if conn.affected_rows() == 1 {
                return Ok(());
            }
            let stored: Option<i64> = conn
                .exec_first(
                    self.sql.stored_generation.as_str(),
                    (row.id.as_str(), &*self.node),
                )
                .await
                .map_err(|e| my_err(&e))?;
            Err(cas_failure(&row.id, stored, expected, lease))
        })
        .await
    }

    async fn list(
        &self,
        owner: Option<&str>,
        statuses: Option<&[SessionStatus]>,
    ) -> Result<Vec<SessionLease>> {
        let status_names: Option<Vec<&'static str>> =
            statuses.map(|s| s.iter().copied().map(status_str).collect());
        if status_names.as_ref().is_some_and(Vec::is_empty) {
            return Ok(Vec::new());
        }
        let mut sql = format!(
            "SELECT id, lease_json FROM {}.leases WHERE node = ?",
            self.sql.schema
        );
        let mut args = vec![text(&self.node)];
        if let Some(o) = owner {
            sql.push_str(" AND owner = ?");
            args.push(text(o));
        }
        if let Some(names) = &status_names {
            let marks = vec!["?"; names.len()].join(", ");
            sql.push_str(&format!(" AND status IN ({marks})"));
            args.extend(names.iter().map(|n| text(n)));
        }
        sql.push_str(" ORDER BY created_at_us, id");
        within("lease list", OPERATION_TIMEOUT, async {
            let mut conn = self.conn().await?;
            let rows: Vec<(String, String)> = conn
                .exec(sql.as_str(), Params::Positional(args))
                .await
                .map_err(|e| my_err(&e))?;
            rows.iter().map(|(id, json)| decode(id, json)).collect()
        })
        .await
    }

    async fn purge_terminal(&self, older_than: OffsetDateTime) -> Result<u64> {
        let cutoff = micros(older_than);
        within("lease purge", OPERATION_TIMEOUT, async {
            let mut conn = self.conn().await?;
            conn.exec_drop(self.sql.purge.as_str(), (&*self.node, cutoff))
                .await
                .map_err(|e| my_err(&e))?;
            Ok(conn.affected_rows())
        })
        .await
    }
}
