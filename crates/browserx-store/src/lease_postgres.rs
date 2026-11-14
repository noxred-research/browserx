//! Durable lease registry on PostgreSQL.

use std::sync::Arc;

use async_trait::async_trait;
use browserx_core::{
    Clock, Error, Generation, LeaseStore, Result, SessionId, SessionLease, SessionStatus,
};
use deadpool_postgres::{
    Manager, ManagerConfig, Object, Pool, PoolError, RecyclingMethod, Runtime,
};
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use time::OffsetDateTime;
use tokio_postgres::NoTls;
use tokio_postgres::config::{SslMode, TargetSessionAttrs};
use tokio_postgres::error::SqlState;
use tokio_postgres::types::ToSql;
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::common::micros;
use crate::relational::{
    DatabaseConfig, Engine, LeaseRow, MIGRATION_TIMEOUT, OPERATION_TIMEOUT, STATEMENT_TIMEOUT,
    Target, TlsPlan, cas_failure, chain, check_cas_request, check_not_newer, decode,
    generation_i64, lock_digest, scrub_json, status_str, within,
};

/// Ordered schema migrations; `{schema}` is the quoted namespace. Never edit an applied entry;
/// append a new one.
const MIGRATIONS: &[(i64, &str)] = &[(
    1,
    "CREATE TABLE {schema}.leases (
         id            TEXT   NOT NULL,
         node          TEXT   NOT NULL,
         owner         TEXT   NOT NULL,
         status        TEXT   NOT NULL,
         generation    BIGINT NOT NULL,
         created_at_us BIGINT NOT NULL,
         updated_at_us BIGINT NOT NULL,
         lease_json    TEXT   NOT NULL,
         PRIMARY KEY (node, id)
     );
     CREATE INDEX leases_node_owner ON {schema}.leases (node, owner);
     CREATE INDEX leases_node_status_updated ON {schema}.leases (node, status, updated_at_us);",
)];

fn latest_schema() -> i64 {
    MIGRATIONS.last().map_or(0, |m| m.0)
}

fn pg_err(e: &tokio_postgres::Error) -> Error {
    Error::Storage(format!("postgres: {}", chain(e)))
}

fn pool_err(e: &PoolError) -> Error {
    match e {
        PoolError::Timeout(_) => Error::Timeout("waiting for a database connection".into()),
        PoolError::Backend(inner) => pg_err(inner),
        other => Error::Storage(format!("postgres pool: {}", chain(other))),
    }
}

/// Statements with the namespace baked in (it is validated, then quoted).
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
        let q = format!("\"{schema}\"");
        Self {
            schema: q.clone(),
            insert: format!(
                "INSERT INTO {q}.leases (id, node, owner, status, generation, created_at_us, updated_at_us, lease_json)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
            ),
            get: format!("SELECT lease_json FROM {q}.leases WHERE id = $1 AND node = $2"),
            cas: format!(
                "UPDATE {q}.leases
                    SET owner = $1, status = $2, generation = $3, updated_at_us = $4, lease_json = $5
                  WHERE id = $6 AND node = $7 AND generation = $8"
            ),
            stored_generation: format!(
                "SELECT generation FROM {q}.leases WHERE id = $1 AND node = $2"
            ),
            purge: format!(
                "DELETE FROM {q}.leases
                  WHERE node = $1 AND status IN ('lost', 'closed') AND updated_at_us < $2"
            ),
        }
    }
}

/// A [`SessionLease`] registry persisted in a PostgreSQL schema.
///
/// One row per lease in `<schema>.leases`, keyed by `(node, id)`; every statement filters by the
/// store's node, so workers that share a schema (and other products that share the server)
/// never read or change each other's rows. The compare-and-swap is one `UPDATE ... WHERE
/// generation = $n` statement. Connections come from a bounded pool and every operation has a
/// timeout.
///
/// **Sensitive content:** as with the SQLite store, a lease embeds its session spec including an
/// upstream proxy password until it turns terminal; protect the database like the state
/// directory (TLS, a dedicated role, no public access).
#[derive(Clone)]
pub struct PostgresLeaseStore {
    pool: Pool,
    sql: Arc<Sql>,
    node: Arc<str>,
    clock: Arc<dyn Clock>,
}

impl PostgresLeaseStore {
    /// Connects, creates the schema if it is missing, applies pending migrations (guarded
    /// against concurrent starters) and scrubs terminal leases of this node.
    pub async fn connect(cfg: &DatabaseConfig, clock: Arc<dyn Clock>) -> Result<Self> {
        let target = cfg.resolve(Engine::Postgres)?;
        let pool = match target.tls {
            TlsPlan::Plain => build_pool(&target, false)?,
            TlsPlan::Required => build_pool(&target, true)?,
            TlsPlan::Opportunistic => {
                let tls = build_pool(&target, true)?;
                match probe(&tls).await {
                    Ok(()) => tls,
                    Err(first) => {
                        let plain = build_pool(&target, false)?;
                        probe(&plain).await.map_err(|_| first)?;
                        plain
                    }
                }
            }
        };
        let store = Self {
            pool,
            sql: Arc::new(Sql::new(&target.schema)),
            node: Arc::from(target.node.as_str()),
            clock,
        };
        within(
            "database migration",
            MIGRATION_TIMEOUT,
            store.migrate(&target.schema),
        )
        .await?;
        Ok(store)
    }

    /// Verifies the database answers queries; for readiness probes.
    pub async fn ping(&self) -> Result<()> {
        probe(&self.pool).await
    }

    async fn client(&self) -> Result<Object> {
        self.pool.get().await.map_err(|e| pool_err(&e))
    }

    async fn migrate(&self, schema: &str) -> Result<()> {
        let now = micros(self.clock.now());
        let key = {
            let d = lock_digest(schema);
            i64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
        };
        let mut client = self.client().await?;
        let tx = client.transaction().await.map_err(|e| pg_err(&e))?;
        tx.batch_execute(&format!(
            "SET LOCAL statement_timeout = '{}s'; SET LOCAL lock_timeout = '{}s'",
            MIGRATION_TIMEOUT.as_secs(),
            MIGRATION_TIMEOUT.as_secs()
        ))
        .await
        .map_err(|e| pg_err(&e))?;
        // Held until this transaction ends: one starter at a time per namespace.
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&key])
            .await
            .map_err(|e| pg_err(&e))?;

        let q = &self.sql.schema;
        // Probe before creating so a role without CREATE privilege can use an existing schema.
        let schema_exists = tx
            .query_opt("SELECT 1 FROM pg_namespace WHERE nspname = $1", &[&schema])
            .await
            .map_err(|e| pg_err(&e))?
            .is_some();
        if !schema_exists {
            tx.batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {q}"))
                .await
                .map_err(|e| pg_err(&e))?;
        }
        let table = format!("{q}.schema_migrations");
        let table_exists: bool = tx
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[&table])
            .await
            .map_err(|e| pg_err(&e))?
            .get(0);
        if !table_exists {
            tx.batch_execute(&format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                     version       BIGINT PRIMARY KEY,
                     applied_at_us BIGINT NOT NULL
                 )"
            ))
            .await
            .map_err(|e| pg_err(&e))?;
        }
        let current: i64 = tx
            .query_one(
                &format!("SELECT COALESCE(MAX(version), 0)::BIGINT FROM {table}"),
                &[],
            )
            .await
            .map_err(|e| pg_err(&e))?
            .get(0);
        check_not_newer(current, latest_schema())?;
        for (version, sql) in MIGRATIONS.iter().filter(|(v, _)| *v > current) {
            tx.batch_execute(&sql.replace("{schema}", q))
                .await
                .map_err(|e| pg_err(&e))?;
            tx.execute(
                &format!("INSERT INTO {table} (version, applied_at_us) VALUES ($1, $2)"),
                &[version, &now],
            )
            .await
            .map_err(|e| pg_err(&e))?;
        }
        self.scrub_terminal(&tx).await?;
        tx.commit().await.map_err(|e| pg_err(&e))
    }

    /// Removes proxy passwords from terminal leases of this node written by a build that kept
    /// them (a lease turns terminal at most once, so this normally finds nothing).
    async fn scrub_terminal(&self, tx: &deadpool_postgres::Transaction<'_>) -> Result<()> {
        let q = &self.sql.schema;
        let node: &str = &self.node;
        let rows = tx
            .query(
                &format!(
                    "SELECT id, lease_json FROM {q}.leases
                      WHERE node = $1 AND status IN ('lost', 'closed')
                        AND lease_json LIKE '%\"password\":\"%' FOR UPDATE"
                ),
                &[&node],
            )
            .await
            .map_err(|e| pg_err(&e))?;
        for row in rows {
            let id: String = row.get(0);
            let json: String = row.get(1);
            if let Some(clean) = scrub_json(&id, &json)? {
                tx.execute(
                    &format!("UPDATE {q}.leases SET lease_json = $1 WHERE id = $2 AND node = $3"),
                    &[&clean, &id, &node],
                )
                .await
                .map_err(|e| pg_err(&e))?;
            }
        }
        Ok(())
    }
}

async fn probe(pool: &Pool) -> Result<()> {
    within("database ping", OPERATION_TIMEOUT, async {
        let client = pool.get().await.map_err(|e| pool_err(&e))?;
        client
            .query_one("SELECT 1", &[])
            .await
            .map_err(|e| pg_err(&e))?;
        Ok(())
    })
    .await
}

fn build_pool(target: &Target, tls: bool) -> Result<Pool> {
    let mut cfg = tokio_postgres::Config::new();
    cfg.host(&target.host)
        .port(target.port)
        .connect_timeout(target.connect_timeout)
        .application_name("browserx")
        .target_session_attrs(TargetSessionAttrs::ReadWrite)
        .ssl_mode(if tls {
            SslMode::Require
        } else {
            SslMode::Disable
        })
        .options(format!(
            "-c statement_timeout={} -c idle_in_transaction_session_timeout={}",
            STATEMENT_TIMEOUT.as_millis(),
            OPERATION_TIMEOUT.as_millis() * 2
        ));
    if let Some(user) = &target.user {
        cfg.user(user);
    }
    if let Some(db) = &target.database {
        cfg.dbname(db);
    }
    if let Some(password) = &target.password {
        cfg.password(password.expose());
    }
    let manager_cfg = ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    };
    let manager = if tls {
        Manager::from_config(
            cfg,
            MakeRustlsConnect::new(tls_config(target)?),
            manager_cfg,
        )
    } else {
        Manager::from_config(cfg, NoTls, manager_cfg)
    };
    Pool::builder(manager)
        .max_size(target.pool_size)
        .wait_timeout(Some(target.connect_timeout))
        .create_timeout(Some(target.connect_timeout))
        .recycle_timeout(Some(target.connect_timeout))
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|e| Error::Storage(format!("postgres pool: {e}")))
}

/// Trust the built-in web roots plus the certificate authorities of `tls_ca_file`.
fn tls_config(target: &Target) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = &target.tls_ca_file {
        let pem = std::fs::read(path)
            .map_err(|e| Error::Storage(format!("read database.tls_ca_file: {e}")))?;
        let mut added = 0usize;
        for cert in CertificateDer::pem_slice_iter(&pem) {
            let cert =
                cert.map_err(|e| Error::Storage(format!("parse database.tls_ca_file: {e}")))?;
            roots
                .add(cert)
                .map_err(|e| Error::Storage(format!("database.tls_ca_file certificate: {e}")))?;
            added += 1;
        }
        if added == 0 {
            return Err(Error::Storage(
                "database.tls_ca_file holds no PEM certificate".into(),
            ));
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Storage(format!("tls versions: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

#[async_trait]
impl LeaseStore for PostgresLeaseStore {
    async fn insert(&self, lease: &SessionLease) -> Result<()> {
        let row = LeaseRow::of(lease)?;
        let now = micros(self.clock.now());
        let node: &str = &self.node;
        within("lease insert", OPERATION_TIMEOUT, async {
            let client = self.client().await?;
            let stmt = client
                .prepare_cached(&self.sql.insert)
                .await
                .map_err(|e| pg_err(&e))?;
            match client
                .execute(
                    &stmt,
                    &[
                        &row.id,
                        &node,
                        &row.owner,
                        &row.status,
                        &row.generation,
                        &row.created_us,
                        &now,
                        &row.json,
                    ],
                )
                .await
            {
                Ok(_) => Ok(()),
                Err(e) if e.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
                    Err(Error::Conflict(format!("lease {} already exists", row.id)))
                }
                Err(e) => Err(pg_err(&e)),
            }
        })
        .await
    }

    async fn get(&self, id: SessionId) -> Result<Option<SessionLease>> {
        let key = id.to_string();
        let node: &str = &self.node;
        within("lease get", OPERATION_TIMEOUT, async {
            let client = self.client().await?;
            let stmt = client
                .prepare_cached(&self.sql.get)
                .await
                .map_err(|e| pg_err(&e))?;
            let row = client
                .query_opt(&stmt, &[&key, &node])
                .await
                .map_err(|e| pg_err(&e))?;
            row.map(|r| decode(&key, &r.get::<_, String>(0)))
                .transpose()
        })
        .await
    }

    async fn compare_and_swap(&self, expected: Generation, lease: &SessionLease) -> Result<()> {
        check_cas_request(expected, lease)?;
        let row = LeaseRow::of(lease)?;
        let expected_i = generation_i64(expected)?;
        let now = micros(self.clock.now());
        let node: &str = &self.node;
        within("lease compare-and-swap", OPERATION_TIMEOUT, async {
            let client = self.client().await?;
            let stmt = client
                .prepare_cached(&self.sql.cas)
                .await
                .map_err(|e| pg_err(&e))?;
            let changed = client
                .execute(
                    &stmt,
                    &[
                        &row.owner,
                        &row.status,
                        &row.generation,
                        &now,
                        &row.json,
                        &row.id,
                        &node,
                        &expected_i,
                    ],
                )
                .await
                .map_err(|e| pg_err(&e))?;
            if changed == 1 {
                return Ok(());
            }
            let stmt = client
                .prepare_cached(&self.sql.stored_generation)
                .await
                .map_err(|e| pg_err(&e))?;
            let stored: Option<i64> = client
                .query_opt(&stmt, &[&row.id, &node])
                .await
                .map_err(|e| pg_err(&e))?
                .map(|r| r.get(0));
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
        let node: &str = &self.node;
        let mut sql = format!(
            "SELECT id, lease_json FROM {}.leases WHERE node = $1",
            self.sql.schema
        );
        let mut args: Vec<&(dyn ToSql + Sync)> = vec![&node];
        if let Some(o) = &owner {
            args.push(o);
            sql.push_str(&format!(" AND owner = ${}", args.len()));
        }
        if let Some(names) = &status_names {
            args.push(names);
            sql.push_str(&format!(" AND status = ANY(${}::text[])", args.len()));
        }
        sql.push_str(" ORDER BY created_at_us, id COLLATE \"C\"");
        within("lease list", OPERATION_TIMEOUT, async {
            let client = self.client().await?;
            let stmt = client.prepare_cached(&sql).await.map_err(|e| pg_err(&e))?;
            let rows = client.query(&stmt, &args).await.map_err(|e| pg_err(&e))?;
            rows.iter()
                .map(|r| decode(&r.get::<_, String>(0), &r.get::<_, String>(1)))
                .collect()
        })
        .await
    }

    async fn purge_terminal(&self, older_than: OffsetDateTime) -> Result<u64> {
        let cutoff = micros(older_than);
        let node: &str = &self.node;
        within("lease purge", OPERATION_TIMEOUT, async {
            let client = self.client().await?;
            let stmt = client
                .prepare_cached(&self.sql.purge)
                .await
                .map_err(|e| pg_err(&e))?;
            client
                .execute(&stmt, &[&node, &cutoff])
                .await
                .map_err(|e| pg_err(&e))
        })
        .await
    }
}
