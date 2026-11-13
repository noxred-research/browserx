//! PostgreSQL lease store against a real server in a throwaway container.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use browserx_core::clock::ManualClock;
use browserx_core::{Clock, Error, Generation, LeaseStore, Secret, SessionStatus};
use browserx_store::{DatabaseConfig, PostgresLeaseStore, TlsMode};
use common::services::{self, Service, Spec};

const IMAGE: &str = "docker.io/library/postgres:18";

/// A running server plus a private password file for it.
struct Pg {
    service: Service,
    port: u16,
    password: String,
    dir: tempfile::TempDir,
    password_file: PathBuf,
}

fn random_password() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

async fn admin_client(port: u16, password: &str) -> Option<tokio_postgres::Client> {
    let mut cfg = tokio_postgres::Config::new();
    cfg.host("127.0.0.1")
        .port(port)
        .user("postgres")
        .password(password)
        .dbname("postgres")
        .connect_timeout(Duration::from_secs(2));
    let (client, connection) = cfg.connect(tokio_postgres::NoTls).await.ok()?;
    tokio::spawn(connection);
    client.simple_query("SELECT 1").await.ok()?;
    Some(client)
}

impl Pg {
    /// Starts the server; with `tls` it serves a certificate issued by a throwaway CA.
    async fn start(tls: bool) -> Option<Self> {
        if !services::enabled("postgres lease store tests") {
            return None;
        }
        let password = random_password();
        let env = format!("POSTGRES_PASSWORD={password}");
        let envs = [env.as_str()];
        let tls_script = "set -e; mkdir -p /tmp/tls; cd /tmp/tls; \
            openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 \
              -subj /CN=bx-test-ca -addext basicConstraints=critical,CA:TRUE \
              -addext keyUsage=critical,keyCertSign 2>/dev/null; \
            openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj /CN=localhost 2>/dev/null; \
            printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\\nbasicConstraints=CA:FALSE\\nextendedKeyUsage=serverAuth\\n' > ext.cnf; \
            openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 2 -extfile ext.cnf 2>/dev/null; \
            chown postgres:postgres server.key server.pem; chmod 600 server.key; \
            exec docker-entrypoint.sh postgres -c ssl=on \
              -c ssl_cert_file=/tmp/tls/server.pem -c ssl_key_file=/tmp/tls/server.key";
        let tls_command = ["sh", "-c", tls_script];
        let spec = Spec {
            image: IMAGE,
            ports: &[5432],
            env: &envs,
            tmpfs: &["/var/lib/postgresql"],
            command: if tls { &tls_command } else { &[] },
            ready_within: Duration::from_secs(90),
        };
        let pw = password.clone();
        let service = Service::start(&spec, |ports| {
            let pw = pw.clone();
            async move { admin_client(ports[0], &pw).await.is_some() }
        })
        .await?;
        let dir = tempfile::tempdir().unwrap();
        let password_file = write_secret(dir.path(), "password", &password);
        Some(Self {
            port: service.ports[0],
            service,
            password,
            dir,
            password_file,
        })
    }

    fn config(&self, node: &str, schema: &str, tls: TlsMode) -> DatabaseConfig {
        DatabaseConfig {
            node: Some(node.to_owned()),
            schema: Some(schema.to_owned()),
            user: Some("postgres".into()),
            password_file: Some(self.password_file.clone()),
            tls,
            ..DatabaseConfig::new(format!("postgres://127.0.0.1:{}/postgres", self.port))
        }
    }

    async fn admin(&self) -> tokio_postgres::Client {
        admin_client(self.port, &self.password).await.unwrap()
    }

    fn ca_file(&self) -> PathBuf {
        let pem = self.service.exec(&["cat", "/tmp/tls/ca.pem"]).unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        write_secret(self.dir.path(), "ca.pem", &pem)
    }
}

fn write_secret(dir: &Path, name: &str, content: &str) -> PathBuf {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(content.as_bytes()).unwrap();
    path
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(common::epoch()))
}

async fn connect(cfg: &DatabaseConfig, clock: &Arc<ManualClock>) -> PostgresLeaseStore {
    PostgresLeaseStore::connect(cfg, clock.clone())
        .await
        .unwrap()
}

fn storage_message(r: browserx_core::Result<PostgresLeaseStore>) -> String {
    match r {
        Err(Error::Storage(m) | Error::Timeout(m) | Error::InvalidRequest(m)) => m,
        Err(other) => other.to_string(),
        Ok(_) => panic!("connect unexpectedly succeeded"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance_and_durability_across_reconnect() {
    let Some(pg) = Pg::start(false).await else {
        return;
    };
    let cfg = pg.config("node-a", "browserx", TlsMode::Prefer);
    let clock = clock();
    let store = Arc::new(connect(&cfg, &clock).await);
    store.ping().await.unwrap();
    common::lease_store_conformance(store.clone(), clock.clone()).await;

    let before = store.list(None, None).await.unwrap();
    assert!(!before.is_empty());
    drop(store);

    let again = connect(&cfg, &clock).await;
    let after = again.list(None, None).await.unwrap();
    assert_eq!(
        before, after,
        "the same node sees its leases after a reconnect"
    );

    // a second connect to an already migrated schema changes nothing
    let admin = pg.admin().await;
    let rows = admin
        .query("SELECT version FROM browserx.schema_migrations", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixteen_writers_race_one_generation_and_sixteen_starters_migrate_once() {
    let Some(pg) = Pg::start(false).await else {
        return;
    };
    let clock = clock();
    let mut cfg = pg.config("node-a", "race_ns", TlsMode::Prefer);
    cfg.pool_size = 16;

    // concurrent starters on a fresh schema: all succeed, the migration runs once
    let mut starters = Vec::new();
    for _ in 0..16 {
        let cfg = cfg.clone();
        let clock = clock.clone();
        starters.push(tokio::spawn(async move {
            PostgresLeaseStore::connect(&cfg, clock).await
        }));
    }
    let mut stores = Vec::new();
    for s in starters {
        stores.push(s.await.unwrap().unwrap());
    }
    let admin = pg.admin().await;
    let applied = admin
        .query("SELECT version FROM race_ns.schema_migrations", &[])
        .await
        .unwrap();
    assert_eq!(applied.len(), 1);

    let store = Arc::new(stores.pop().unwrap());
    let lease = common::lease("racer", SessionStatus::Idle, clock.now());
    store.insert(&lease).await.unwrap();
    let mut tasks = Vec::new();
    for i in 0..16u32 {
        let store = store.clone();
        let mut next = lease.clone();
        next.generation = Generation(2);
        next.recoveries = i;
        tasks.push(tokio::spawn(async move {
            store.compare_and_swap(Generation(1), &next).await
        }));
    }
    let mut wins = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(()) => wins += 1,
            Err(Error::StaleGeneration { expected, found }) => {
                assert_eq!(expected, Generation(1));
                assert_eq!(found, Generation(2));
            }
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }
    assert_eq!(wins, 1);
    assert_eq!(
        store
            .get(lease.session_id)
            .await
            .unwrap()
            .unwrap()
            .generation,
        Generation(2)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_instance_namespaces_and_nodes_do_not_see_each_other() {
    let Some(pg) = Pg::start(false).await else {
        return;
    };
    let admin = pg.admin().await;
    // another product's tables, with the very names this store uses
    admin
        .batch_execute(
            "CREATE SCHEMA other_product;
             CREATE TABLE other_product.leases (id integer PRIMARY KEY, note text, status text, updated_at_us bigint);
             INSERT INTO other_product.leases VALUES (1, 'foreign', 'closed', 0);
             CREATE TABLE other_product.schema_migrations (version bigint PRIMARY KEY);
             INSERT INTO other_product.schema_migrations VALUES (99);",
        )
        .await
        .unwrap();

    let clock = clock();
    let a = connect(&pg.config("node-a", "ns_one", TlsMode::Prefer), &clock).await;
    let a2 = connect(&pg.config("node-b", "ns_one", TlsMode::Prefer), &clock).await;
    let b = connect(&pg.config("node-a", "ns_two", TlsMode::Prefer), &clock).await;

    let t0 = clock.now();
    let mut closed_a = common::lease("alice", SessionStatus::Closed, t0);
    closed_a.spec.proxy = None;
    a.insert(&closed_a).await.unwrap();
    let live_a = common::lease("alice", SessionStatus::Idle, t0);
    a.insert(&live_a).await.unwrap();

    // the same id may exist on another node and in another namespace: they are separate rows
    a2.insert(&closed_a).await.unwrap();
    b.insert(&closed_a).await.unwrap();

    // nothing leaks across nodes or namespaces
    let only_b = common::lease("bob", SessionStatus::Closed, t0);
    a2.insert(&only_b).await.unwrap();
    assert!(a.get(only_b.session_id).await.unwrap().is_none());
    assert!(b.get(only_b.session_id).await.unwrap().is_none());
    assert_eq!(a.list(None, None).await.unwrap().len(), 2);
    assert_eq!(a2.list(None, None).await.unwrap().len(), 2);
    assert_eq!(b.list(None, None).await.unwrap().len(), 1);
    let mut ghost = only_b.clone();
    ghost.generation = Generation(2);
    assert!(matches!(
        a.compare_and_swap(Generation(1), &ghost).await,
        Err(Error::NotFound(_))
    ));

    // purge touches only this node's terminal rows
    clock.advance(time::Duration::hours(3));
    let cutoff = clock.now();
    assert_eq!(a.purge_terminal(cutoff).await.unwrap(), 1);
    assert_eq!(a.list(None, None).await.unwrap().len(), 1);
    assert_eq!(
        a2.list(None, None).await.unwrap().len(),
        2,
        "another node's rows survive"
    );
    assert_eq!(
        b.list(None, None).await.unwrap().len(),
        1,
        "another namespace survives"
    );

    // migration tables are separate, and the other product's objects were never touched
    for schema in ["ns_one", "ns_two"] {
        let rows = admin
            .query(
                &format!("SELECT version FROM {schema}.schema_migrations"),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "{schema}");
    }
    let foreign = admin
        .query("SELECT id, note FROM other_product.leases", &[])
        .await
        .unwrap();
    assert_eq!(foreign.len(), 1);
    assert_eq!(foreign[0].get::<_, String>(1), "foreign");
    let versions = admin
        .query("SELECT version FROM other_product.schema_migrations", &[])
        .await
        .unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].get::<_, i64>(0), 99);

    // even connecting to the foreign schema's name never mutates a table it does not own: the
    // store refuses the foreign migration history instead of purging or rewriting it
    let msg = storage_message(
        PostgresLeaseStore::connect(
            &pg.config("node-a", "other_product", TlsMode::Prefer),
            clock.clone(),
        )
        .await,
    );
    assert!(msg.contains("newer"), "{msg}");
    let foreign = admin
        .query("SELECT note FROM other_product.leases", &[])
        .await
        .unwrap();
    assert_eq!(foreign.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn newer_schema_is_refused_and_terminal_rows_are_scrubbed_on_open() {
    let Some(pg) = Pg::start(false).await else {
        return;
    };
    let clock = clock();
    let cfg = pg.config("node-a", "scrub_ns", TlsMode::Prefer);
    let store = connect(&cfg, &clock).await;
    drop(store);
    let admin = pg.admin().await;

    // legacy terminal rows that kept the proxy password: this node's is scrubbed, another
    // node's is left alone
    let t0 = clock.now();
    let mut mine = common::lease("scrub", SessionStatus::Closed, t0);
    mine.spec.proxy = Some(browserx_core::ProxyRoute {
        url: "http://proxy.invalid:3128".into(),
        username: Some("user".into()),
        password: Some(Secret::new("synthetic-legacy-password")),
    });
    let json = serde_json::to_string(&mine).unwrap();
    assert!(json.contains("synthetic-legacy-password"));
    for node in ["node-a", "node-other"] {
        admin
            .execute(
                "INSERT INTO scrub_ns.leases
                   (id, node, owner, status, generation, created_at_us, updated_at_us, lease_json)
                 VALUES ($1, $2, 'scrub', 'closed', 1, 0, 0, $3)",
                &[&mine.session_id.to_string(), &node, &json],
            )
            .await
            .unwrap();
    }
    drop(connect(&cfg, &clock).await);
    let stored = |node: &'static str| {
        let admin = &admin;
        let id = mine.session_id.to_string();
        async move {
            admin
                .query_one(
                    "SELECT lease_json FROM scrub_ns.leases WHERE id = $1 AND node = $2",
                    &[&id, &node],
                )
                .await
                .unwrap()
                .get::<_, String>(0)
        }
    };
    assert!(!stored("node-a").await.contains("synthetic-legacy-password"));
    assert!(
        stored("node-other")
            .await
            .contains("synthetic-legacy-password")
    );

    // a database written by a newer build is refused
    admin
        .execute(
            "INSERT INTO scrub_ns.schema_migrations VALUES (999, 0)",
            &[],
        )
        .await
        .unwrap();
    let msg = storage_message(PostgresLeaseStore::connect(&cfg, clock.clone()).await);
    assert!(msg.contains("newer than this build"), "{msg}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_modes_against_a_plain_server_and_wrong_password() {
    let Some(pg) = Pg::start(false).await else {
        return;
    };
    let clock = clock();
    // prefer to loopback falls back to plain text; disable is explicit plain text
    drop(connect(&pg.config("n", "modes", TlsMode::Prefer), &clock).await);
    drop(connect(&pg.config("n", "modes", TlsMode::Disable), &clock).await);
    // require fails when the server has no TLS
    let msg = storage_message(
        PostgresLeaseStore::connect(&pg.config("n", "modes", TlsMode::Require), clock.clone())
            .await,
    );
    assert!(!msg.is_empty());

    // a wrong password is refused, and the error never carries a password
    let wrong = write_secret(pg.dir.path(), "wrong", "not-the-password-0123456789");
    let mut cfg = pg.config("n", "modes", TlsMode::Disable);
    cfg.password_file = Some(wrong);
    let msg = storage_message(PostgresLeaseStore::connect(&cfg, clock.clone()).await);
    assert!(!msg.contains("not-the-password"));
    assert!(!msg.contains(&pg.password));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_with_a_private_certificate_authority() {
    let Some(pg) = Pg::start(true).await else {
        return;
    };
    let clock = clock();
    let ca = pg.ca_file();

    let mut cfg = pg.config("n", "tls_ns", TlsMode::Require);
    cfg.tls_ca_file = Some(ca.clone());
    let store = connect(&cfg, &clock).await;
    store.ping().await.unwrap();
    let admin = pg.admin().await;
    let rows = admin
        .query(
            "SELECT ssl FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid)
              WHERE a.application_name = 'browserx'",
            &[],
        )
        .await
        .unwrap();
    assert!(!rows.is_empty());
    assert!(
        rows.iter().all(|r| r.get::<_, bool>(0)),
        "connections use TLS"
    );
    common::lease_store_conformance(Arc::new(store), clock.clone()).await;

    // the private CA is not in the built-in roots: require without it fails the handshake
    let cfg = pg.config("n", "tls_ns", TlsMode::Require);
    let msg = storage_message(PostgresLeaseStore::connect(&cfg, clock.clone()).await);
    assert!(!msg.is_empty());

    // prefer on loopback works with the CA, too
    let mut cfg = pg.config("n", "tls_ns", TlsMode::Prefer);
    cfg.tls_ca_file = Some(ca);
    connect(&cfg, &clock).await.ping().await.unwrap();
}

// ---- configuration, no server needed ----

#[test]
fn config_errors_are_clear() {
    let base = DatabaseConfig::new("postgres://db.example.test/app");
    let err = |cfg: &DatabaseConfig| cfg.validate().unwrap_err().to_string();

    assert!(err(&base).contains("database.node is required"));

    let with_node = DatabaseConfig {
        node: Some("worker-1".into()),
        ..base.clone()
    };
    with_node.validate().unwrap();

    let with_password = DatabaseConfig {
        url: "postgres://app:hunter2@db.example.test/app".into(),
        ..with_node.clone()
    };
    let text = err(&with_password);
    assert!(text.contains("must not carry a password"));
    assert!(!text.contains("hunter2"));

    let bad_schema = DatabaseConfig {
        schema: Some("Bad-Schema".into()),
        ..with_node.clone()
    };
    assert!(err(&bad_schema).contains("database.schema"));

    let sqlite_node = DatabaseConfig {
        node: Some("worker-1".into()),
        ..DatabaseConfig::new("sqlite:///tmp/browserx.db")
    };
    assert!(err(&sqlite_node).contains("database.node"));
}

#[tokio::test]
async fn connecting_with_an_invalid_config_fails_before_any_network_use() {
    let cfg = DatabaseConfig::new("postgres://203.0.113.1/app");
    let r = PostgresLeaseStore::connect(&cfg, clock()).await;
    assert!(matches!(r, Err(Error::InvalidRequest(_))));
    let sqlite = DatabaseConfig::new("sqlite:///tmp/x.db");
    assert!(matches!(
        PostgresLeaseStore::connect(&sqlite, clock()).await,
        Err(Error::InvalidRequest(_))
    ));
}
