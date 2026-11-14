//! MariaDB lease store against a real server in a throwaway container.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use browserx_core::clock::ManualClock;
use browserx_core::{Clock, Error, Generation, LeaseStore, Secret, SessionStatus};
use browserx_store::{DatabaseConfig, MariaDbLeaseStore, TlsMode};
use common::services::{self, Service, Spec};
use mysql_async::prelude::Queryable;

const IMAGE: &str = "docker.io/library/mariadb:11.8@sha256:d36f18d65a0459510b8b0f643b226a6d299e3206486e2b64ff20754a6d291707";

/// A running server plus a private password file for it.
struct Maria {
    service: Service,
    port: u16,
    password: String,
    dir: tempfile::TempDir,
    password_file: PathBuf,
}

fn random_password() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

async fn admin_conn(port: u16, password: &str) -> Option<mysql_async::Conn> {
    let opts = mysql_async::OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(port)
        .user(Some("root"))
        .pass(Some(password))
        .prefer_socket(false);
    let mut conn = tokio::time::timeout(Duration::from_secs(3), mysql_async::Conn::new(opts))
        .await
        .ok()?
        .ok()?;
    conn.query_drop("SELECT 1").await.ok()?;
    Some(conn)
}

impl Maria {
    /// Starts the server; with `tls` it serves a certificate issued by a throwaway CA.
    async fn start(tls: bool) -> Option<Self> {
        if !services::enabled("mariadb lease store tests") {
            return None;
        }
        let password = random_password();
        let env = format!("MARIADB_ROOT_PASSWORD={password}");
        let envs = [env.as_str()];
        let tls_script = "set -e; mkdir -p /tmp/tls; cd /tmp/tls; \
            openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 \
              -subj /CN=bx-test-ca -addext basicConstraints=critical,CA:TRUE \
              -addext keyUsage=critical,keyCertSign 2>/dev/null; \
            openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj /CN=localhost 2>/dev/null; \
            printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\\nbasicConstraints=CA:FALSE\\nextendedKeyUsage=serverAuth\\n' > ext.cnf; \
            openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 2 -extfile ext.cnf 2>/dev/null; \
            chown mysql:mysql server.key server.pem ca.pem; chmod 600 server.key; \
            exec docker-entrypoint.sh mariadbd --ssl-ca=/tmp/tls/ca.pem \
              --ssl-cert=/tmp/tls/server.pem --ssl-key=/tmp/tls/server.key";
        let tls_command = ["sh", "-c", tls_script];
        let spec = Spec {
            image: IMAGE,
            ports: &[3306],
            env: &envs,
            tmpfs: &["/var/lib/mysql"],
            command: if tls { &tls_command } else { &[] },
            ready_within: Duration::from_secs(120),
        };
        let pw = password.clone();
        let service = Service::start(&spec, |ports| {
            let pw = pw.clone();
            async move { admin_conn(ports[0], &pw).await.is_some() }
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
            user: Some("root".into()),
            password_file: Some(self.password_file.clone()),
            tls,
            ..DatabaseConfig::new(format!("mariadb://127.0.0.1:{}", self.port))
        }
    }

    async fn admin(&self) -> mysql_async::Conn {
        admin_conn(self.port, &self.password).await.unwrap()
    }

    fn ca_file(&self) -> PathBuf {
        let pem = self.service.exec(&["cat", "/tmp/tls/ca.pem"]).unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        write_secret(self.dir.path(), "ca.pem", &pem)
    }
}

fn write_secret(dir: &Path, name: &str, content: &str) -> PathBuf {
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

async fn connect(cfg: &DatabaseConfig, clock: &Arc<ManualClock>) -> MariaDbLeaseStore {
    MariaDbLeaseStore::connect(cfg, clock.clone())
        .await
        .unwrap()
}

fn failure(r: browserx_core::Result<MariaDbLeaseStore>) -> String {
    match r {
        Err(Error::Storage(m) | Error::Timeout(m) | Error::InvalidRequest(m)) => m,
        Err(other) => other.to_string(),
        Ok(_) => panic!("connect unexpectedly succeeded"),
    }
}

async fn stored(admin: &mut mysql_async::Conn, id: &str, node: &str) -> String {
    admin
        .exec_first::<String, _, _>(
            "SELECT lease_json FROM scrub_ns.leases WHERE id = ? AND node = ?",
            (id, node),
        )
        .await
        .unwrap()
        .unwrap()
}

async fn count(admin: &mut mysql_async::Conn, sql: &str) -> i64 {
    admin.query_first::<i64, _>(sql).await.unwrap().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance_and_durability_across_reconnect() {
    let Some(db) = Maria::start(false).await else {
        return;
    };
    let cfg = db.config("node-a", "browserx", TlsMode::Prefer);
    let clock = clock();
    let store = Arc::new(connect(&cfg, &clock).await);
    store.ping().await.unwrap();
    common::lease_store_conformance(store.clone(), clock.clone()).await;

    // rewriting a row with identical content still counts as a match
    let lease = common::lease("same", SessionStatus::Idle, clock.now());
    store.insert(&lease).await.unwrap();
    store.compare_and_swap(Generation(1), &lease).await.unwrap();
    store.compare_and_swap(Generation(1), &lease).await.unwrap();

    let before = store.list(None, None).await.unwrap();
    assert!(!before.is_empty());
    drop(store);

    let again = connect(&cfg, &clock).await;
    let after = again.list(None, None).await.unwrap();
    assert_eq!(
        before, after,
        "the same node sees its leases after a reconnect"
    );

    let mut admin = db.admin().await;
    assert_eq!(
        count(
            &mut admin,
            "SELECT COUNT(*) FROM browserx.schema_migrations"
        )
        .await,
        1
    );
    // ids and owners compare exactly: no case or trailing-space folding
    let upper = common::lease("Alice", SessionStatus::Idle, clock.now());
    again.insert(&upper).await.unwrap();
    assert!(
        again
            .list(Some("alice "), None)
            .await
            .unwrap()
            .iter()
            .all(|l| l.owner != "Alice")
    );
    assert_eq!(
        again
            .list(Some("Alice"), None)
            .await
            .unwrap()
            .iter()
            .filter(|l| l.session_id == upper.session_id)
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixteen_writers_race_one_generation_and_sixteen_starters_migrate_once() {
    let Some(db) = Maria::start(false).await else {
        return;
    };
    let clock = clock();
    let mut cfg = db.config("node-a", "race_ns", TlsMode::Prefer);
    cfg.pool_size = 16;

    let mut starters = Vec::new();
    for _ in 0..16 {
        let cfg = cfg.clone();
        let clock = clock.clone();
        starters.push(tokio::spawn(async move {
            MariaDbLeaseStore::connect(&cfg, clock).await
        }));
    }
    let mut stores = Vec::new();
    for s in starters {
        stores.push(s.await.unwrap().unwrap());
    }
    let mut admin = db.admin().await;
    assert_eq!(
        count(&mut admin, "SELECT COUNT(*) FROM race_ns.schema_migrations").await,
        1
    );

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
async fn shared_instance_databases_and_nodes_do_not_see_each_other() {
    let Some(db) = Maria::start(false).await else {
        return;
    };
    let mut admin = db.admin().await;
    // another product's tables, with the very names this store uses
    for statement in [
        "CREATE DATABASE other_product",
        "CREATE TABLE other_product.leases (id INT PRIMARY KEY, note TEXT, status TEXT, updated_at_us BIGINT)",
        "INSERT INTO other_product.leases VALUES (1, 'foreign', 'closed', 0)",
        "CREATE TABLE other_product.schema_migrations (version BIGINT PRIMARY KEY)",
        "INSERT INTO other_product.schema_migrations VALUES (99)",
    ] {
        admin.query_drop(statement).await.unwrap();
    }

    let clock = clock();
    let a = connect(&db.config("node-a", "ns_one", TlsMode::Prefer), &clock).await;
    let a2 = connect(&db.config("node-b", "ns_one", TlsMode::Prefer), &clock).await;
    let b = connect(&db.config("node-a", "ns_two", TlsMode::Prefer), &clock).await;

    let t0 = clock.now();
    let closed_a = common::lease("alice", SessionStatus::Closed, t0);
    a.insert(&closed_a).await.unwrap();
    let live_a = common::lease("alice", SessionStatus::Idle, t0);
    a.insert(&live_a).await.unwrap();

    // the same id may exist on another node and in another database: separate rows
    a2.insert(&closed_a).await.unwrap();
    b.insert(&closed_a).await.unwrap();

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
        "another database survives"
    );

    // migration tables are separate; the other product's objects were never touched
    for schema in ["ns_one", "ns_two"] {
        assert_eq!(
            count(
                &mut admin,
                &format!("SELECT COUNT(*) FROM {schema}.schema_migrations")
            )
            .await,
            1,
            "{schema}"
        );
    }
    assert_eq!(
        count(&mut admin, "SELECT COUNT(*) FROM other_product.leases").await,
        1
    );
    assert_eq!(
        count(
            &mut admin,
            "SELECT MAX(version) FROM other_product.schema_migrations"
        )
        .await,
        99
    );
    let note: Option<String> = admin
        .query_first("SELECT note FROM other_product.leases")
        .await
        .unwrap();
    assert_eq!(note.as_deref(), Some("foreign"));

    // pointing a store at the foreign database is refused (its history is newer), and it
    // leaves the foreign tables as they were
    let msg = failure(
        MariaDbLeaseStore::connect(
            &db.config("node-a", "other_product", TlsMode::Prefer),
            clock.clone(),
        )
        .await,
    );
    assert!(msg.contains("newer"), "{msg}");
    assert_eq!(
        count(&mut admin, "SELECT COUNT(*) FROM other_product.leases").await,
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn newer_schema_is_refused_and_terminal_rows_are_scrubbed_on_open() {
    let Some(db) = Maria::start(false).await else {
        return;
    };
    let clock = clock();
    let cfg = db.config("node-a", "scrub_ns", TlsMode::Prefer);
    drop(connect(&cfg, &clock).await);
    let mut admin = db.admin().await;

    // legacy terminal rows that kept the proxy password: this node's is scrubbed, another
    // node's is left alone
    let mut mine = common::lease("scrub", SessionStatus::Closed, clock.now());
    mine.spec.proxy = Some(browserx_core::ProxyRoute {
        url: "http://proxy.invalid:3128".into(),
        username: Some("user".into()),
        password: Some(Secret::new("synthetic-legacy-password")),
    });
    let json = serde_json::to_string(&mine).unwrap();
    assert!(json.contains("synthetic-legacy-password"));
    let id = mine.session_id.to_string();
    for node in ["node-a", "node-other"] {
        admin
            .exec_drop(
                "INSERT INTO scrub_ns.leases
                   (id, node, owner, status, generation, created_at_us, updated_at_us, lease_json)
                 VALUES (?, ?, 'scrub', 'closed', 1, 0, 0, ?)",
                (&id, node, &json),
            )
            .await
            .unwrap();
    }
    drop(connect(&cfg, &clock).await);
    assert!(
        !stored(&mut admin, &id, "node-a")
            .await
            .contains("synthetic-legacy-password")
    );
    assert!(
        stored(&mut admin, &id, "node-other")
            .await
            .contains("synthetic-legacy-password")
    );

    // a database written by a newer build is refused
    admin
        .query_drop("INSERT INTO scrub_ns.schema_migrations VALUES (999, 0)")
        .await
        .unwrap();
    let msg = failure(MariaDbLeaseStore::connect(&cfg, clock.clone()).await);
    assert!(msg.contains("newer than this build"), "{msg}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_modes_and_wrong_password() {
    let Some(db) = Maria::start(false).await else {
        return;
    };
    let clock = clock();
    // prefer to loopback works whether or not the server offers TLS; disable is explicit plain
    drop(connect(&db.config("n", "modes", TlsMode::Prefer), &clock).await);
    drop(connect(&db.config("n", "modes", TlsMode::Disable), &clock).await);
    // require without a trusted certificate authority cannot succeed against this server: it
    // has either no TLS or a self-signed certificate
    let msg = failure(
        MariaDbLeaseStore::connect(&db.config("n", "modes", TlsMode::Require), clock.clone()).await,
    );
    assert!(!msg.is_empty());

    // a wrong password is refused, and the error never carries a password
    let wrong = write_secret(db.dir.path(), "wrong", "not-the-password-0123456789");
    let mut cfg = db.config("n", "modes", TlsMode::Disable);
    cfg.password_file = Some(wrong);
    let msg = failure(MariaDbLeaseStore::connect(&cfg, clock.clone()).await);
    assert!(!msg.contains("not-the-password"));
    assert!(!msg.contains(&db.password));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_with_a_private_certificate_authority() {
    let Some(db) = Maria::start(true).await else {
        return;
    };
    let clock = clock();
    let ca = db.ca_file();
    let mut admin = db.admin().await;
    let accepts = |row: Option<(String, String)>| row.unwrap().1.parse::<u64>().unwrap();
    let before = accepts(
        admin
            .query_first("SHOW GLOBAL STATUS LIKE 'Ssl_accepts'")
            .await
            .unwrap(),
    );

    let mut cfg = db.config("n", "tls_ns", TlsMode::Require);
    cfg.tls_ca_file = Some(ca.clone());
    let store = connect(&cfg, &clock).await;
    store.ping().await.unwrap();
    let after = accepts(
        admin
            .query_first("SHOW GLOBAL STATUS LIKE 'Ssl_accepts'")
            .await
            .unwrap(),
    );
    assert!(after > before, "connections use TLS");
    common::lease_store_conformance(Arc::new(store), clock.clone()).await;

    // the private CA is not in the built-in roots: require without it fails the handshake
    let cfg = db.config("n", "tls_ns", TlsMode::Require);
    assert!(!failure(MariaDbLeaseStore::connect(&cfg, clock.clone()).await).is_empty());

    // prefer on loopback works with the CA, too
    let mut cfg = db.config("n", "tls_ns", TlsMode::Prefer);
    cfg.tls_ca_file = Some(ca);
    connect(&cfg, &clock).await.ping().await.unwrap();
}

#[test]
fn config_errors_are_clear() {
    let base = DatabaseConfig::new("mariadb://db.example.test");
    let err = |cfg: &DatabaseConfig| cfg.validate().unwrap_err().to_string();

    assert!(err(&base).contains("database.node is required"));
    let with_node = DatabaseConfig {
        node: Some("worker-1".into()),
        ..base.clone()
    };
    with_node.validate().unwrap();
    let with_password = DatabaseConfig {
        url: "mysql://app:hunter2@db.example.test".into(),
        ..with_node.clone()
    };
    let text = err(&with_password);
    assert!(text.contains("must not carry a password"));
    assert!(!text.contains("hunter2"));
    let bad_schema = DatabaseConfig {
        schema: Some("bad`name".into()),
        ..with_node.clone()
    };
    assert!(err(&bad_schema).contains("database.schema"));
}

#[tokio::test]
async fn connecting_with_an_invalid_config_fails_before_any_network_use() {
    let cfg = DatabaseConfig::new("mariadb://203.0.113.1");
    assert!(matches!(
        MariaDbLeaseStore::connect(&cfg, clock()).await,
        Err(Error::InvalidRequest(_))
    ));
    let postgres = DatabaseConfig {
        node: Some("n".into()),
        ..DatabaseConfig::new("postgres://203.0.113.1/app")
    };
    assert!(matches!(
        MariaDbLeaseStore::connect(&postgres, clock()).await,
        Err(Error::InvalidRequest(_))
    ));
}
