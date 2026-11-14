//! The worker on shared services: leases in PostgreSQL, sealed snapshots in an S3-API object
//! store, a real Chromium. Starts throwaway containers with podman (see `common::services`) and
//! runs only with `BROWSERX_TEST_SERVICES=1`; skipped, with a note, without Chromium.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use browserx_core::{PersistenceMode, SessionSpec, SessionStatus};
use browserx_runtime::discover_chromium;
use browserx_server::Config;
use browserx_store::{ObjectStore, ObjectStoreConfig, Sealer};
use common::services::{self, Service, Spec};

const ACCESS: &str = "bxtestaccesskey";
const SECRET: &str = "bxtestsecretkey0123456789abcdef";

struct Services {
    _pg: Service,
    _s3: Service,
    pg_port: u16,
    s3_port: u16,
    pg_password: String,
}

async fn start_services() -> Option<Services> {
    if !services::enabled("the worker on shared services") {
        return None;
    }
    let password = hex::encode(rand::random::<[u8; 16]>());
    let pg_env = format!("POSTGRES_PASSWORD={password}");
    let probe_password = password.clone();
    let pg = Service::start(
        &Spec {
            image: "docker.io/library/postgres:18@sha256:b9f6b8ff03b62f3cfd9d9ba3fe56226a9991c79d3fb46fd46536263bf02be553",
            ports: &[5432],
            env: &[&pg_env],
            tmpfs: &["/var/lib/postgresql"],
            command: &[],
            ready_within: Duration::from_secs(90),
        },
        move |ports| {
            let password = probe_password.clone();
            async move {
                let mut cfg = tokio_postgres::Config::new();
                cfg.host("127.0.0.1")
                    .port(ports[0])
                    .user("postgres")
                    .password(&password)
                    .dbname("postgres")
                    .connect_timeout(Duration::from_secs(2));
                match cfg.connect(tokio_postgres::NoTls).await {
                    Ok((client, connection)) => {
                        tokio::spawn(connection);
                        client.simple_query("SELECT 1").await.is_ok()
                    }
                    Err(_) => false,
                }
            }
        },
    )
    .await?;
    let key_env = format!("AWS_ACCESS_KEY_ID={ACCESS}");
    let secret_env = format!("AWS_SECRET_ACCESS_KEY={SECRET}");
    let s3 = Service::start(
        &Spec {
            image: "docker.io/chrislusf/seaweedfs:latest@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0",
            ports: &[8333],
            env: &[&key_env, &secret_env],
            tmpfs: &["/data"],
            command: &[
                "server",
                "-dir=/data",
                "-s3",
                "-s3.port=8333",
                "-ip.bind=0.0.0.0",
                "-volume.max=8",
                "-master.volumeSizeLimitMB=128",
            ],
            ready_within: Duration::from_secs(120),
        },
        |ports| async move { services::tcp_open(ports[0]).await },
    )
    .await?;
    Some(Services {
        pg_port: pg.ports[0],
        s3_port: s3.ports[0],
        _pg: pg,
        _s3: s3,
        pg_password: password,
    })
}

struct Worker {
    dir: tempfile::TempDir,
}

impl Worker {
    fn config(
        &self,
        svc: &Services,
        node: &str,
        schema: &str,
        bucket: &str,
        prefix: &str,
    ) -> Config {
        let keys = self.dir.path().join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        let snapshot_key = keys.join("snapshot.key");
        if !snapshot_key.exists() {
            Sealer::generate_key_file(&snapshot_key).unwrap();
        }
        std::fs::write(keys.join("db.password"), &svc.pg_password).unwrap();
        std::fs::write(
            keys.join("objects.credentials"),
            format!("access_key_id = \"{ACCESS}\"\nsecret_access_key = \"{SECRET}\"\n"),
        )
        .unwrap();
        let exe = discover_chromium().unwrap();
        let args = std::env::var("BROWSERX_TEST_BROWSER_ARGS")
            .unwrap_or_else(|_| "--no-sandbox --disable-gpu".into());
        let args: Vec<String> = args.split_whitespace().map(|a| format!("{a:?}")).collect();
        let text = format!(
            "[server]\nlisten = \"127.0.0.1:0\"\nops_listen = \"127.0.0.1:0\"\n\
             [[auth.api_keys]]\nname = \"eval\"\nsha256 = \"{}\"\nmax_sessions = 8\n\
             [pool]\nmax_browsers = 2\nqueue_timeout_secs = 20\n\
             [storage]\nstate_dir = \"{}\"\nsnapshot_key_file = \"{}\"\n\
             [egress]\nblock_private = true\nallow_cidrs = [\"127.0.0.0/8\"]\n\
             [database]\nurl = \"postgres://postgres@127.0.0.1:{}/postgres\"\nschema = \"{schema}\"\n\
             node = \"{node}\"\npassword_file = \"{}\"\ntls = \"disable\"\n\
             [object_store]\nprofile = \"self-hosted\"\nendpoint = \"http://127.0.0.1:{}\"\n\
             bucket = \"{bucket}\"\nprefix = \"{prefix}\"\npath_style = true\n\
             credentials_file = \"{}\"\nallow_http = true\n\
             [runtime.launch_profiles.default]\nheadless = true\nexecutable = \"{}\"\nargs = [{}]\n",
            browserx_server::key_digest("bxk_test_key"),
            self.dir.path().join("state").display(),
            snapshot_key.display(),
            svc.pg_port,
            keys.join("db.password").display(),
            svc.s3_port,
            keys.join("objects.credentials").display(),
            exe.display(),
            args.join(", ")
        );
        Config::from_toml(&text).unwrap()
    }
}

fn object_store(svc: &Services, bucket: &str, prefix: &str) -> ObjectStore {
    let cfg: ObjectStoreConfig = toml::from_str(&format!(
        "profile = \"self-hosted\"\nendpoint = \"http://127.0.0.1:{}\"\nbucket = \"{bucket}\"\n\
         prefix = \"{prefix}\"\npath_style = true\nallow_http = true\n",
        svc.s3_port
    ))
    .unwrap();
    ObjectStore::connect_with_env(&cfg, &|name| match name {
        "BROWSERX_OBJECT_STORE_ACCESS_KEY_ID" => Some(ACCESS.to_owned()),
        "BROWSERX_OBJECT_STORE_SECRET_ACCESS_KEY" => Some(SECRET.to_owned()),
        _ => None,
    })
    .unwrap()
}

#[tokio::test]
async fn a_worker_keeps_leases_in_postgresql_and_snapshots_in_the_object_store() {
    if discover_chromium().is_none() {
        eprintln!("SKIP: no Chromium found (set BROWSERX_CHROMIUM_PATH to run this test)");
        return;
    }
    let Some(svc) = start_services().await else {
        return;
    };
    let bucket = "bx-worker-test";
    // The port opens before the S3 gateway answers: retry until the bucket exists.
    let setup = object_store(&svc, bucket, "browserx/");
    let mut waited = 0;
    while setup.create_bucket().await.is_err() {
        waited += 1;
        assert!(waited < 120, "the object store did not come up");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let worker = Worker {
        dir: tempfile::tempdir().unwrap(),
    };

    // Worker one, node `node-a`.
    let cfg = worker.config(&svc, "node-a", "browserx", bucket, "browserx/");
    let (pool, _state) = browserx_server::build(&cfg).await.unwrap();
    pool.start().await.unwrap();
    pool.ping_store().await.unwrap();
    let spec = SessionSpec {
        persistence: PersistenceMode::Snapshot,
        ..SessionSpec::default()
    };
    let (lease, token) = pool.create("eval", spec).await.unwrap();
    let profile = lease.profile_id.expect("a snapshot session has a profile");
    let meta = pool
        .snapshot_now("eval", lease.session_id, &token)
        .await
        .unwrap();
    assert_eq!(meta.version, 1);
    pool.release("eval", lease.session_id, Some(&token), None)
        .await
        .unwrap();
    pool.shutdown().await;

    // The sealed snapshot is an object under the worker's prefix, and only there.
    let objects = object_store(&svc, bucket, "browserx/")
        .list(&format!("browserx/snapshots/{profile}/"))
        .await
        .unwrap();
    // The explicit snapshot and the final one taken at release.
    assert_eq!(objects.len(), 2, "{objects:?}");

    // A replacement worker with the same node finds the lease and the snapshot history.
    let (again, _state) = browserx_server::build(&cfg).await.unwrap();
    again.start().await.unwrap();
    let found = again.get("eval", lease.session_id).await.unwrap();
    assert_eq!(found.status, SessionStatus::Closed);
    assert_eq!(
        again
            .list_profile_snapshots("eval", profile)
            .await
            .unwrap()
            .len(),
        2
    );
    again.shutdown().await;

    // Another node on the same database and bucket sees none of it.
    let other = worker.config(&svc, "node-b", "browserx", bucket, "browserx/");
    let (stranger, _state) = browserx_server::build(&other).await.unwrap();
    stranger.start().await.unwrap();
    assert!(stranger.get("eval", lease.session_id).await.is_err());
    assert!(stranger.list("eval", None).await.unwrap().is_empty());
    stranger.shutdown().await;

    // Another product namespace (schema, bucket prefix) is empty too.
    let elsewhere = worker.config(&svc, "node-a", "other_product", bucket, "other/");
    let (separate, _state) = browserx_server::build(&elsewhere).await.unwrap();
    separate.start().await.unwrap();
    assert!(separate.get("eval", lease.session_id).await.is_err());
    separate.shutdown().await;
}

#[test]
fn the_database_and_object_store_sections_are_validated_when_the_configuration_loads() {
    let base = "[[auth.api_keys]]\nname = \"k\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\nmax_sessions = 1\n";
    for (extra, expect) in [
        ("[database]\nurl = \"postgres://u@h/db\"\n", "node"),
        (
            "[database]\nurl = \"postgres://u:pw@h/db\"\nnode = \"a\"\n",
            "password",
        ),
        (
            "[database]\nurl = \"sqlite:///x.db\"\nnode = \"a\"\n",
            "sqlite",
        ),
        (
            "[object_store]\nprofile = \"edge\"\nbucket = \"bucket-one\"\n",
            "endpoint",
        ),
        (
            "[object_store]\nprofile = \"standard\"\nbucket = \"bucket-one\"\nbogus = 1\n",
            "bogus",
        ),
    ] {
        let error = Config::from_toml(&format!("{base}{extra}"))
            .unwrap_err()
            .to_string();
        assert!(error.to_lowercase().contains(expect), "{extra}: {error}");
    }
    let ok = format!("{base}[database]\nurl = \"sqlite:///var/lib/bx/state.db\"\n");
    assert!(Config::from_toml(&ok).is_ok());
}
