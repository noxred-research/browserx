//! The `self-hosted` object-store profile against the two self-hosted S3 servers it is meant
//! for, with the same contract suite on each: credentials from a file, path-style addressing,
//! prefix isolation between two products in one bucket, list pagination, delete, an object near
//! the size of a real snapshot, the sealed-snapshot conformance suite and refusal of wrong
//! credentials. Multipart upload is not part of the suite: BrowserX writes each sealed snapshot
//! as one request (at most 64 MiB).
//!
//! Each server runs in a throwaway container started with podman and pinned by digest, and the
//! tests run only with `BROWSERX_TEST_SERVICES=1` (see `common::services`). MinIO's upstream
//! images are no longer published, so the legacy mirror is used.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use browserx_core::{ProfileId, SnapshotStore};
use browserx_store::{ObjectError, ObjectStore, ObjectStoreConfig, S3SnapshotStore};
use common::services::{self, Service, Spec};
use common::{sealed_snapshot, snapshot_store_conformance, test_sealer};

const MINIO: &str = "docker.io/bitnamilegacy/minio@sha256:b3d51900e846b92f7503ca6be07d2e8c56ebb6a13a60bc71b8777c716c074bcf";
const RUSTFS: &str = "docker.io/rustfs/rustfs@sha256:ecbf4480ae142703b50e5fe7e73c2c3472a270fa73d26ff62419bbc8929679c4";

struct Credentials {
    user: String,
    password: String,
    dir: tempfile::TempDir,
}

impl Credentials {
    fn new() -> Self {
        Self {
            user: format!("bxuser{:08x}", rand::random::<u32>()),
            password: format!("bxpass{:016x}", rand::random::<u64>()),
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn file(&self, password: &str) -> PathBuf {
        let path = self.dir.path().join(format!("{password}.credentials"));
        std::fs::write(
            &path,
            format!(
                "access_key_id = \"{}\"\nsecret_access_key = \"{password}\"\n",
                self.user
            ),
        )
        .unwrap();
        path
    }
}

fn config(port: u16, bucket: &str, prefix: &str, credentials: &Path) -> ObjectStoreConfig {
    serde_json::from_value(serde_json::json!({
        "profile": "self-hosted",
        "endpoint": format!("http://127.0.0.1:{port}"),
        "bucket": bucket,
        "prefix": prefix,
        "path_style": true,
        "credentials_file": credentials,
        "max_retries": 1,
        "request_timeout_secs": 60,
    }))
    .unwrap()
}

/// The contract suite, against a server that answers on `port` with `credentials`.
async fn contract(port: u16, credentials: &Credentials) {
    let good = credentials.file(&credentials.password);
    let bucket = format!("bx-{:08x}", rand::random::<u32>());
    let mine = ObjectStore::connect(&config(port, &bucket, "browserx/", &good)).unwrap();
    // The port opens before the gateway answers: retry until the bucket exists.
    let mut waited = 0;
    while mine.create_bucket().await.is_err() {
        waited += 1;
        assert!(waited < 120, "the object store did not come up");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    mine.ping().await.unwrap();
    let theirs = ObjectStore::connect(&config(port, &bucket, "other/", &good)).unwrap();
    let no_meta = std::collections::BTreeMap::new();

    // Prefix isolation: each side lists only its own objects, and the client refuses a key
    // outside its prefix instead of sending it.
    mine.put("browserx/a/one", b"mine", &no_meta, false)
        .await
        .unwrap();
    theirs
        .put("other/a/one", b"theirs", &no_meta, false)
        .await
        .unwrap();
    let listed: Vec<String> = mine
        .list("browserx/")
        .await
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(listed, vec!["browserx/a/one".to_owned()]);
    assert!(
        mine.put("other/a/one", b"x", &no_meta, false)
            .await
            .is_err()
    );
    assert!(mine.get("other/a/one").await.is_err());
    assert!(mine.delete("other/a/one").await.is_err());
    assert_eq!(
        theirs.get("other/a/one").await.unwrap().unwrap().0,
        b"theirs",
        "the foreign object is untouched"
    );

    // Round trip with user metadata, and head.
    let metadata =
        std::collections::BTreeMap::from([("bx-meta".to_owned(), "eyJ2IjoxfQ==".to_owned())]);
    mine.put("browserx/a/meta", b"payload", &metadata, false)
        .await
        .unwrap();
    let (body, got) = mine.get("browserx/a/meta").await.unwrap().unwrap();
    assert_eq!(body, b"payload");
    assert_eq!(got.get("bx-meta"), Some(&"eyJ2IjoxfQ==".to_owned()));
    assert_eq!(mine.head("browserx/a/meta").await.unwrap().unwrap().size, 7);
    assert!(mine.get("browserx/a/missing").await.unwrap().is_none());

    // List pagination: more objects than one page (1000) holds.
    let total = 1_105_usize;
    let mut pending = Vec::new();
    for n in 0..total {
        let store = mine.clone();
        pending.push(tokio::spawn(async move {
            store
                .put(
                    &format!("browserx/page/{n:05}"),
                    b"x",
                    &std::collections::BTreeMap::new(),
                    false,
                )
                .await
        }));
        if pending.len() == 24 {
            for task in pending.drain(..) {
                task.await.unwrap().unwrap();
            }
        }
    }
    for task in pending {
        task.await.unwrap().unwrap();
    }
    let page = mine.list("browserx/page/").await.unwrap();
    let keys: BTreeSet<&str> = page.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(page.len(), total);
    assert_eq!(keys.len(), total, "no key is listed twice across pages");

    // Delete: one, then many; the foreign prefix keeps its object.
    mine.delete("browserx/page/00000").await.unwrap();
    assert!(mine.head("browserx/page/00000").await.unwrap().is_none());
    let rest: Vec<String> = mine
        .list("browserx/page/")
        .await
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(rest.len(), total - 1);
    assert_eq!(mine.delete_many(&rest[..500]).await.unwrap(), 500);
    assert_eq!(
        mine.list("browserx/page/").await.unwrap().len(),
        total - 501
    );
    mine.delete("browserx/page/missing").await.unwrap();
    assert!(theirs.head("other/a/one").await.unwrap().is_some());

    // An object the size of a real snapshot.
    let big = vec![7_u8; 8 * 1024 * 1024];
    mine.put("browserx/big", &big, &no_meta, false)
        .await
        .unwrap();
    assert_eq!(mine.get("browserx/big").await.unwrap().unwrap().0, big);

    // The sealed-snapshot suite, unchanged, and two products sharing the bucket.
    let snapshots = |prefix: &str| {
        S3SnapshotStore::with_store(
            ObjectStore::connect(&config(port, &bucket, prefix, &good)).unwrap(),
        )
    };
    snapshot_store_conformance(Arc::new(snapshots("conformance/"))).await;
    let sealer = test_sealer();
    let (first, second) = (snapshots("product-a/"), snapshots("product-b/"));
    let profile = ProfileId::new();
    for version in 1..=3 {
        first
            .put(&sealed_snapshot(&sealer, profile, version))
            .await
            .unwrap();
    }
    assert!(second.latest(profile).await.unwrap().is_none());
    second
        .put(&sealed_snapshot(&sealer, profile, 1))
        .await
        .unwrap();
    assert_eq!(first.prune(profile, 1).await.unwrap(), 2);
    assert_eq!(first.delete_profile(profile).await.unwrap(), 1);
    assert!(second.latest(profile).await.unwrap().is_some());

    // Wrong credentials are refused with a typed error that does not echo them.
    let wrong = credentials.file(&format!("bxwrong{:016x}", rand::random::<u64>()));
    let bad = ObjectStore::connect(&config(port, &bucket, "browserx/", &wrong)).unwrap();
    match bad.ping().await {
        Err(ObjectError::Auth { .. }) => {}
        other => panic!("expected an authentication error, got {other:?}"),
    }
    assert!(
        !bad.ping()
            .await
            .unwrap_err()
            .to_string()
            .contains("not-the-password")
    );
}

async fn run(image: &str, env: Vec<String>, tmpfs: &[&str], ready_path: Option<&'static str>) {
    if !services::enabled("the self-hosted object store contract") {
        return;
    }
    let credentials = Credentials::new();
    let envs: Vec<String> = env
        .into_iter()
        .map(|e| {
            e.replace("{user}", &credentials.user)
                .replace("{password}", &credentials.password)
        })
        .collect();
    let refs: Vec<&str> = envs.iter().map(String::as_str).collect();
    let Some(service) = Service::start(
        &Spec {
            image,
            ports: &[9000],
            env: &refs,
            tmpfs,
            command: &[],
            ready_within: Duration::from_secs(120),
        },
        move |ports| async move {
            match ready_path {
                Some(path) => reqwest::get(format!("http://127.0.0.1:{}{path}", ports[0]))
                    .await
                    .is_ok_and(|r| r.status().is_success()),
                None => services::tcp_open(ports[0]).await,
            }
        },
    )
    .await
    else {
        return;
    };
    contract(service.ports[0], &credentials).await;
}

#[tokio::test]
async fn minio_meets_the_self_hosted_contract() {
    run(
        MINIO,
        vec![
            "MINIO_ROOT_USER={user}".into(),
            "MINIO_ROOT_PASSWORD={password}".into(),
        ],
        &["/bitnami/minio/data", "/data"],
        Some("/minio/health/ready"),
    )
    .await;
}

#[tokio::test]
async fn rustfs_meets_the_self_hosted_contract() {
    run(
        RUSTFS,
        vec![
            "RUSTFS_ACCESS_KEY={user}".into(),
            "RUSTFS_SECRET_KEY={password}".into(),
        ],
        &["/data:rw,mode=1777", "/logs:rw,mode=1777"],
        None,
    )
    .await;
}
