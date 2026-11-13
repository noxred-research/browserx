//! S3-API object store and snapshot store.
//!
//! Configuration, credential and client-behaviour tests run everywhere (they use a local mock
//! for retries and timeouts). The tests against a real S3-compatible server (SeaweedFS in a
//! throwaway container, profile `self-hosted`) run with `BROWSERX_TEST_SERVICES=1` and podman.
//! The `standard` and `edge` profiles are covered by configuration and signing tests, not by a
//! real cloud.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use browserx_core::{Error, ProfileId, SnapshotStore};
use browserx_store::{ObjectError, ObjectStore, ObjectStoreConfig, Profile, S3SnapshotStore, Sse};
use common::services::{self, Service, Spec};
use common::{sealed_snapshot, snapshot_store_conformance, test_sealer};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const ACCESS_KEY: &str = "bxtestaccesskey01";
const SECRET_KEY: &str = "bxtest-secret-0123456789abcdef";

fn cfg(v: Value) -> ObjectStoreConfig {
    serde_json::from_value(v).unwrap()
}

fn validate_err(v: Value) -> String {
    match cfg(v).validate() {
        Err(Error::InvalidRequest(m)) => m,
        other => panic!("expected an invalid-request error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------

#[test]
fn standard_profile() {
    cfg(json!({"profile": "standard", "region": "eu-west-1", "bucket": "my-bucket"}))
        .validate()
        .unwrap();
    cfg(
        json!({"profile": "standard", "region": "eu-west-1", "bucket": "my-bucket",
               "endpoint": "https://s3.example.test", "path_style": true, "sse": "kms",
               "kms_key_id": "alias-one"}),
    )
    .validate()
    .unwrap();
    assert!(validate_err(json!({"profile": "standard", "bucket": "my-bucket"})).contains("region"));
    // virtual-host addressing cannot work with an IP address or a dotted bucket
    assert!(
        validate_err(
            json!({"profile": "standard", "region": "eu-west-1", "bucket": "my-bucket",
                            "endpoint": "https://10.0.0.5"})
        )
        .contains("path_style")
    );
    assert!(
        validate_err(json!({"profile": "standard", "region": "eu-west-1", "bucket": "my.bucket"}))
            .contains("path_style")
    );
}

#[test]
fn edge_profile() {
    assert!(validate_err(json!({"profile": "edge", "bucket": "my-bucket"})).contains("endpoint"));
    cfg(json!({"profile": "edge", "bucket": "my-bucket", "endpoint": "https://objects.example.test"}))
        .validate()
        .unwrap();
    cfg(
        json!({"profile": "edge", "bucket": "my-bucket", "endpoint": "https://objects.example.test",
               "sse": "aes256"}),
    )
    .validate()
    .unwrap();
    let msg = validate_err(json!({"profile": "edge", "bucket": "my-bucket",
                                  "endpoint": "https://objects.example.test",
                                  "sse": "kms", "kms_key_id": "k1"}));
    assert!(msg.contains("kms"), "{msg}");
}

#[test]
fn self_hosted_profile() {
    cfg(json!({"profile": "self-hosted", "bucket": "my-bucket", "endpoint": "https://s3.internal.test"}))
        .validate()
        .unwrap();
    assert!(
        validate_err(json!({"profile": "self-hosted", "bucket": "my-bucket"})).contains("endpoint")
    );
    let msg = validate_err(json!({"profile": "self-hosted", "bucket": "my-bucket",
                                  "endpoint": "http://s3.internal.test:9000"}));
    assert!(msg.contains("allow_http"), "{msg}");
    cfg(json!({"profile": "self-hosted", "bucket": "my-bucket",
               "endpoint": "http://s3.internal.test:9000", "allow_http": true}))
    .validate()
    .unwrap();
    for loopback in [
        "http://127.0.0.1:9000",
        "http://localhost:9000",
        "http://[::1]:9000",
    ] {
        cfg(json!({"profile": "self-hosted", "bucket": "my-bucket", "endpoint": loopback}))
            .validate()
            .unwrap();
    }
}

#[test]
fn compatible_profile() {
    let base = json!({"profile": "compatible", "bucket": "my-bucket", "endpoint": "https://s3.example.test",
                      "region": "r1", "path_style": false});
    cfg(base.clone()).validate().unwrap();
    for missing in ["endpoint", "region", "path_style"] {
        let mut v = base.clone();
        v.as_object_mut().unwrap().remove(missing);
        assert!(validate_err(v).contains(missing), "{missing}");
    }
}

#[test]
fn bucket_prefix_and_endpoint_rules() {
    let with = |extra: Value| {
        let mut v = json!({"profile": "self-hosted", "bucket": "my-bucket", "endpoint": "https://s3.example.test"});
        for (k, val) in extra.as_object().unwrap() {
            v[k] = val.clone();
        }
        v
    };
    for bucket in [
        "ab",
        "UPPER-case",
        "under_score",
        "-leading",
        "trailing-",
        "1.2.3.4",
        "a..b",
        &"x".repeat(64),
    ] {
        assert!(
            validate_err(with(json!({"bucket": bucket}))).contains("bucket"),
            "{bucket}"
        );
    }
    cfg(with(json!({"bucket": "a.b-c.d", "path_style": true})))
        .validate()
        .unwrap();
    for prefix in [
        "",
        "/",
        "/abs/",
        "a/../b/",
        "a//b/",
        "a/./b/",
        "a\\b/",
        "line\nbreak/",
    ] {
        assert!(
            validate_err(with(json!({"prefix": prefix}))).contains("prefix"),
            "{prefix:?}"
        );
    }
    assert_eq!(
        cfg(with(json!({}))).normalized_prefix().unwrap(),
        "browserx/"
    );
    assert_eq!(
        cfg(with(json!({"prefix": "team/one"})))
            .normalized_prefix()
            .unwrap(),
        "team/one/"
    );
    // endpoints
    for endpoint in [
        "https://user:pw@s3.example.test",
        "https://user@s3.example.test",
        "https://s3.example.test/base",
        "https://s3.example.test/?x=1",
        "ftp://s3.example.test",
        "not a url",
    ] {
        let msg = validate_err(with(json!({"endpoint": endpoint})));
        assert!(msg.contains("endpoint"), "{endpoint}: {msg}");
        assert!(!msg.contains("pw"), "{msg}");
    }
    // numeric limits and encryption pairs
    assert!(
        validate_err(with(json!({"request_timeout_secs": 0}))).contains("request_timeout_secs")
    );
    assert!(
        validate_err(with(json!({"request_timeout_secs": 601}))).contains("request_timeout_secs")
    );
    assert!(validate_err(with(json!({"max_retries": 11}))).contains("max_retries"));
    assert!(validate_err(with(json!({"sse": "kms"}))).contains("kms_key_id"));
    assert!(validate_err(with(json!({"sse": "aes256", "kms_key_id": "k"}))).contains("kms_key_id"));
    assert!(validate_err(with(json!({"kms_key_id": "k"}))).contains("kms_key_id"));
    cfg(with(json!({"sse": "none"}))).validate().unwrap();
    assert!(validate_err(with(json!({"region": "Bad_Region"}))).contains("region"));
}

#[test]
fn config_is_strict_and_round_trips() {
    let unknown = json!({"profile": "edge", "bucket": "my-bucket", "endpoint": "https://e.test",
                         "access_key_id": "nope"});
    assert!(serde_json::from_value::<ObjectStoreConfig>(unknown).is_err());
    assert!(
        serde_json::from_value::<ObjectStoreConfig>(
            json!({"profile": "other", "bucket": "my-bucket"})
        )
        .is_err()
    );
    assert!(serde_json::from_value::<ObjectStoreConfig>(json!({"profile": "edge"})).is_err());
    for (profile, name) in [
        (Profile::Standard, "standard"),
        (Profile::Edge, "edge"),
        (Profile::SelfHosted, "self-hosted"),
        (Profile::Compatible, "compatible"),
    ] {
        assert_eq!(serde_json::to_value(profile).unwrap(), json!(name));
        assert_eq!(
            serde_json::from_value::<Profile>(json!(name)).unwrap(),
            profile
        );
    }
    assert_eq!(serde_json::to_value(Sse::Aes256).unwrap(), json!("aes256"));
    let c = cfg(
        json!({"profile": "self-hosted", "bucket": "my-bucket", "endpoint": "http://127.0.0.1:9000",
                       "credentials_file": "/etc/browserx/object.cred", "sse": "aes256"}),
    );
    let back: ObjectStoreConfig =
        serde_json::from_value(serde_json::to_value(&c).unwrap()).unwrap();
    assert_eq!(back.credentials_file, c.credentials_file);
    assert_eq!(back.prefix, "browserx/");
    assert_eq!(back.request_timeout_secs, 60);
    assert_eq!(back.max_retries, 3);
    back.validate().unwrap();
}

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------

fn write_file(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn local_cfg(port: u16, bucket: &str, prefix: &str, creds: Option<&Path>) -> ObjectStoreConfig {
    cfg(json!({
        "profile": "self-hosted",
        "endpoint": format!("http://127.0.0.1:{port}"),
        "bucket": bucket,
        "prefix": prefix,
        "credentials_file": creds,
        "max_retries": 0,
        "request_timeout_secs": 30,
    }))
}

fn no_env(_: &str) -> Option<String> {
    None
}

fn connect_err(c: &ObjectStoreConfig, env: &dyn Fn(&str) -> Option<String>) -> String {
    match ObjectStore::connect_with_env(c, env) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected the connection setup to be refused"),
    }
}

#[test]
fn credentials_from_file_and_environment() {
    let dir = tempfile::tempdir().unwrap();
    let base = local_cfg(9, "my-bucket", "p/", None);

    // nothing configured
    let msg = connect_err(&base, &no_env);
    assert!(msg.contains("BROWSERX_OBJECT_STORE_ACCESS_KEY_ID"), "{msg}");

    // environment
    let env = |name: &str| match name {
        "BROWSERX_OBJECT_STORE_ACCESS_KEY_ID" => Some(ACCESS_KEY.to_owned()),
        "BROWSERX_OBJECT_STORE_SECRET_ACCESS_KEY" => Some(SECRET_KEY.to_owned()),
        "BROWSERX_OBJECT_STORE_SESSION_TOKEN" => Some("session-token-value".to_owned()),
        _ => None,
    };
    let store = ObjectStore::connect_with_env(&base, &env).unwrap();
    for text in [format!("{store:?}"), store.summary().to_owned()] {
        assert!(
            !text.contains(SECRET_KEY) && !text.contains(ACCESS_KEY),
            "{text}"
        );
        assert!(!text.contains("session-token-value"), "{text}");
    }
    assert!(store.summary().contains("self-hosted") && store.summary().contains("my-bucket"));
    let half =
        |name: &str| (name == "BROWSERX_OBJECT_STORE_ACCESS_KEY_ID").then(|| ACCESS_KEY.to_owned());
    assert!(connect_err(&base, &half).contains("BROWSERX_OBJECT_STORE_SECRET_ACCESS_KEY"));

    // file
    let good = write_file(
        dir.path(),
        "good.cred",
        &format!(
            "# object store\naccess_key_id = \"{ACCESS_KEY}\"\nsecret_access_key = \"{SECRET_KEY}\"\nsession_token = \"tok\"\n"
        ),
    );
    let c = local_cfg(9, "my-bucket", "p/", Some(&good));
    ObjectStore::connect_with_env(&c, &no_env).unwrap();
    // the file wins over the environment
    let store = ObjectStore::connect_with_env(&c, &env).unwrap();
    assert!(!format!("{store:?}").contains(SECRET_KEY));

    for (name, text) in [
        (
            "unknown.cred",
            format!(
                "access_key_id = \"{ACCESS_KEY}\"\nsecret_access_key = \"{SECRET_KEY}\"\nregion = \"x\"\n"
            ),
        ),
        (
            "dup.cred",
            format!(
                "access_key_id = \"{ACCESS_KEY}\"\naccess_key_id = \"{ACCESS_KEY}\"\nsecret_access_key = \"{SECRET_KEY}\"\n"
            ),
        ),
        (
            "missing.cred",
            format!("access_key_id = \"{ACCESS_KEY}\"\n"),
        ),
        (
            "empty.cred",
            format!("access_key_id = \"\"\nsecret_access_key = \"{SECRET_KEY}\"\n"),
        ),
        ("garbage.cred", format!("{SECRET_KEY}\n")),
        (
            "quote.cred",
            format!(
                "access_key_id = \"{ACCESS_KEY}\"\nsecret_access_key = \"a\\\"b{SECRET_KEY}\"\n"
            ),
        ),
        (
            "big.cred",
            format!(
                "# {}\naccess_key_id = \"a\"\nsecret_access_key = \"b\"\n",
                "x".repeat(20_000)
            ),
        ),
    ] {
        let path = write_file(dir.path(), name, &text);
        let msg = connect_err(&local_cfg(9, "my-bucket", "p/", Some(&path)), &no_env);
        assert!(
            !msg.contains(SECRET_KEY) && !msg.contains(ACCESS_KEY),
            "{name}: {msg}"
        );
    }
    let msg = connect_err(
        &local_cfg(9, "my-bucket", "p/", Some(&dir.path().join("absent"))),
        &no_env,
    );
    assert!(msg.contains("credentials_file"), "{msg}");
}

#[test]
fn tls_ca_file_must_hold_a_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let creds = write_file(
        dir.path(),
        "c.cred",
        "access_key_id = \"a\"\nsecret_access_key = \"b\"\n",
    );
    let ca = write_file(dir.path(), "ca.pem", "not a certificate\n");
    let mut c = local_cfg(9, "my-bucket", "p/", Some(&creds));
    c.tls_ca_file = Some(ca);
    let msg = connect_err(&c, &no_env);
    assert!(msg.contains("tls_ca_file"), "{msg}");
    c.tls_ca_file = Some(dir.path().join("missing.pem"));
    assert!(connect_err(&c, &no_env).contains("tls_ca_file"));
}

// ---------------------------------------------------------------------------------------------
// Client behaviour against a local mock (no real service)
// ---------------------------------------------------------------------------------------------

struct Mock {
    port: u16,
    requests: Arc<AtomicUsize>,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
}

/// Answers every request with the next canned response (the last one repeats).
async fn mock(responses: Vec<String>, stall: bool) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (counter, log) = (Arc::clone(&requests), Arc::clone(&seen));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let reply = responses[n.min(responses.len() - 1)].clone();
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => buf.extend_from_slice(&chunk[..k]),
                    }
                }
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).into_owned());
                if stall {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    return;
                }
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    Mock {
        port,
        requests,
        seen,
    }
}

fn response(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len()
    )
}

fn mock_store(port: u16, retries: u32, timeout: u64) -> ObjectStore {
    let mut c = local_cfg(port, "my-bucket", "browserx/", None);
    c.max_retries = retries;
    c.request_timeout_secs = timeout;
    let env = |name: &str| match name {
        "BROWSERX_OBJECT_STORE_ACCESS_KEY_ID" => Some(ACCESS_KEY.to_owned()),
        "BROWSERX_OBJECT_STORE_SECRET_ACCESS_KEY" => Some(SECRET_KEY.to_owned()),
        _ => None,
    };
    ObjectStore::connect_with_env(&c, &env).unwrap()
}

#[tokio::test]
async fn server_errors_are_retried_with_a_bound() {
    let ok = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\nx-amz-meta-bx-meta: abc\r\n\r\n".to_owned();
    let m = mock(
        vec![
            response("503 Service Unavailable", "", ""),
            response("500 Internal Server Error", "", ""),
            ok,
        ],
        false,
    )
    .await;
    let head = mock_store(m.port, 3, 10)
        .head("browserx/a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.size, 5);
    assert_eq!(
        head.metadata.get("bx-meta").map(String::as_str),
        Some("abc")
    );
    assert_eq!(m.requests.load(Ordering::SeqCst), 3);

    // never-ending 500: 1 try + 2 retries, then a typed error
    let m = mock(
        vec![response(
            "500 Internal Server Error",
            "",
            "<Error><Code>InternalError</Code></Error>",
        )],
        false,
    )
    .await;
    let err = mock_store(m.port, 2, 10)
        .get("browserx/a")
        .await
        .unwrap_err();
    assert!(
        matches!(err, ObjectError::Server { status: 500, ref code } if code == "InternalError"),
        "{err:?}"
    );
    assert_eq!(m.requests.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn client_errors_are_not_retried_and_are_typed() {
    let xml = |code: &str| {
        format!("<?xml version=\"1.0\"?><Error><Code>{code}</Code><Message>m</Message></Error>")
    };
    let m = mock(
        vec![response("403 Forbidden", "", &xml("InvalidAccessKeyId"))],
        false,
    )
    .await;
    let store = mock_store(m.port, 3, 10);
    let err = store.ping().await.unwrap_err();
    assert!(
        matches!(err, ObjectError::Auth { status: 403, ref code } if code == "InvalidAccessKeyId"),
        "{err:?}"
    );
    assert_eq!(m.requests.load(Ordering::SeqCst), 1);
    let text = format!("{err} {err:?}");
    assert!(
        !text.contains(SECRET_KEY) && !text.contains(ACCESS_KEY) && !text.contains("127.0.0.1"),
        "{text}"
    );
    let core: Error = err.into();
    assert!(
        matches!(&core, Error::Storage(m) if m.contains("authentication")),
        "{core:?}"
    );

    let m = mock(
        vec![response("404 Not Found", "", &xml("NoSuchKey"))],
        false,
    )
    .await;
    assert!(
        mock_store(m.port, 3, 10)
            .get("browserx/a")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(m.requests.load(Ordering::SeqCst), 1);
    let m = mock(
        vec![response("404 Not Found", "", &xml("NoSuchBucket"))],
        false,
    )
    .await;
    assert!(matches!(
        mock_store(m.port, 3, 10).ping().await,
        Err(ObjectError::NoSuchBucket)
    ));
    let m = mock(
        vec![response(
            "412 Precondition Failed",
            "",
            &xml("PreconditionFailed"),
        )],
        false,
    )
    .await;
    let err = mock_store(m.port, 3, 10)
        .put("browserx/a", b"x", &BTreeMap::new(), true)
        .await
        .unwrap_err();
    assert!(matches!(err, ObjectError::PreconditionFailed), "{err:?}");
    assert_eq!(m.requests.load(Ordering::SeqCst), 1);
    let m = mock(
        vec![response("501 Not Implemented", "", &xml("NotImplemented"))],
        false,
    )
    .await;
    let err = mock_store(m.port, 3, 10)
        .put("browserx/a", b"x", &BTreeMap::new(), true)
        .await
        .unwrap_err();
    assert!(matches!(err, ObjectError::Unsupported(_)), "{err:?}");
    assert_eq!(m.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn request_carries_a_signature_and_never_the_secret() {
    let m = mock(
        vec![response(
            "200 OK",
            "",
            "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
        )],
        false,
    )
    .await;
    mock_store(m.port, 0, 10).ping().await.unwrap();
    let seen = m.seen.lock().unwrap().clone();
    let req = &seen[0];
    assert!(
        req.starts_with("GET /my-bucket?list-type=2&max-keys=1&prefix=browserx%2F HTTP/1.1\r\n"),
        "{req}"
    );
    let lower = req.to_ascii_lowercase();
    assert!(
        lower.contains("authorization: aws4-hmac-sha256 credential=bxtestaccesskey01/"),
        "{req}"
    );
    assert!(
        lower.contains("signedheaders=host;x-amz-content-sha256;x-amz-date"),
        "{req}"
    );
    assert!(
        lower.contains(&format!("host: 127.0.0.1:{}", m.port)),
        "{req}"
    );
    assert!(!req.contains(SECRET_KEY), "{req}");
}

#[tokio::test]
async fn timeouts_and_refused_connections_are_bounded_and_typed() {
    let m = mock(vec![response("200 OK", "", "")], true).await;
    let started = Instant::now();
    let err = mock_store(m.port, 1, 1).ping().await.unwrap_err();
    assert!(matches!(err, ObjectError::Timeout), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        m.requests.load(Ordering::SeqCst),
        2,
        "one try and one retry"
    );
    assert!(matches!(Error::from(err), Error::Timeout(_)));

    // a port nobody listens on
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let err = mock_store(port, 1, 5).ping().await.unwrap_err();
    assert!(matches!(err, ObjectError::Transport("connect")), "{err:?}");
    let text = format!("{err} {err:?}");
    assert!(
        !text.contains("127.0.0.1") && !text.contains(SECRET_KEY),
        "{text}"
    );
}

#[tokio::test]
async fn oversized_responses_are_refused() {
    let big =
        "HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\nConnection: close\r\n\r\n".to_owned();
    let m = mock(vec![big], false).await;
    let err = mock_store(m.port, 0, 10)
        .get("browserx/a")
        .await
        .unwrap_err();
    assert!(matches!(err, ObjectError::TooLarge(_)), "{err:?}");
}

#[tokio::test]
async fn keys_outside_the_prefix_never_leave_the_process() {
    let m = mock(vec![response("200 OK", "", "")], false).await;
    let store = mock_store(m.port, 0, 5);
    let meta = BTreeMap::new();
    for key in [
        "other/x",
        "browserx",
        "browserx/",
        "browserx/../other/x",
        "browserx/a/./b",
        "browserx//a",
        "browserx/a/",
        "browserx/a\\b",
        "browserx/a\nb",
    ] {
        assert!(
            matches!(store.get(key).await, Err(ObjectError::KeyOutsidePrefix)),
            "{key:?}"
        );
        assert!(
            matches!(store.head(key).await, Err(ObjectError::KeyOutsidePrefix)),
            "{key:?}"
        );
        assert!(
            matches!(store.delete(key).await, Err(ObjectError::KeyOutsidePrefix)),
            "{key:?}"
        );
        assert!(
            matches!(
                store.put(key, b"x", &meta, false).await,
                Err(ObjectError::KeyOutsidePrefix)
            ),
            "{key:?}"
        );
    }
    for prefix in ["other/", "", "browserx/../", "browser"] {
        assert!(
            matches!(store.list(prefix).await, Err(ObjectError::KeyOutsidePrefix)),
            "{prefix:?}"
        );
    }
    // one bad key anywhere refuses the whole batch before anything is sent
    let keys = vec!["browserx/a".to_owned(), "other/b".to_owned()];
    assert!(matches!(
        store.delete_many(&keys).await,
        Err(ObjectError::KeyOutsidePrefix)
    ));
    assert_eq!(m.requests.load(Ordering::SeqCst), 0);
    // payload and metadata limits
    let too_big = vec![0u8; browserx_store::MAX_SEALED_BYTES + 1];
    assert!(matches!(
        store.put("browserx/a", &too_big, &meta, false).await,
        Err(ObjectError::TooLarge(_))
    ));
    let huge = BTreeMap::from([("k".to_owned(), "v".repeat(4000))]);
    assert!(matches!(
        store.put("browserx/a", b"x", &huge, false).await,
        Err(ObjectError::TooLarge(_))
    ));
    assert_eq!(m.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn sse_headers_are_sent_and_signed() {
    for (sse, kms, expect) in [
        (
            Sse::Aes256,
            None,
            vec!["x-amz-server-side-encryption: aes256"],
        ),
        (
            Sse::Kms,
            Some("alias-one"),
            vec![
                "x-amz-server-side-encryption: aws:kms",
                "x-amz-server-side-encryption-aws-kms-key-id: alias-one",
            ],
        ),
    ] {
        let m = mock(vec![response("200 OK", "", "")], false).await;
        let mut c = local_cfg(m.port, "my-bucket", "browserx/", None);
        c.sse = Some(sse);
        c.kms_key_id = kms.map(str::to_owned);
        let env = |name: &str| match name {
            "BROWSERX_OBJECT_STORE_ACCESS_KEY_ID" => Some(ACCESS_KEY.to_owned()),
            "BROWSERX_OBJECT_STORE_SECRET_ACCESS_KEY" => Some(SECRET_KEY.to_owned()),
            _ => None,
        };
        let store = ObjectStore::connect_with_env(&c, &env).unwrap();
        store
            .put("browserx/a", b"x", &BTreeMap::new(), false)
            .await
            .unwrap();
        let req = m.seen.lock().unwrap()[0].to_ascii_lowercase();
        for line in expect {
            assert!(req.contains(&line.to_ascii_lowercase()), "{line}: {req}");
        }
        assert!(
            req.contains("signedheaders=") && req.contains("x-amz-server-side-encryption"),
            "{req}"
        );
        // reads carry no encryption header
        store.get("browserx/a").await.unwrap();
        assert!(
            !m.seen.lock().unwrap()[1]
                .to_ascii_lowercase()
                .contains("server-side-encryption")
        );
    }
}

#[tokio::test]
async fn conditional_create_falls_back_when_the_service_rejects_it() {
    let empty = response(
        "200 OK",
        "",
        "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
    );
    let m = mock(
        vec![
            empty.clone(),
            response(
                "501 Not Implemented",
                "",
                "<Error><Code>NotImplemented</Code></Error>",
            ),
            empty,
        ],
        false,
    )
    .await;
    let store = S3SnapshotStore::with_store(mock_store(m.port, 0, 10));
    let sealer = test_sealer();
    let profile = ProfileId::new();
    store
        .put(&sealed_snapshot(&sealer, profile, 1))
        .await
        .unwrap();
    store
        .put(&sealed_snapshot(&sealer, profile, 2))
        .await
        .unwrap();
    let seen: Vec<String> = m
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.to_ascii_lowercase())
        .collect();
    assert_eq!(seen.len(), 5, "{seen:?}");
    assert!(
        seen[1].starts_with("put ") && seen[1].contains("if-none-match: *"),
        "{}",
        seen[1]
    );
    assert!(
        seen[2].starts_with("put ") && !seen[2].contains("if-none-match"),
        "{}",
        seen[2]
    );
    assert!(
        seen[4].starts_with("put ") && !seen[4].contains("if-none-match"),
        "{}",
        seen[4]
    );
    assert!(seen[1].contains("x-amz-meta-bx-meta: "), "{}", seen[1]);
}

// ---------------------------------------------------------------------------------------------
// Real service: SeaweedFS as a self-hosted S3 server
// ---------------------------------------------------------------------------------------------

struct Server {
    _service: Service,
    _dir: tempfile::TempDir,
    creds: PathBuf,
    port: u16,
}

impl Server {
    async fn start() -> Option<Self> {
        if !services::enabled("the S3 tests") {
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let creds = write_file(
            dir.path(),
            "object.cred",
            &format!("access_key_id = \"{ACCESS_KEY}\"\nsecret_access_key = \"{SECRET_KEY}\"\n"),
        );
        let key_env = format!("AWS_ACCESS_KEY_ID={ACCESS_KEY}");
        let secret_env = format!("AWS_SECRET_ACCESS_KEY={SECRET_KEY}");
        let probe_creds = creds.clone();
        let service = Service::start(
            &Spec {
                image: "docker.io/chrislusf/seaweedfs:latest",
                ports: &[8333],
                env: &[&key_env, &secret_env],
                tmpfs: &["/data"],
                command: &[
                    "server",
                    "-dir=/data",
                    "-s3",
                    "-s3.port=8333",
                    "-s3.domainName=s3.localhost",
                    "-ip.bind=0.0.0.0",
                    "-volume.max=8",
                    "-master.volumeSizeLimitMB=128",
                ],
                ready_within: Duration::from_secs(120),
            },
            move |ports| {
                let creds = probe_creds.clone();
                async move {
                    // A listing with valid credentials answers only when the filer is up.
                    let c = local_cfg(ports[0], "bx-readiness", "browserx/", Some(&creds));
                    let Ok(store) = ObjectStore::connect(&c) else {
                        return false;
                    };
                    store.create_bucket().await.is_ok() && store.ping().await.is_ok()
                }
            },
        )
        .await?;
        let port = service.ports[0];
        Some(Self {
            _service: service,
            _dir: dir,
            creds,
            port,
        })
    }

    fn config(&self, bucket: &str, prefix: &str) -> ObjectStoreConfig {
        local_cfg(self.port, bucket, prefix, Some(&self.creds))
    }

    async fn bucket(&self) -> String {
        let name = format!("bx-{:08x}", rand::random::<u32>());
        ObjectStore::connect(&self.config(&name, "browserx/"))
            .unwrap()
            .create_bucket()
            .await
            .unwrap();
        name
    }
}

fn filler(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[3]
        })
        .collect()
}

#[tokio::test]
async fn s3_snapshot_store_against_a_real_server() {
    let Some(server) = Server::start().await else {
        return;
    };
    let bucket = server.bucket().await;

    // --- conformance, unchanged ---
    let store = S3SnapshotStore::connect(&server.config(&bucket, "browserx/")).unwrap();
    store.ping().await.unwrap();
    assert!(store.profile_summary().contains(&bucket));
    assert!(!store.profile_summary().contains(SECRET_KEY));
    snapshot_store_conformance(Arc::new(store.clone())).await;

    // --- layout, metadata and bookkeeping ---
    let sealer = test_sealer();
    let profile = ProfileId::new();
    let snap = sealed_snapshot(&sealer, profile, 12);
    store.put(&snap).await.unwrap();
    let raw = ObjectStore::connect(&server.config(&bucket, "browserx/")).unwrap();
    let key = format!("browserx/snapshots/{}/{:020}.snap", profile.prefixed(), 12);
    let head = raw.head(&key).await.unwrap().unwrap();
    assert_eq!(head.size, snap.meta.size);
    let encoded = head.metadata.get("bx-meta").expect("metadata header");
    assert!(encoded.len() < 2048, "{}", encoded.len());
    let (bytes, _) = raw.get(&key).await.unwrap().unwrap();
    assert_eq!(bytes, snap.sealed);
    // a stray object next to the snapshots is not a version and does not break anything
    raw.put(
        &format!("browserx/snapshots/{}/notes.txt", profile.prefixed()),
        b"x",
        &BTreeMap::new(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(store.list(profile).await.unwrap().len(), 1);
    assert_eq!(store.latest(profile).await.unwrap().unwrap(), snap);
    // metadata that disagrees with the object location is refused
    let other = sealed_snapshot(&sealer, profile, 13);
    let wrong_key = format!("browserx/snapshots/{}/{:020}.snap", profile.prefixed(), 14);
    let wrong_meta = BTreeMap::from([(
        "bx-meta".to_owned(),
        head.metadata.get("bx-meta").unwrap().clone(),
    )]);
    raw.put(&wrong_key, &other.sealed, &wrong_meta, false)
        .await
        .unwrap();
    assert!(matches!(
        store.latest(profile).await,
        Err(Error::Storage(_))
    ));
    assert_eq!(store.delete_profile(profile).await.unwrap(), 2);
    assert!(
        raw.list(&format!("browserx/snapshots/{}/", profile.prefixed()))
            .await
            .unwrap()
            .is_empty()
    );

    // metadata too large for an object's user metadata is refused before any request
    let mut fat = sealed_snapshot(&sealer, ProfileId::new(), 1);
    fat.meta.key_id = "k".repeat(4000);
    assert!(matches!(
        store.put(&fat).await,
        Err(Error::InvalidRequest(_))
    ));

    // --- a large object round-trips ---
    let big_profile = ProfileId::new();
    let mut big = sealed_snapshot(&sealer, big_profile, 1);
    big.sealed = filler(8 * 1024 * 1024);
    big.meta.size = u64::try_from(big.sealed.len()).unwrap();
    store.put(&big).await.unwrap();
    let back = store.latest(big_profile).await.unwrap().unwrap();
    assert_eq!(back.meta, big.meta);
    assert!(
        back.sealed == big.sealed,
        "8 MiB payload differs after the round trip"
    );
    assert_eq!(store.delete_profile(big_profile).await.unwrap(), 1);
}

#[tokio::test]
async fn shared_instance_namespaces_do_not_see_each_other() {
    let Some(server) = Server::start().await else {
        return;
    };
    let bucket = server.bucket().await;
    let sealer = test_sealer();

    let a = S3SnapshotStore::connect(&server.config(&bucket, "team-a/")).unwrap();
    let b = S3SnapshotStore::connect(&server.config(&bucket, "team-b/browserx")).unwrap();
    let foreign = ObjectStore::connect(&server.config(&bucket, "other-tool/")).unwrap();
    foreign
        .put(
            "other-tool/snapshots/keep.snap",
            b"foreign",
            &BTreeMap::new(),
            false,
        )
        .await
        .unwrap();

    // the same profile id in both namespaces
    let profile = ProfileId::new();
    for v in 1..=4 {
        a.put(&sealed_snapshot(&sealer, profile, v)).await.unwrap();
    }
    assert!(b.latest(profile).await.unwrap().is_none());
    assert!(b.list(profile).await.unwrap().is_empty());
    for v in 1..=3 {
        b.put(&sealed_snapshot(&sealer, profile, v * 10))
            .await
            .unwrap();
    }
    let versions = |metas: Vec<browserx_core::SnapshotMeta>| {
        metas.iter().map(|m| m.version).collect::<Vec<_>>()
    };
    assert_eq!(versions(a.list(profile).await.unwrap()), vec![4, 3, 2, 1]);
    assert_eq!(versions(b.list(profile).await.unwrap()), vec![30, 20, 10]);
    assert_eq!(a.latest(profile).await.unwrap().unwrap().meta.version, 4);

    // pruning and erasing one namespace touches neither the other nor the foreign object
    assert_eq!(a.prune(profile, 1).await.unwrap(), 3);
    assert_eq!(versions(b.list(profile).await.unwrap()), vec![30, 20, 10]);
    assert_eq!(a.delete_profile(profile).await.unwrap(), 1);
    assert!(a.latest(profile).await.unwrap().is_none());
    assert_eq!(versions(b.list(profile).await.unwrap()), vec![30, 20, 10]);
    assert_eq!(b.prune(profile, 1).await.unwrap(), 2);
    assert_eq!(b.delete_profile(profile).await.unwrap(), 1);
    let (bytes, _) = foreign
        .get("other-tool/snapshots/keep.snap")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, b"foreign");

    // a client cannot be pointed outside its prefix
    let store_a = ObjectStore::connect(&server.config(&bucket, "team-a/")).unwrap();
    assert!(matches!(
        store_a.list("team-b/").await,
        Err(ObjectError::KeyOutsidePrefix)
    ));
    assert!(matches!(
        store_a.delete("other-tool/snapshots/keep.snap").await,
        Err(ObjectError::KeyOutsidePrefix)
    ));
    // a second bucket on the same instance is independent too
    let other_bucket = server.bucket().await;
    let c = S3SnapshotStore::connect(&server.config(&other_bucket, "team-a/")).unwrap();
    a.put(&sealed_snapshot(&sealer, profile, 1)).await.unwrap();
    assert!(c.latest(profile).await.unwrap().is_none());
    a.delete_profile(profile).await.unwrap();
}

#[tokio::test]
async fn object_operations_against_a_real_server() {
    let Some(server) = Server::start().await else {
        return;
    };
    let bucket = server.bucket().await;
    let store = ObjectStore::connect(&server.config(&bucket, "browserx/")).unwrap();

    // special characters survive signing, listing and XML escaping
    let keys = [
        "browserx/with space/a b.bin",
        "browserx/plus+and&amp;/x=1.bin",
        "browserx/unicode/é-日本.bin",
        "browserx/dollar$/q?x#y.bin",
    ];
    let meta = BTreeMap::from([("bx-note".to_owned(), "hello world".to_owned())]);
    for key in keys {
        store.put(key, key.as_bytes(), &meta, false).await.unwrap();
    }
    for key in keys {
        let (bytes, md) = store.get(key).await.unwrap().unwrap();
        assert_eq!(bytes, key.as_bytes(), "{key}");
        assert_eq!(
            md.get("bx-note").map(String::as_str),
            Some("hello world"),
            "{key}"
        );
        assert_eq!(
            store.head(key).await.unwrap().unwrap().size,
            u64::try_from(key.len()).unwrap()
        );
    }
    let mut listed: Vec<String> = store
        .list("browserx/")
        .await
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    listed.sort();
    let mut expected: Vec<String> = keys.iter().map(|k| (*k).to_owned()).collect();
    expected.sort();
    assert_eq!(listed, expected);
    assert!(store.get("browserx/absent").await.unwrap().is_none());
    assert!(store.head("browserx/absent").await.unwrap().is_none());
    store.delete("browserx/absent").await.unwrap();

    // conditional create: refused when the key exists (or reported as unsupported)
    let key = "browserx/cond/one";
    match store.put(key, b"first", &BTreeMap::new(), true).await {
        Ok(()) => {}
        Err(ObjectError::Unsupported(code)) => {
            eprintln!("NOTE: server does not support conditional create ({code})");
            return;
        }
        Err(e) => panic!("{e:?}"),
    }
    let second = store.put(key, b"second", &BTreeMap::new(), true).await;
    match second {
        Err(ObjectError::PreconditionFailed) => {
            assert_eq!(store.get(key).await.unwrap().unwrap().0, b"first");
        }
        Ok(()) => eprintln!("NOTE: server ignores If-None-Match on put (overwrote the object)"),
        Err(e) => panic!("{e:?}"),
    }

    // pagination: more entries than one page
    let total = 1105usize;
    let mut tasks = tokio::task::JoinSet::new();
    for chunk in 0..(total / 65 + 1) {
        let store = store.clone();
        tasks.spawn(async move {
            for i in (chunk * 65)..((chunk + 1) * 65).min(total) {
                store
                    .put(
                        &format!("browserx/many/{i:05}"),
                        b"x",
                        &BTreeMap::new(),
                        false,
                    )
                    .await
                    .unwrap();
            }
        });
    }
    while let Some(done) = tasks.join_next().await {
        done.unwrap();
    }
    let all = store.list("browserx/many/").await.unwrap();
    assert_eq!(all.len(), total);
    assert!(
        all.windows(2).all(|w| w[0].0 < w[1].0),
        "listing is in key order"
    );
    let keys: Vec<String> = all.iter().take(500).map(|(k, _)| k.clone()).collect();
    assert_eq!(store.delete_many(&keys).await.unwrap(), 500);
    assert_eq!(
        store.list("browserx/many/").await.unwrap().len(),
        total - 500
    );
    let rest: Vec<String> = store
        .list("browserx/many/")
        .await
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .take(600)
        .collect();
    store.delete_many(&rest).await.unwrap();
    let rest: Vec<String> = store
        .list("browserx/many/")
        .await
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    store.delete_many(&rest).await.unwrap();
    assert!(store.list("browserx/many/").await.unwrap().is_empty());
}

#[tokio::test]
async fn concurrent_writers_of_one_version_cannot_both_win() {
    let Some(server) = Server::start().await else {
        return;
    };
    let bucket = server.bucket().await;
    let store = S3SnapshotStore::connect(&server.config(&bucket, "browserx/")).unwrap();
    let sealer = test_sealer();
    let probe = ObjectStore::connect(&server.config(&bucket, "browserx/")).unwrap();
    let supports = match probe
        .put("browserx/probe", b"1", &BTreeMap::new(), true)
        .await
    {
        Ok(()) => matches!(
            probe
                .put("browserx/probe", b"2", &BTreeMap::new(), true)
                .await,
            Err(ObjectError::PreconditionFailed)
        ),
        Err(_) => false,
    };
    if !supports {
        eprintln!("NOTE: server has no conditional create; skipping the concurrent-writer check");
        return;
    }
    for round in 0..5u64 {
        let profile = ProfileId::new();
        let (a, b) = (store.clone(), store.clone());
        let (s1, s2) = (
            sealed_snapshot(&sealer, profile, round + 1),
            sealed_snapshot(&sealer, profile, round + 1),
        );
        let (r1, r2) = tokio::join!(
            tokio::spawn(async move { a.put(&s1).await }),
            tokio::spawn(async move { b.put(&s2).await })
        );
        let results = [r1.unwrap(), r2.unwrap()];
        let wins = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(wins, 1, "{results:?}");
        assert!(
            results.iter().any(|r| matches!(r, Err(Error::Conflict(_)))),
            "{results:?}"
        );
        assert_eq!(store.list(profile).await.unwrap().len(), 1);
        store.delete_profile(profile).await.unwrap();
    }
}

#[tokio::test]
async fn wrong_credentials_give_a_typed_error_without_secrets() {
    let Some(server) = Server::start().await else {
        return;
    };
    let bucket = server.bucket().await;
    let dir = tempfile::tempdir().unwrap();
    let bad_secret = format!("this-secret-is-{}-{:016x}", "wrong", rand::random::<u64>());
    let bad = write_file(
        dir.path(),
        "bad.cred",
        &format!("access_key_id = \"{ACCESS_KEY}\"\nsecret_access_key = \"{bad_secret}\"\n"),
    );
    let unknown = write_file(
        dir.path(),
        "unknown.cred",
        &format!("access_key_id = \"nosuchaccesskey\"\nsecret_access_key = \"{SECRET_KEY}\"\n"),
    );
    for path in [bad, unknown] {
        let c = local_cfg(server.port, &bucket, "browserx/", Some(&path));
        let store = ObjectStore::connect(&c).unwrap();
        let err = store.ping().await.unwrap_err();
        assert!(matches!(err, ObjectError::Auth { .. }), "{err:?}");
        let text = format!("{err} {err:?} {store:?} {c:?}");
        for secret in [
            bad_secret.as_str(),
            SECRET_KEY,
            ACCESS_KEY,
            "nosuchaccesskey",
        ] {
            assert!(!text.contains(secret), "{text}");
        }
        assert!(!text.contains("Signature="), "{text}");
        // the same failure through the snapshot store is a storage error that says why
        let snaps = S3SnapshotStore::connect(&c).unwrap();
        let core = snaps.latest(ProfileId::new()).await.unwrap_err();
        assert!(
            matches!(&core, Error::Storage(m) if m.contains("authentication")),
            "{core:?}"
        );
        assert!(!core.to_string().contains(bad_secret.as_str()));
    }
    // a bucket that does not exist
    let c = server.config("bx-no-such-bucket", "browserx/");
    assert!(matches!(
        ObjectStore::connect(&c).unwrap().ping().await,
        Err(ObjectError::NoSuchBucket)
    ));
}

#[tokio::test]
async fn sse_header_and_virtual_host_addressing() {
    let Some(server) = Server::start().await else {
        return;
    };
    let bucket = server.bucket().await;
    let sealer = test_sealer();

    // server-side encryption header is accepted by the service
    let mut c = server.config(&bucket, "browserx/");
    c.sse = Some(Sse::Aes256);
    let enc = S3SnapshotStore::connect(&c).unwrap();
    let profile = ProfileId::new();
    match enc.put(&sealed_snapshot(&sealer, profile, 1)).await {
        Ok(()) => assert_eq!(enc.latest(profile).await.unwrap().unwrap().meta.version, 1),
        Err(e) => eprintln!("NOTE: server rejects the AES256 header: {e}"),
    }
    let _ = enc.delete_profile(profile).await;

    // virtual-host addressing: bucket.s3.localhost, needs name resolution for *.localhost
    let host = format!("{bucket}.s3.localhost:{}", server.port);
    if std::net::ToSocketAddrs::to_socket_addrs(&host).is_err() {
        eprintln!("NOTE: {host} does not resolve here; skipping virtual-host addressing");
        return;
    }
    let mut v = server.config(&bucket, "browserx/");
    v.endpoint = Some(format!("http://s3.localhost:{}", server.port));
    v.path_style = Some(false);
    let vhost = S3SnapshotStore::connect(&v).unwrap();
    assert!(vhost.profile_summary().contains("virtual-host"));
    vhost.ping().await.unwrap();
    let profile = ProfileId::new();
    vhost
        .put(&sealed_snapshot(&sealer, profile, 1))
        .await
        .unwrap();
    // the path-style client sees the object the virtual-host client wrote
    let path_style = S3SnapshotStore::connect(&server.config(&bucket, "browserx/")).unwrap();
    assert_eq!(
        path_style
            .latest(profile)
            .await
            .unwrap()
            .unwrap()
            .meta
            .version,
        1
    );
    assert_eq!(vhost.delete_profile(profile).await.unwrap(), 1);
}
