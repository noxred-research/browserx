#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The OpenSearch and Elasticsearch audit export sinks against real servers in podman.

mod common;

use std::path::Path;
use std::time::Duration;

use common::export_kit::{
    Proxy, assert_chain, config, eventually, local_records, secret_file, slowest, start_ctx, stats,
    write_entries,
};
use common::services::{self, Service, Spec};
use serde_json::{Value, json};

const OPENSEARCH: &str = "docker.io/opensearchproject/opensearch:2@sha256:3bfa1ec74d56928c2e018033d45c460ce2c0ea65a5cedd577de3102326c31b89";
const ELASTICSEARCH: &str = "docker.elastic.co/elasticsearch/elasticsearch:8.15.3@sha256:01c1732062b4a846c5ca687b0094b89bad0bfed00c6d71626db32fb8f3131a78";
const ADMIN_PASSWORD: &str = "Synthetic-Pass-7391!";

#[derive(Clone)]
enum Auth {
    None,
    Basic(&'static str, &'static str),
}

struct Api {
    base: String,
    auth: Auth,
    http: reqwest::Client,
}

impl Api {
    fn new(base: String, auth: Auth) -> Self {
        Self {
            base,
            auth,
            http: reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
        }
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base))
            .header("content-type", "application/json");
        if let Auth::Basic(user, password) = &self.auth {
            request = request.basic_auth(user, Some(password));
        }
        if let Some(body) = body {
            request = request.body(body.to_string());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn get(&self, path: &str) -> Value {
        let (status, body) = self.call(reqwest::Method::GET, path, None).await;
        assert!(status < 300, "GET {path} answered {status}: {body}");
        body
    }

    /// The documents of `index` matching `query`, by `seq`.
    async fn search(&self, index: &str, query: Value) -> Vec<Value> {
        let mut last = (0, Value::Null);
        for _ in 0..30 {
            self.call(reqwest::Method::POST, &format!("/{index}/_refresh"), None)
                .await;
            last = self
                .call(
                    reqwest::Method::POST,
                    &format!("/{index}/_search"),
                    Some(json!({"size": 1000, "sort": [{"seq": {"order": "asc", "unmapped_type": "long"}}], "query": query})),
                )
                .await;
            if last.0 != 503 {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let (status, body) = last;
        assert!(status < 300, "search answered {status}: {body}");
        body["hits"]["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["_source"].clone())
            .collect()
    }

    /// Index names without the engine's own hidden indices.
    async fn indices(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .get("/_cat/indices?format=json&h=index&expand_wildcards=all")
            .await
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["index"].as_str().unwrap().to_owned())
            .filter(|n| !n.starts_with('.'))
            .collect();
        names.sort();
        names
    }
}

async fn ready(port: u16, scheme: &str) -> bool {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(format!("{scheme}://127.0.0.1:{port}/"))
        .send()
        .await
        .is_ok()
}

async fn start_opensearch(secure: bool) -> Option<Service> {
    let password = format!("OPENSEARCH_INITIAL_ADMIN_PASSWORD={ADMIN_PASSWORD}");
    let mut env = vec![
        "discovery.type=single-node",
        "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m",
        "cluster.routing.allocation.disk.threshold_enabled=false",
    ];
    if secure {
        env.push(&password);
    } else {
        env.push("DISABLE_SECURITY_PLUGIN=true");
        env.push("DISABLE_INSTALL_DEMO_CONFIG=true");
    }
    Service::start(
        &Spec {
            image: OPENSEARCH,
            ports: &[9200],
            env: &env,
            tmpfs: &["/usr/share/opensearch/data:rw,mode=0777"],
            command: &[],
            ready_within: Duration::from_secs(120),
        },
        move |ports| async move { ready(ports[0], if secure { "https" } else { "http" }).await },
    )
    .await
}

async fn start_elasticsearch() -> Option<Service> {
    let password = format!("ELASTIC_PASSWORD={ADMIN_PASSWORD}");
    Service::start(
        &Spec {
            image: ELASTICSEARCH,
            ports: &[9200],
            env: &[
                "discovery.type=single-node",
                "ES_JAVA_OPTS=-Xms512m -Xmx512m",
                "xpack.security.enabled=true",
                "xpack.security.http.ssl.enabled=false",
                "xpack.ml.enabled=false",
                "cluster.routing.allocation.disk.threshold_enabled=false",
                &password,
            ],
            tmpfs: &["/usr/share/elasticsearch/data:rw,mode=0777"],
            command: &[],
            ready_within: Duration::from_secs(150),
        },
        |ports| async move { ready(ports[0], "http").await },
    )
    .await
}

fn section(kind: &str, url: &str, prefix: &str, auth: &str) -> String {
    format!(
        "[search]\nkind = \"{kind}\"\nurl = \"{url}\"\nindex_prefix = \"{prefix}\"\nbatch_size = 10\nflush_interval_ms = 50\nrequest_timeout_ms = 3000\n{auth}"
    )
}

/// The checks every engine must pass: namespaces, foreign indices, searchability, chain,
/// duplicates, idempotent migrations and refusal of a newer schema.
async fn shared_suite(kind: &str, url: &str, auth_lines: &str, api: &Api, dir: &Path) {
    api.call(reqwest::Method::PUT, "/foreign-logs", None).await;
    api.call(
        reqwest::Method::POST,
        "/foreign-logs/_doc/1?refresh=true",
        Some(json!({"message": "keep me"})),
    )
    .await;

    let a = start_ctx(config(
        dir,
        "a",
        "ENG-A",
        &section(kind, url, "bxa-", auth_lines),
    ));
    let b = start_ctx(config(
        dir,
        "b",
        "ENG-B",
        &section(kind, url, "bxb-", auth_lines),
    ));
    a.preflight_export().await.unwrap();
    b.preflight_export().await.unwrap();
    write_entries(&a.audit, "a", 25);
    write_entries(&b.audit, "b", 8);
    a.shutdown().await;
    b.shutdown().await;

    // Everything arrived through the alias with the full record.
    let received = api.search("bxa-audit", json!({"match_all": {}})).await;
    let record_fields: Vec<Value> = received
        .iter()
        .map(|doc| {
            let mut record = doc.as_object().unwrap().clone();
            for extra in [
                "engagement",
                "operator",
                "reason",
                "action_class",
                "trace_id",
                "arguments_text",
            ] {
                record.remove(extra);
            }
            Value::Object(record)
        })
        .collect();
    assert_eq!(record_fields, local_records(a.audit.path()));
    assert_chain(&record_fields, 25);

    // Searchable as designed.
    let by_text = api
        .search(
            "bxa-audit",
            json!({"match_phrase": {"arguments_text": "zebra-a-7"}}),
        )
        .await;
    assert_eq!(by_text.len(), 1);
    assert_eq!(by_text[0]["seq"], 8);
    let by_fields = api
        .search(
            "bxa-audit",
            json!({"bool": {"filter": [{"term": {"outcome": "refused"}}, {"term": {"engagement": "ENG-A"}},
                {"term": {"reason": "out_of_scope"}}, {"range": {"seq": {"gte": 10, "lte": 20}}},
                {"range": {"ts": {"gte": "2026-01-01T00:00:00Z"}}}]}}),
        )
        .await;
    assert_eq!(by_fields.len(), 6);
    let by_detail = api
        .search("bxa-audit", json!({"match": {"detail": "synthetic"}}))
        .await;
    assert_eq!(by_detail.len(), 25);
    let mapping = api.get("/bxa-audit-v1/_mapping").await;
    assert_eq!(
        mapping["bxa-audit-v1"]["mappings"]["_meta"]["browserx_schema_version"],
        1
    );
    assert_eq!(
        api.get("/bxa-audit-v1/_alias").await["bxa-audit-v1"]["aliases"]["bxa-audit"]["is_write_index"],
        true
    );

    // Namespaces are separate and the foreign index survived untouched.
    assert_eq!(
        api.search("bxb-audit", json!({"match_all": {}}))
            .await
            .len(),
        8
    );
    assert!(
        api.search("bxb-audit", json!({"term": {"engagement": "ENG-A"}}))
            .await
            .is_empty()
    );
    assert_eq!(
        api.indices().await,
        ["bxa-audit-v1", "bxb-audit-v1", "foreign-logs"]
    );
    assert_eq!(
        api.search("foreign-logs", json!({"match_all": {}}))
            .await
            .len(),
        1
    );

    // A restart migrates nothing again; a record sent twice is stored once (id = hash).
    let again = start_ctx(config(
        dir,
        "a",
        "ENG-A",
        &section(kind, url, "bxa-", auth_lines),
    ));
    again.preflight_export().await.unwrap();
    let duplicate = received.iter().find(|d| d["seq"] == 3).unwrap().clone();
    let exporter = again.audit.exporter().unwrap();
    exporter.offer(&duplicate);
    exporter.offer(&duplicate);
    eventually("duplicates to be sent", Duration::from_secs(10), || async {
        (stats(exporter).sent == 2).then_some(())
    })
    .await;
    again.shutdown().await;
    assert_eq!(
        api.search("bxa-audit", json!({"match_all": {}}))
            .await
            .len(),
        25
    );
    assert_eq!(
        api.get("/_cat/indices/bxa-*?format=json")
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // An index written by a newer BrowserX is refused, and nothing is written to it.
    let (status, body) = api
        .call(
            reqwest::Method::PUT,
            "/bxa-audit-v1/_mapping",
            Some(json!({"_meta": {"browserx_schema_version": 99}})),
        )
        .await;
    assert!(status < 300, "{body}");
    let newer = start_ctx(config(
        dir,
        "a",
        "ENG-A",
        &section(kind, url, "bxa-", auth_lines),
    ));
    let error = newer.preflight_export().await.unwrap_err().to_string();
    assert!(error.contains("schema version 99"), "{error}");
    write_entries(&newer.audit, "late", 2);
    newer.shutdown().await;
    assert_eq!(
        api.search("bxa-audit", json!({"match_all": {}}))
            .await
            .len(),
        25
    );
    assert!(stats(newer.audit.exporter().unwrap()).dropped >= 2);

    // A server of the other engine is refused.
    let other = if kind == "opensearch" {
        "elasticsearch"
    } else {
        "opensearch"
    };
    let wrong = start_ctx(config(
        dir,
        "w",
        "ENG-W",
        &section(other, url, "bxw-", auth_lines),
    ));
    let error = wrong.preflight_export().await.unwrap_err().to_string();
    assert!(error.contains("search.kind"), "{error}");
    wrong.shutdown().await;
    assert!(!api.indices().await.iter().any(|n| n.starts_with("bxw-")));
}

async fn outage_suite(kind: &str, service: &Service, auth_lines: &str, api: &Api, dir: &Path) {
    let proxy = Proxy::bind().await;
    proxy.set_target(service.ports[0]);
    let url = format!("http://127.0.0.1:{}", proxy.port);
    let extra =
        format!("{}buffer = 40\n", section(kind, &url, "bxo-", auth_lines)).replace("3000", "700");
    let ctx = start_ctx(config(dir, "o", "ENG-O", &extra));
    ctx.preflight_export().await.unwrap();
    write_entries(&ctx.audit, "before", 5);
    eventually("the first records", Duration::from_secs(15), || async {
        (stats(ctx.audit.exporter().unwrap()).sent == 5).then_some(())
    })
    .await;

    proxy.set_down(true);
    let mut tag = 0;
    let worst = slowest(300, || {
        tag += 1;
        write_entries(&ctx.audit, &format!("down{tag}"), 1);
    });
    assert!(
        worst < Duration::from_millis(250),
        "a call took {worst:?} during the outage"
    );
    assert!(stats(ctx.audit.exporter().unwrap()).dropped > 0);
    let during = eventually("the failure to show", Duration::from_secs(20), || async {
        let s = stats(ctx.audit.exporter().unwrap());
        s.last_error.is_some().then_some(s)
    })
    .await;
    assert_eq!(during.state, "unreachable", "{during:?}");

    proxy.set_down(false);
    eventually("the backlog to drain", Duration::from_secs(60), || async {
        (stats(ctx.audit.exporter().unwrap()).queued == 0).then_some(())
    })
    .await;
    let marker = write_entries(&ctx.audit, "after", 4);
    ctx.shutdown().await;
    let stored = api.search("bxo-audit", json!({"match_all": {}})).await;
    let seqs: Vec<u64> = stored.iter().map(|d| d["seq"].as_u64().unwrap()).collect();
    for seq in marker {
        assert!(
            seqs.contains(&seq),
            "record {seq} did not arrive after the outage"
        );
    }
    assert_eq!(stats(ctx.audit.exporter().unwrap()).state, "ready");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn opensearch_without_security() {
    if !services::enabled("OpenSearch export") {
        return;
    }
    let Some(service) = start_opensearch(false).await else {
        return;
    };
    let url = format!("http://127.0.0.1:{}", service.ports[0]);
    let api = Api::new(url.clone(), Auth::None);
    let dir = tempfile::tempdir().unwrap();
    shared_suite("opensearch", &url, "", &api, dir.path()).await;
    outage_suite("opensearch", &service, "", &api, dir.path()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn opensearch_with_security_basic_auth_and_a_private_ca() {
    if !services::enabled("OpenSearch secured export") {
        return;
    }
    let Some(service) = start_opensearch(true).await else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let ca = service
        .exec(&["cat", "/usr/share/opensearch/config/root-ca.pem"])
        .expect("the demo root CA");
    std::fs::write(dir.path().join("ca.pem"), ca).unwrap();
    secret_file(dir.path(), "admin.pw", ADMIN_PASSWORD);
    secret_file(dir.path(), "wrong.pw", "Wrong-Pass-1234!");
    let url = format!("https://localhost:{}", service.ports[0]);
    let api = Api::new(url.clone(), Auth::Basic("admin", ADMIN_PASSWORD));
    // The security plugin answers 503 until it has initialised its index.
    eventually("the security plugin", Duration::from_secs(90), || async {
        let (status, _) = api
            .call(
                reqwest::Method::GET,
                "/_cluster/health?wait_for_status=yellow&timeout=5s",
                None,
            )
            .await;
        (status == 200).then_some(())
    })
    .await;
    let basic = |pw: &str| {
        format!("username = \"admin\"\npassword_file = \"{pw}\"\ntls_ca_file = \"ca.pem\"\n")
    };

    let ctx = start_ctx(config(
        dir.path(),
        "s",
        "ENG-S",
        &section("opensearch", &url, "bxs-", &basic("admin.pw")),
    ));
    ctx.preflight_export().await.unwrap();
    write_entries(&ctx.audit, "s", 6);
    ctx.shutdown().await;
    let after = stats(ctx.audit.exporter().unwrap());
    assert_eq!((after.sent, after.dropped), (6, 0), "{after:?}");
    let stored = api.search("bxs-audit", json!({"match_all": {}})).await;
    assert_eq!(stored.len(), 6);
    assert_chain(
        &stored
            .iter()
            .map(|d| {
                let mut r = d.as_object().unwrap().clone();
                for k in [
                    "engagement",
                    "operator",
                    "reason",
                    "action_class",
                    "trace_id",
                    "arguments_text",
                ] {
                    r.remove(k);
                }
                Value::Object(r)
            })
            .collect::<Vec<_>>(),
        6,
    );

    // A wrong password is reported without the password, and nothing is written.
    let wrong = start_ctx(config(
        dir.path(),
        "x",
        "ENG-X",
        &section("opensearch", &url, "bxx-", &basic("wrong.pw")),
    ));
    wrong.preflight_export().await.unwrap();
    let state = stats(wrong.audit.exporter().unwrap());
    assert_eq!(state.state, "unreachable", "{state:?}");
    let message = state.last_error.unwrap();
    assert!(
        message.contains("credentials") && !message.contains("Wrong-Pass"),
        "{message}"
    );
    wrong.shutdown().await;
    assert!(!api.indices().await.iter().any(|n| n.starts_with("bxx-")));

    // Without the private CA the certificate is not trusted.
    let no_ca = start_ctx(config(
        dir.path(),
        "y",
        "ENG-Y",
        &section(
            "opensearch",
            &url,
            "bxy-",
            "username = \"admin\"\npassword_file = \"admin.pw\"\n",
        ),
    ));
    no_ca.preflight_export().await.unwrap();
    assert_eq!(stats(no_ca.audit.exporter().unwrap()).state, "unreachable");
    no_ca.shutdown().await;
    assert!(!api.indices().await.iter().any(|n| n.starts_with("bxy-")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn elasticsearch_with_basic_auth_and_an_api_key() {
    if !services::enabled("Elasticsearch export") {
        return;
    }
    let Some(service) = start_elasticsearch().await else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let url = format!("http://127.0.0.1:{}", service.ports[0]);
    let api = Api::new(url.clone(), Auth::Basic("elastic", ADMIN_PASSWORD));
    secret_file(dir.path(), "elastic.pw", ADMIN_PASSWORD);
    let (status, key) = api
        .call(
            reqwest::Method::POST,
            "/_security/api_key",
            Some(json!({"name": "browserx-test"})),
        )
        .await;
    assert!(status < 300, "{key}");
    secret_file(dir.path(), "api.key", key["encoded"].as_str().unwrap());

    let basic = "username = \"elastic\"\npassword_file = \"elastic.pw\"\n";
    shared_suite("elasticsearch", &url, basic, &api, dir.path()).await;

    // The API key path: a separate namespace, same server.
    let by_key = start_ctx(config(
        dir.path(),
        "k",
        "ENG-K",
        &section(
            "elasticsearch",
            &url,
            "bxk-",
            "api_key_file = \"api.key\"\n",
        ),
    ));
    by_key.preflight_export().await.unwrap();
    write_entries(&by_key.audit, "k", 5);
    by_key.shutdown().await;
    assert_eq!(
        api.search("bxk-audit", json!({"match_all": {}}))
            .await
            .len(),
        5
    );

    // No credentials at all: refused, reported, nothing created.
    let anonymous = start_ctx(config(
        dir.path(),
        "z",
        "ENG-Z",
        &section("elasticsearch", &url, "bxz-", ""),
    ));
    anonymous.preflight_export().await.unwrap();
    let state = stats(anonymous.audit.exporter().unwrap());
    assert!(state.last_error.unwrap().contains("credentials"));
    anonymous.shutdown().await;
    assert!(!api.indices().await.iter().any(|n| n.starts_with("bxz-")));

    outage_suite("elasticsearch", &service, basic, &api, dir.path()).await;
}
