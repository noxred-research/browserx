#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The Kafka audit export sink against a real single-node Kafka (KRaft) in podman.

mod common;

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use common::export_kit::{
    Proxy, assert_chain, config, eventually, local_records, secret_file, slowest, start_ctx, stats,
    write_entries,
};
use common::services::{self, Service, Spec};
use rskafka::client::ClientBuilder;
use rskafka::client::partition::{OffsetAt, UnknownTopicHandling};
use serde_json::Value;

const IMAGE: &str = "docker.io/apache/kafka:latest@sha256:77e3df9054047a88b520d0cc46e16696d3b22022e1d580aeccd2632df6532837";
const KAFKA_BIN: &str = "/opt/kafka/bin/kafka-topics.sh";
const SASL_USER: &str = "bx";
const SASL_PASSWORD: &str = "synthetic-kafka-password";

/// A broker whose advertised addresses are the test's loopback proxies.
struct Broker {
    service: Service,
    plain: Proxy,
    sasl: Proxy,
}

async fn start() -> Option<Broker> {
    let plain = Proxy::bind().await;
    let sasl = Proxy::bind().await;
    let advertised = format!(
        "KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://127.0.0.1:{},INTERNAL://localhost:9094,SASL://127.0.0.1:{}",
        plain.port, sasl.port
    );
    let jaas = format!(
        "KAFKA_LISTENER_NAME_SASL_PLAIN_SASL_JAAS_CONFIG=org.apache.kafka.common.security.plain.PlainLoginModule required user_{SASL_USER}=\"{SASL_PASSWORD}\";"
    );
    let service = Service::start(
        &Spec {
            image: IMAGE,
            ports: &[9092, 9095],
            env: &[
                "KAFKA_NODE_ID=1",
                "KAFKA_PROCESS_ROLES=broker,controller",
                "KAFKA_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093,INTERNAL://:9094,SASL://:9095",
                &advertised,
                "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT,SASL:SASL_PLAINTEXT",
                "KAFKA_INTER_BROKER_LISTENER_NAME=INTERNAL",
                "KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER",
                "KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093",
                "KAFKA_SASL_ENABLED_MECHANISMS=PLAIN",
                &jaas,
                "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1",
                "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1",
                "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1",
                "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0",
                "KAFKA_AUTO_CREATE_TOPICS_ENABLE=false",
            ],
            tmpfs: &["/var/lib/kafka/data", "/tmp"],
            command: &[],
            ready_within: Duration::from_secs(60),
        },
        |ports| async move { services::tcp_open(ports[0]).await },
    )
    .await?;
    plain.set_target(service.ports[0]);
    sasl.set_target(service.ports[1]);
    let deadline = Instant::now() + Duration::from_secs(90);
    while service
        .exec(&[KAFKA_BIN, "--bootstrap-server", "localhost:9094", "--list"])
        .is_none()
    {
        assert!(Instant::now() < deadline, "Kafka did not start");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Some(Broker {
        service,
        plain,
        sasl,
    })
}

fn create_topic(broker: &Broker, topic: &str, partitions: u32) {
    let partitions = partitions.to_string();
    broker
        .service
        .exec(&[
            KAFKA_BIN,
            "--bootstrap-server",
            "localhost:9094",
            "--create",
            "--topic",
            topic,
            "--partitions",
            &partitions,
        ])
        .unwrap_or_else(|| panic!("cannot create topic {topic}"));
}

async fn client(port: u16) -> rskafka::client::Client {
    ClientBuilder::new(vec![format!("127.0.0.1:{port}")])
        .build()
        .await
        .unwrap()
}

/// Every record of `topic` as (value, key, headers), over all partitions.
async fn consume(port: u16, topic: &str) -> Vec<(Value, String, Vec<(String, String)>)> {
    let client = client(port).await;
    let partitions = client
        .list_topics()
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.name == topic)
        .unwrap_or_else(|| panic!("topic {topic} is missing"))
        .partitions;
    let mut out = Vec::new();
    for partition in partitions {
        let pc = client
            .partition_client(topic, partition, UnknownTopicHandling::Retry)
            .await
            .unwrap();
        let end = pc.get_offset(OffsetAt::Latest).await.unwrap();
        let mut offset = 0;
        while offset < end {
            let (records, _) = pc.fetch_records(offset, 1..10_000_000, 1000).await.unwrap();
            for r in records {
                offset = r.offset + 1;
                let value: Value =
                    serde_json::from_slice(r.record.value.as_deref().unwrap()).unwrap();
                let key = String::from_utf8(r.record.key.unwrap()).unwrap();
                let headers = r
                    .record
                    .headers
                    .into_iter()
                    .map(|(k, v)| (k, String::from_utf8(v).unwrap()))
                    .collect();
                out.push((value, key, headers));
            }
        }
    }
    out
}

async fn high_watermark(port: u16, topic: &str) -> i64 {
    let client = client(port).await;
    client
        .partition_client(topic, 0, UnknownTopicHandling::Retry)
        .await
        .unwrap()
        .get_offset(OffsetAt::Latest)
        .await
        .unwrap()
}

fn section(brokers: u16, prefix: &str) -> String {
    format!(
        "[events]\nkind = \"kafka\"\nbrokers = [\"127.0.0.1:{brokers}\"]\ntopic_prefix = \"{prefix}\"\nbatch_size = 10\nflush_interval_ms = 50\nrequest_timeout_ms = 3000\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_arrive_by_key_with_chain_intact_in_separate_topics_and_topics_are_never_created() {
    if !services::enabled("Kafka export") {
        return;
    }
    let Some(broker) = start().await else { return };
    create_topic(&broker, "browserx.audit", 3);
    create_topic(&broker, "other.audit", 2);
    create_topic(&broker, "foreign.topic", 1);
    let port = broker.plain.port;
    let foreign = client(port)
        .await
        .partition_client("foreign.topic", 0, UnknownTopicHandling::Retry)
        .await
        .unwrap();
    foreign
        .produce(
            vec![rskafka::record::Record {
                key: None,
                value: Some(b"not ours".to_vec()),
                headers: Default::default(),
                timestamp: rskafka::chrono::DateTime::from_timestamp_millis(1_700_000_000_000)
                    .unwrap(),
            }],
            rskafka::client::partition::Compression::NoCompression,
        )
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let one = start_ctx(config(
        dir.path(),
        "one",
        "ENG-ONE",
        &section(port, "browserx."),
    ));
    let two = start_ctx(config(
        dir.path(),
        "two",
        "ENG-TWO",
        &section(port, "other."),
    ));
    let ghost = start_ctx(config(
        dir.path(),
        "ghost",
        "ENG-G",
        &section(port, "ghost."),
    ));
    one.preflight_export().await.unwrap();
    two.preflight_export().await.unwrap();
    ghost.preflight_export().await.unwrap();
    write_entries(&one.audit, "one", 30);
    write_entries(&two.audit, "two", 9);
    write_entries(&ghost.audit, "ghost", 2);
    one.shutdown().await;
    two.shutdown().await;

    let received = consume(port, "browserx.audit").await;
    let values: Vec<Value> = received.iter().map(|r| r.0.clone()).collect();
    let mut sorted = values.clone();
    sorted.sort_by_key(|v| v["seq"].as_u64().unwrap());
    assert_eq!(sorted, local_records(one.audit.path()));
    assert_chain(&values, 30);
    // One engagement, one key, one partition; the headers carry the dedupe pair.
    assert!(received.iter().all(|r| r.1 == "ENG-ONE"));
    for (value, _, headers) in &received {
        let get = |name: &str| headers.iter().find(|h| h.0 == name).map(|h| h.1.clone());
        assert_eq!(get("audit-seq"), Some(value["seq"].to_string()));
        assert_eq!(get("audit-hash").as_deref(), value["hash"].as_str());
    }
    let other = consume(port, "other.audit").await;
    assert_eq!(other.len(), 9);
    assert!(other.iter().all(|r| r.1 == "ENG-TWO"));
    assert_chain(&other.iter().map(|r| r.0.clone()).collect::<Vec<_>>(), 9);

    // Topics are never created; a foreign topic is untouched.
    let ghost_stats = stats(ghost.audit.exporter().unwrap());
    assert_eq!(ghost_stats.state, "unreachable");
    assert!(ghost_stats.last_error.unwrap().contains("does not exist"));
    ghost.shutdown().await;
    let topics: BTreeSet<String> = client(port)
        .await
        .list_topics()
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert_eq!(
        topics,
        ["browserx.audit", "foreign.topic", "other.audit"]
            .map(str::to_owned)
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(high_watermark(port, "foreign.topic").await, 1);
    // A retried partial batch cannot reorder or lose: exactly 30 and 9, no extras.
    assert_eq!(values.len(), 30);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sasl_plain_authenticates_and_a_wrong_password_does_not() {
    if !services::enabled("Kafka SASL export") {
        return;
    }
    let Some(broker) = start().await else { return };
    create_topic(&broker, "browserx.audit", 1);
    let dir = tempfile::tempdir().unwrap();
    secret_file(dir.path(), "good.pw", SASL_PASSWORD);
    secret_file(dir.path(), "bad.pw", "wrong-password-value");
    let sasl = |pw: &str| {
        format!(
            "{}allow_plaintext = true\n[events.sasl]\nmechanism = \"plain\"\nusername = \"{SASL_USER}\"\npassword_file = \"{pw}\"\n",
            section(broker.sasl.port, "browserx.")
        )
    };
    let good = start_ctx(config(dir.path(), "good", "ENG-S", &sasl("good.pw")));
    good.preflight_export().await.unwrap();
    write_entries(&good.audit, "s", 5);
    good.shutdown().await;
    assert_eq!(consume(broker.plain.port, "browserx.audit").await.len(), 5);

    let bad = start_ctx(config(dir.path(), "bad", "ENG-B", &sasl("bad.pw")));
    bad.preflight_export().await.unwrap();
    let state = stats(bad.audit.exporter().unwrap());
    assert_eq!(state.state, "unreachable", "{state:?}");
    let message = state.last_error.unwrap();
    assert!(!message.contains("wrong-password-value") && !message.contains(SASL_PASSWORD));
    write_entries(&bad.audit, "b", 3);
    bad.shutdown().await;
    assert_eq!(consume(broker.plain.port, "browserx.audit").await.len(), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_outage_never_slows_recording_drops_are_counted_and_export_resumes() {
    if !services::enabled("Kafka outage") {
        return;
    }
    let Some(broker) = start().await else { return };
    create_topic(&broker, "browserx.audit", 1);
    let dir = tempfile::tempdir().unwrap();
    let ctx = start_ctx(config(
        dir.path(),
        "o",
        "ENG-O",
        &format!("{}buffer = 40\n", section(broker.plain.port, "browserx.")).replace("3000", "700"),
    ));
    ctx.preflight_export().await.unwrap();
    write_entries(&ctx.audit, "before", 5);
    eventually("the first records", Duration::from_secs(15), || async {
        (stats(ctx.audit.exporter().unwrap()).sent == 5).then_some(())
    })
    .await;

    broker.plain.set_down(true);
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
    let during = eventually("the failure to show", Duration::from_secs(15), || async {
        let s = stats(ctx.audit.exporter().unwrap());
        s.last_error.is_some().then_some(s)
    })
    .await;
    assert_eq!(during.state, "unreachable", "{during:?}");

    broker.plain.set_down(false);
    eventually("the backlog to drain", Duration::from_secs(60), || async {
        (stats(ctx.audit.exporter().unwrap()).queued == 0).then_some(())
    })
    .await;
    let marker = write_entries(&ctx.audit, "after", 4);
    ctx.shutdown().await;
    let received = consume(broker.plain.port, "browserx.audit").await;
    let seqs: BTreeSet<u64> = received
        .iter()
        .map(|r| r.0["seq"].as_u64().unwrap())
        .collect();
    for seq in marker {
        assert!(
            seqs.contains(&seq),
            "record {seq} did not arrive after the outage"
        );
    }
    assert_eq!(stats(ctx.audit.exporter().unwrap()).state, "ready");
}
