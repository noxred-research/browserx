#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The RabbitMQ (AMQP 0-9-1) audit export sink against a real broker in podman.

mod common;

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use common::export_kit::{
    Proxy, assert_chain, config, eventually, local_records, secret_file, slowest, start_ctx, stats,
    write_entries,
};
use common::services::{self, Service, Spec};
use lapin::options::{
    BasicGetOptions, BasicPublishOptions, ExchangeDeclareOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::{BasicProperties, Channel, Connection, ConnectionProperties, ExchangeKind};
use serde_json::Value;

const IMAGE: &str = "docker.io/library/rabbitmq:4-management@sha256:753099a19b577c322117f793f864b3129cbba96d40317221a69d73976e3c843c";
const USER: &str = "bx";
const PASSWORD: &str = "synthetic-amqp-password";

/// True once the broker answers the AMQP protocol header with `connection.start`. A bare TCP
/// check is not enough: the published port accepts connections before the broker runs, and a
/// `rabbitmqctl` started that early breaks the broker's Erlang cookie.
async fn amqp_greets(port: u16) -> bool {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let attempt = async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .ok()?;
        stream.write_all(b"AMQP\x00\x00\x09\x01").await.ok()?;
        let mut head = [0_u8; 7];
        stream.read_exact(&mut head).await.ok()?;
        (head[0] == 1).then_some(())
    };
    tokio::time::timeout(Duration::from_secs(2), attempt)
        .await
        .is_ok_and(|ok| ok.is_some())
}

async fn start() -> Option<Service> {
    let service = Service::start(
        &Spec {
            image: IMAGE,
            ports: &[5672],
            env: &[],
            tmpfs: &[],
            command: &[],
            ready_within: Duration::from_secs(90),
        },
        |ports| async move { amqp_greets(ports[0]).await },
    )
    .await?;
    // Starting an Erlang node per `exec` is slow on a busy host and a call may time out after it
    // took effect: wait for the broker once, then retry, treating "already there" as done.
    let run = |args: &[&str]| {
        let mut command = vec!["rabbitmqctl"];
        command.extend_from_slice(args);
        service.exec(&command)
    };
    for _ in 0..40 {
        if run(&["await_startup", "--timeout", "30"]).is_some() {
            break;
        }
    }
    let ctl = |args: &[&str], list: Option<(&str, &str)>| {
        for _ in 0..20 {
            if run(args).is_some() {
                return;
            }
            if let Some((listing, name)) = list
                && run(&[listing, "-q"]).is_some_and(|out| {
                    out.lines()
                        .any(|l| l.split_whitespace().next() == Some(name))
                })
            {
                return;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        let why = std::process::Command::new("podman")
            .args(["exec", service.name(), "rabbitmqctl"])
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&[o.stdout, o.stderr].concat()).into_owned())
            .unwrap_or_default();
        panic!("rabbitmqctl {args:?} failed: {why}");
    };
    ctl(&["add_user", USER, PASSWORD], Some(("list_users", USER)));
    for vhost in ["bxv1", "bxv2"] {
        ctl(&["add_vhost", vhost], Some(("list_vhosts", vhost)));
        ctl(
            &["set_permissions", "-p", vhost, USER, ".*", ".*", ".*"],
            None,
        );
    }
    ctl(&["add_vhost", "nope"], Some(("list_vhosts", "nope")));
    Some(service)
}

async fn connect(port: u16, vhost: &str) -> (Connection, Channel) {
    let connection = Connection::connect(
        &format!("amqp://{USER}:{PASSWORD}@127.0.0.1:{port}/{vhost}"),
        ConnectionProperties::default(),
    )
    .await
    .unwrap();
    let channel = connection.create_channel().await.unwrap();
    (connection, channel)
}

async fn bound_queue(channel: &Channel, queue: &str, exchange: &str) {
    channel
        .queue_declare(
            queue.into(),
            QueueDeclareOptions {
                durable: true,
                ..QueueDeclareOptions::default()
            },
            Default::default(),
        )
        .await
        .unwrap();
    channel
        .queue_bind(
            queue.into(),
            exchange.into(),
            "#".into(),
            QueueBindOptions::default(),
            Default::default(),
        )
        .await
        .unwrap();
}

/// Takes `count` messages from `queue`: (body, routing key, message id).
async fn take(channel: &Channel, queue: &str, count: usize) -> Vec<(Value, String, String)> {
    take_within(channel, queue, count, Duration::from_secs(30)).await
}

async fn take_within(
    channel: &Channel,
    queue: &str,
    count: usize,
    wait: Duration,
) -> Vec<(Value, String, String)> {
    let mut out = Vec::new();
    let deadline = Instant::now() + wait;
    while out.len() < count && Instant::now() < deadline {
        match channel
            .basic_get(queue.into(), BasicGetOptions { no_ack: true })
            .await
            .unwrap()
        {
            Some(message) => out.push((
                serde_json::from_slice(&message.delivery.data).unwrap(),
                message.delivery.routing_key.to_string(),
                message
                    .delivery
                    .properties
                    .message_id()
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
            )),
            None => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    out
}

fn section(dir: &std::path::Path, port: u16, vhost: &str, prefix: &str) -> String {
    secret_file(dir, "amqp.pw", PASSWORD);
    format!(
        "[events]\nkind = \"amqp\"\nurl = \"amqp://127.0.0.1:{port}\"\nusername = \"{USER}\"\npassword_file = \"amqp.pw\"\nvhost = \"{vhost}\"\nexchange_prefix = \"{prefix}\"\nbatch_size = 10\nflush_interval_ms = 50\nrequest_timeout_ms = 3000\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_are_confirmed_routed_by_tool_and_namespaces_and_foreign_objects_stay_separate() {
    if !services::enabled("RabbitMQ export") {
        return;
    }
    let Some(service) = start().await else { return };
    let port = service.ports[0];
    let dir = tempfile::tempdir().unwrap();

    // A foreign exchange and queue with a message in the first vhost.
    let (_c1, ch1) = connect(port, "bxv1").await;
    ch1.exchange_declare(
        "foreign.ex".into(),
        ExchangeKind::Direct,
        ExchangeDeclareOptions {
            durable: true,
            ..ExchangeDeclareOptions::default()
        },
        Default::default(),
    )
    .await
    .unwrap();
    ch1.queue_declare(
        "foreign.q".into(),
        QueueDeclareOptions {
            durable: true,
            ..Default::default()
        },
        Default::default(),
    )
    .await
    .unwrap();
    ch1.queue_bind(
        "foreign.q".into(),
        "foreign.ex".into(),
        "k".into(),
        QueueBindOptions::default(),
        Default::default(),
    )
    .await
    .unwrap();
    ch1.basic_publish(
        "foreign.ex".into(),
        "k".into(),
        BasicPublishOptions::default(),
        b"not ours",
        BasicProperties::default(),
    )
    .await
    .unwrap()
    .await
    .unwrap();

    let a = start_ctx(config(
        dir.path(),
        "a",
        "ENG-A",
        &section(dir.path(), port, "bxv1", "browserx."),
    ));
    let b = start_ctx(config(
        dir.path(),
        "b",
        "ENG-B",
        &section(dir.path(), port, "bxv2", "browserx."),
    ));
    let c = start_ctx(config(
        dir.path(),
        "c",
        "ENG-C",
        &section(dir.path(), port, "bxv1", "other."),
    ));
    let nope = start_ctx(config(
        dir.path(),
        "n",
        "ENG-N",
        &section(dir.path(), port, "nope", "browserx."),
    ));
    for ctx in [&a, &b, &c, &nope] {
        ctx.preflight_export().await.unwrap();
    }
    let (_c2, ch2) = connect(port, "bxv2").await;
    bound_queue(&ch1, "qa", "browserx.audit").await;
    bound_queue(&ch1, "qc", "other.audit").await;
    bound_queue(&ch2, "qb", "browserx.audit").await;

    write_entries(&a.audit, "a", 24);
    write_entries(&b.audit, "b", 6);
    write_entries(&c.audit, "c", 5);
    write_entries(&nope.audit, "n", 3);
    for ctx in [&a, &b, &c, &nope] {
        ctx.shutdown().await;
    }

    let got_a = take(&ch1, "qa", 24).await;
    let values: Vec<Value> = got_a.iter().map(|m| m.0.clone()).collect();
    assert_eq!(values, local_records(a.audit.path()));
    assert_chain(&values, 24);
    for (value, routing_key, message_id) in &got_a {
        assert_eq!(routing_key, value["tool"].as_str().unwrap());
        assert_eq!(message_id, value["hash"].as_str().unwrap());
    }
    assert_eq!(
        take_within(&ch1, "qa", 1, Duration::from_secs(1))
            .await
            .len(),
        0,
        "nothing from another namespace"
    );
    let got_b = take(&ch2, "qb", 6).await;
    assert_eq!(
        got_b.iter().map(|m| m.0.clone()).collect::<Vec<_>>(),
        local_records(b.audit.path())
    );
    assert_eq!(
        take_within(&ch2, "qb", 1, Duration::from_secs(1))
            .await
            .len(),
        0
    );
    let got_c = take(&ch1, "qc", 5).await;
    assert_eq!(
        got_c.iter().map(|m| m.0.clone()).collect::<Vec<_>>(),
        local_records(c.audit.path())
    );

    // No permission in the `nope` vhost: nothing was declared there, and the sink says why.
    let refused = stats(nope.audit.exporter().unwrap());
    assert_eq!(refused.state, "unreachable", "{refused:?}");
    assert!(refused.dropped >= 3, "{refused:?}");
    assert!(!refused.last_error.unwrap().contains(PASSWORD));
    let exchanges = service
        .exec(&[
            "rabbitmqctl",
            "list_exchanges",
            "-p",
            "nope",
            "name",
            "--quiet",
        ])
        .unwrap();
    assert!(!exchanges.contains("browserx.audit"), "{exchanges}");

    // The foreign exchange and its queue were not touched: the one raw message is still there.
    let (_c3, ch3) = connect(port, "bxv1").await;
    ch3.exchange_declare(
        "foreign.ex".into(),
        ExchangeKind::Direct,
        ExchangeDeclareOptions {
            passive: true,
            ..ExchangeDeclareOptions::default()
        },
        Default::default(),
    )
    .await
    .unwrap();
    let queue = ch3
        .queue_declare(
            "foreign.q".into(),
            QueueDeclareOptions {
                passive: true,
                ..QueueDeclareOptions::default()
            },
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(queue.message_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_outage_never_slows_recording_drops_are_counted_and_export_resumes() {
    if !services::enabled("RabbitMQ outage") {
        return;
    }
    let Some(service) = start().await else { return };
    let proxy = Proxy::bind().await;
    proxy.set_target(service.ports[0]);
    let dir = tempfile::tempdir().unwrap();
    let extra = format!(
        "{}buffer = 40\n",
        section(dir.path(), proxy.port, "bxv1", "browserx.")
    )
    .replace("3000", "700");
    let ctx = start_ctx(config(dir.path(), "o", "ENG-O", &extra));
    ctx.preflight_export().await.unwrap();
    let (_c, channel) = connect(service.ports[0], "bxv1").await;
    bound_queue(&channel, "q", "browserx.audit").await;
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
    let sent = stats(ctx.audit.exporter().unwrap()).sent as usize;
    let got = take(&channel, "q", sent).await;
    let seqs: BTreeSet<u64> = got.iter().map(|m| m.0["seq"].as_u64().unwrap()).collect();
    for seq in marker {
        assert!(
            seqs.contains(&seq),
            "record {seq} did not arrive after the outage"
        );
    }
    assert_eq!(stats(ctx.audit.exporter().unwrap()).state, "ready");
}
