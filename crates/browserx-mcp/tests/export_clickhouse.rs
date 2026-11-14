#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The ClickHouse audit export sink against a real ClickHouse server (podman).

mod common;

use std::time::Duration;

use common::export_kit::{
    Proxy, assert_chain, config, eventually, local_records, secret_file, slowest, start_ctx, stats,
    write_entries,
};
use common::services::{self, Service, Spec};
use serde_json::Value;

const IMAGE: &str = "docker.io/clickhouse/clickhouse-server:latest@sha256:4f491abc44d9f4a1747c033c35ddd5bc385521305d85ca8251ba0824ff597035";
const USER: &str = "bxtest";
const PASSWORD: &str = "synthetic-clickhouse-password";

async fn start() -> Option<Service> {
    Service::start(
        &Spec {
            image: IMAGE,
            ports: &[8123],
            env: &[
                "CLICKHOUSE_USER=bxtest",
                "CLICKHOUSE_PASSWORD=synthetic-clickhouse-password",
                "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1",
            ],
            tmpfs: &["/var/lib/clickhouse"],
            command: &[],
            ready_within: Duration::from_secs(90),
        },
        |ports| async move {
            reqwest::get(format!("http://127.0.0.1:{}/ping", ports[0]))
                .await
                .is_ok_and(|r| r.status().is_success())
        },
    )
    .await
}

/// Runs `sql` (as the test user) and returns the response text.
async fn query(port: u16, sql: &str) -> String {
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .basic_auth(USER, Some(PASSWORD))
        .body(sql.to_owned())
        .send()
        .await
        .unwrap();
    let ok = response.status().is_success();
    let text = response.text().await.unwrap();
    assert!(ok, "query `{sql}` failed: {text}");
    text
}

fn section(dir: &std::path::Path, port: u16, database: &str) -> String {
    secret_file(dir, "ch.pw", PASSWORD);
    format!(
        "[analytics]\nurl = \"http://127.0.0.1:{port}\"\ndatabase = \"{database}\"\nuser = \"{USER}\"\npassword_file = \"ch.pw\"\nbatch_size = 10\nflush_interval_ms = 50\nrequest_timeout_ms = 2000\n"
    )
}

async fn raw_rows(port: u16, database: &str, engagement: &str) -> Vec<Value> {
    query(
        port,
        &format!(
            "SELECT raw FROM {database}.audit_v1 WHERE engagement = '{engagement}' ORDER BY seq FORMAT TSVRaw"
        ),
    )
    .await
    .lines()
    .map(|line| serde_json::from_str(line).unwrap())
    .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_arrive_with_chain_intact_in_separate_databases_and_foreign_data_survives() {
    if !services::enabled("ClickHouse export") {
        return;
    }
    let Some(service) = start().await else { return };
    let port = service.ports[0];
    // A database the sink must never touch.
    query(port, "CREATE DATABASE foreign_db").await;
    query(
        port,
        "CREATE TABLE foreign_db.keep (x UInt8) ENGINE = Memory",
    )
    .await;
    query(port, "INSERT INTO foreign_db.keep VALUES (1), (2), (3)").await;

    let dir = tempfile::tempdir().unwrap();
    let one = start_ctx(config(
        dir.path(),
        "one",
        "ENG-ONE",
        &section(dir.path(), port, "bx_one"),
    ));
    let two = start_ctx(config(
        dir.path(),
        "two",
        "ENG-TWO",
        &section(dir.path(), port, "bx_two"),
    ));
    one.preflight_export().await.unwrap();
    two.preflight_export().await.unwrap();

    write_entries(&one.audit, "one", 25);
    write_entries(&two.audit, "two", 7);
    one.shutdown().await;
    two.shutdown().await;

    // Every record arrived, byte for byte as written locally, and the chain verifies.
    let local = local_records(one.audit.path());
    let received = raw_rows(port, "bx_one", "ENG-ONE").await;
    assert_eq!(received, local);
    assert_chain(&received, 25);
    let received_two = raw_rows(port, "bx_two", "ENG-TWO").await;
    assert_eq!(received_two, local_records(two.audit.path()));
    assert_chain(&received_two, 7);

    // Typed and extracted columns.
    let typed = query(
        port,
        "SELECT count(), uniqExact(hash), min(seq), max(seq), any(operator), any(action_class) \
         FROM bx_one.audit_v1 WHERE reason = 'out_of_scope' AND outcome = 'refused' \
         AND tool IN ('open_page','click','snapshot') AND toYear(ts) >= 2026 FORMAT TSV",
    )
    .await;
    assert_eq!(typed.trim(), "12\t12\t2\t24\talice\tread");
    let args = query(
        port,
        "SELECT JSONExtractString(arguments, 'needle'), trace_id FROM bx_one.audit_v1 WHERE seq = 3 FORMAT TSV",
    )
    .await;
    assert_eq!(args.trim(), "zebra-one-2\ttrace-one-2");
    assert_eq!(
        query(
            port,
            "SELECT count() FROM bx_one.audit_v1 WHERE engagement = 'ENG-TWO'"
        )
        .await
        .trim(),
        "0"
    );

    // Nothing else was created or touched.
    let databases = query(
        port,
        "SELECT name FROM system.databases ORDER BY name FORMAT TSV",
    )
    .await;
    let names: Vec<&str> = databases.lines().collect();
    for expected in ["bx_one", "bx_two", "foreign_db"] {
        assert!(names.contains(&expected), "{names:?}");
    }
    assert_eq!(
        names
            .iter()
            .filter(|n| !n.starts_with("system")
                && !n.eq_ignore_ascii_case("information_schema")
                && **n != "default")
            .count(),
        3,
        "{names:?}"
    );
    assert_eq!(
        query(port, "SELECT sum(x) FROM foreign_db.keep")
            .await
            .trim(),
        "6"
    );
    assert_eq!(
        query(
            port,
            "SELECT name FROM system.tables WHERE database = 'bx_one' ORDER BY name FORMAT TSV"
        )
        .await
        .trim(),
        "audit_v1\nschema_migrations"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migrations_are_idempotent_and_a_newer_schema_is_refused() {
    if !services::enabled("ClickHouse migrations") {
        return;
    }
    let Some(service) = start().await else { return };
    let port = service.ports[0];
    let dir = tempfile::tempdir().unwrap();
    for round in 0..2 {
        let ctx = start_ctx(config(
            dir.path(),
            "m",
            "ENG-M",
            &section(dir.path(), port, "bx_mig"),
        ));
        ctx.preflight_export().await.unwrap();
        write_entries(&ctx.audit, &format!("m{round}"), 2);
        ctx.shutdown().await;
    }
    assert_eq!(
        query(port, "SELECT count() FROM bx_mig.schema_migrations")
            .await
            .trim(),
        "1"
    );
    assert_eq!(
        query(port, "SELECT count() FROM bx_mig.audit_v1")
            .await
            .trim(),
        "4"
    );

    query(
        port,
        "INSERT INTO bx_mig.schema_migrations (version, name) VALUES (99, 'from_the_future')",
    )
    .await;
    let ctx = start_ctx(config(
        dir.path(),
        "m",
        "ENG-M",
        &section(dir.path(), port, "bx_mig"),
    ));
    let error = ctx.preflight_export().await.unwrap_err().to_string();
    assert!(error.contains("schema version 99"), "{error}");
    assert_eq!(stats(ctx.audit.exporter().unwrap()).state, "refused");
    // The refused sink drops what it is given, counts it, and the tool path is unaffected.
    write_entries(&ctx.audit, "late", 3);
    ctx.shutdown().await;
    assert_eq!(
        query(port, "SELECT count() FROM bx_mig.audit_v1")
            .await
            .trim(),
        "4"
    );
    assert!(stats(ctx.audit.exporter().unwrap()).dropped >= 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_outage_never_slows_recording_drops_are_counted_and_export_resumes() {
    if !services::enabled("ClickHouse outage") {
        return;
    }
    let Some(service) = start().await else { return };
    let proxy = Proxy::bind().await;
    proxy.set_target(service.ports[0]);
    let dir = tempfile::tempdir().unwrap();
    let extra = format!(
        "{}buffer = 40\n",
        section(dir.path(), proxy.port, "bx_outage")
    )
    .replace("request_timeout_ms = 2000", "request_timeout_ms = 500");
    let ctx = start_ctx(config(dir.path(), "o", "ENG-O", &extra));
    ctx.preflight_export().await.unwrap();
    write_entries(&ctx.audit, "before", 5);
    eventually("the first records", Duration::from_secs(10), || async {
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
    let during = eventually("the failure to show", Duration::from_secs(15), || async {
        let s = stats(ctx.audit.exporter().unwrap());
        s.last_error.is_some().then_some(s)
    })
    .await;
    assert!(during.dropped > 0, "{during:?}");
    assert!(during.queued <= 40 + 10, "{during:?}");
    assert_eq!(during.state, "unreachable", "{during:?}");
    let message = during.last_error.unwrap();
    assert!(!message.contains(PASSWORD));

    proxy.set_down(false);
    // The backlog drains first; records offered into a full queue would be dropped.
    eventually("the backlog to drain", Duration::from_secs(40), || async {
        (stats(ctx.audit.exporter().unwrap()).queued == 0).then_some(())
    })
    .await;
    let marker = write_entries(&ctx.audit, "after", 4);
    let last = *marker.last().unwrap();
    eventually("export to resume", Duration::from_secs(40), || async {
        let count = query(
            service.ports[0],
            &format!("SELECT count() FROM bx_outage.audit_v1 WHERE seq = {last}"),
        )
        .await;
        (count.trim() != "0").then_some(())
    })
    .await;
    ctx.shutdown().await;
    let after = stats(ctx.audit.exporter().unwrap());
    assert_eq!(after.state, "ready", "{after:?}");
    assert!(after.sent >= 9, "{after:?}");
    // Whatever arrived is a prefix-correct subset: every stored hash is a real local hash.
    let local: std::collections::BTreeSet<String> = local_records(ctx.audit.path())
        .iter()
        .map(|r| r["hash"].as_str().unwrap().to_owned())
        .collect();
    let stored = query(
        service.ports[0],
        "SELECT hash FROM bx_outage.audit_v1 FORMAT TSV",
    )
    .await;
    assert!(stored.lines().all(|h| local.contains(h)));
}
