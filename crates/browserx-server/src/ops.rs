//! Operations listener: liveness, readiness and Prometheus metrics.

use std::fmt::Write as _;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use browserx_pool::MetricsSnapshot;
use serde_json::json;

use crate::api::AppState;

async fn healthz() -> &'static str {
    "ok\n"
}

async fn readyz(State(app): State<AppState>) -> Response {
    let mut problems: Vec<String> = Vec::new();
    if app.pool().is_draining() {
        problems.push("draining".into());
    }
    if let Err(e) = app.pool().ping_store().await {
        problems.push(format!("lease store unreachable: {e}"));
    }
    let profiles = app.pool().launch_profiles();
    if !profiles.contains(&app.inner.default_launch_profile) {
        problems.push(format!(
            "default launch profile `{}` is not available",
            app.inner.default_launch_profile
        ));
    }
    if let Err(why) = (app.inner.ready)() {
        problems.push(why);
    }
    if problems.is_empty() {
        (StatusCode::OK, axum::Json(json!({ "ready": true }))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({ "ready": false, "problems": problems })),
        )
            .into_response()
    }
}

async fn metrics(State(app): State<AppState>) -> Response {
    let text = render_metrics(&app.pool().metrics().await);
    let mut response = text.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

/// Router of the operations listener.
pub fn ops_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
}

fn family(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// Renders the Prometheus text exposition format.
#[must_use]
pub fn render_metrics(m: &MetricsSnapshot) -> String {
    let mut out = String::with_capacity(2048);
    family(
        &mut out,
        "browserx_sessions",
        "Sessions by lifecycle status (terminal ones until purged).",
        "gauge",
    );
    for (status, n) in &m.sessions {
        let _ = writeln!(out, "browserx_sessions{{status=\"{status}\"}} {n}");
    }
    family(
        &mut out,
        "browserx_browsers",
        "Running browser processes by isolation.",
        "gauge",
    );
    for (isolation, n) in &m.browsers {
        let _ = writeln!(out, "browserx_browsers{{isolation=\"{isolation}\"}} {n}");
    }
    family(
        &mut out,
        "browserx_admissions_total",
        "Session admissions by result.",
        "counter",
    );
    for (result, n) in &m.admissions {
        let _ = writeln!(out, "browserx_admissions_total{{result=\"{result}\"}} {n}");
    }
    family(
        &mut out,
        "browserx_queue_depth",
        "Admissions waiting for capacity.",
        "gauge",
    );
    let _ = writeln!(out, "browserx_queue_depth {}", m.queue_depth);
    family(
        &mut out,
        "browserx_recoveries_total",
        "Browser recoveries by outcome.",
        "counter",
    );
    for (outcome, n) in &m.recoveries {
        let _ = writeln!(
            out,
            "browserx_recoveries_total{{outcome=\"{outcome}\"}} {n}"
        );
    }
    family(
        &mut out,
        "browserx_launch_seconds",
        "Browser launch latency.",
        "histogram",
    );
    let h = &m.launch_seconds;
    for (bound, cumulative) in h.bounds.iter().zip(&h.cumulative) {
        let _ = writeln!(
            out,
            "browserx_launch_seconds_bucket{{le=\"{bound}\"}} {cumulative}"
        );
    }
    let _ = writeln!(
        out,
        "browserx_launch_seconds_bucket{{le=\"+Inf\"}} {}",
        h.count
    );
    let _ = writeln!(out, "browserx_launch_seconds_sum {}", h.sum);
    let _ = writeln!(out, "browserx_launch_seconds_count {}", h.count);
    family(
        &mut out,
        "browserx_relay_connections",
        "Open CDP relay connections.",
        "gauge",
    );
    let _ = writeln!(out, "browserx_relay_connections {}", m.relay_connections);
    family(
        &mut out,
        "browserx_snapshots_total",
        "State snapshot attempts by result.",
        "counter",
    );
    for (result, n) in &m.snapshots {
        let _ = writeln!(out, "browserx_snapshots_total{{result=\"{result}\"}} {n}");
    }
    family(
        &mut out,
        "browserx_egress_refused_total",
        "Browser connections refused by the egress policy.",
        "counter",
    );
    let _ = writeln!(out, "browserx_egress_refused_total {}", m.egress_refused);
    out
}
