//! Deterministic assessment of a BrowserX pool: a verdict and graded checks with evidence and
//! remediation. This is the code path behind `pool_status`, `assess` and `diagnose`; a model
//! can add a narrative on top, but never changes a finding.

use serde::Serialize;
use serde_json::{Value, json};

use crate::metrics::PoolSnapshot;

/// How bad a check is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    /// Healthy.
    Pass,
    /// Needs attention.
    Warn,
    /// Broken or at risk.
    Fail,
}

/// One graded finding.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Stable identifier.
    pub id: &'static str,
    /// Grade.
    pub status: Grade,
    /// One sentence.
    pub summary: String,
    /// The numbers behind the grade.
    pub evidence: Value,
    /// What to do, when the check is not a pass.
    pub remediation: Option<String>,
}

/// What the operations listener said about readiness.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Readiness {
    /// `/healthz` answered 200.
    pub live: Option<bool>,
    /// `/readyz` answered ready.
    pub ready: Option<bool>,
    /// Reasons `/readyz` gave when not ready.
    pub problems: Vec<String>,
    /// `/readyz` round trip in milliseconds.
    pub latency_ms: Option<u64>,
    /// Transport error, when the listener could not be reached.
    pub error: Option<String>,
}

impl Readiness {
    /// Builds readiness from the two probes' answers.
    #[must_use]
    pub fn from_probes(
        health: Option<&crate::backend::Probe>,
        ready: Option<&crate::backend::Probe>,
    ) -> Self {
        let mut out = Self {
            live: health.map(|p| p.status == Some(200)),
            ..Self::default()
        };
        if let Some(probe) = ready {
            out.latency_ms = Some(probe.latency_ms);
            out.error.clone_from(&probe.error);
            if probe.error.is_none() {
                out.ready = Some(probe.status == Some(200));
                if let Ok(body) = serde_json::from_str::<Value>(&probe.body) {
                    out.problems = body
                        .get("problems")
                        .and_then(Value::as_array)
                        .map(|list| {
                            list.iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default();
                }
            }
        }
        out
    }
}

/// The overall state of the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Nothing needs attention.
    Ok,
    /// Admissions are queueing or being refused for lack of capacity.
    Saturated,
    /// Something is broken: not ready, recoveries lost, snapshots failing, no metrics.
    Degraded,
}

/// Inputs of the assessment. Missing inputs are reported, never guessed.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    /// Readiness from the operations listener, when it is configured.
    pub readiness: Option<&'a Readiness>,
    /// Pool metrics, when a scrape succeeded.
    pub pool: Option<&'a PoolSnapshot>,
    /// Why metrics are missing.
    pub metrics_error: Option<&'a str>,
}

fn count(map: &std::collections::BTreeMap<String, u64>, key: &str) -> u64 {
    map.get(key).copied().unwrap_or(0)
}

fn unknown(id: &'static str, what: &str) -> Check {
    Check {
        id,
        status: Grade::Warn,
        summary: format!("{what} is unknown: no metrics are available"),
        evidence: json!({}),
        remediation: Some(
            "Set server.ops_url in the MCP configuration and check that the operations listener is reachable."
                .into(),
        ),
    }
}

/// The verdict and the reasons for it.
#[must_use]
pub fn verdict(inputs: &Inputs<'_>) -> (Verdict, Vec<String>) {
    let mut degraded = Vec::new();
    let mut saturated = Vec::new();
    if let Some(r) = inputs.readiness {
        if let Some(error) = &r.error {
            degraded.push(format!("the operations listener is unreachable: {error}"));
        } else if r.ready == Some(false) {
            degraded.push(format!("not ready: {}", r.problems.join("; ")));
        }
    }
    match inputs.pool {
        Some(pool) => {
            if count(&pool.recoveries, "lost") > 0 {
                degraded.push("a browser was lost and could not be recovered in the window".into());
            }
            if count(&pool.snapshots, "failed") > 0 {
                degraded.push("snapshots failed in the window".into());
            }
            if pool.queue_depth > 0 {
                saturated.push(format!(
                    "{} admissions are waiting for capacity",
                    pool.queue_depth
                ));
            }
            for result in ["queue_full", "timeout"] {
                if count(&pool.admissions, result) > 0 {
                    saturated.push(format!("admissions were refused ({result}) in the window"));
                }
            }
        }
        None => degraded.push(inputs.metrics_error.map_or_else(
            || "no metrics are available".to_owned(),
            |e| format!("no metrics: {e}"),
        )),
    }
    if !degraded.is_empty() {
        (Verdict::Degraded, degraded)
    } else if !saturated.is_empty() {
        (Verdict::Saturated, saturated)
    } else {
        (Verdict::Ok, Vec::new())
    }
}

/// The graded checks.
#[must_use]
pub fn checks(inputs: &Inputs<'_>) -> Vec<Check> {
    let mut out = vec![readiness_check(inputs.readiness)];
    let Some(pool) = inputs.pool else {
        for (id, what) in [
            ("queue_saturation", "Queue saturation"),
            ("recovery_rate", "Recovery rate"),
            ("lost_sessions", "Lost sessions"),
            ("snapshot_failures", "Snapshot failures"),
            ("egress_refusals", "Egress refusals"),
        ] {
            out.push(unknown(id, what));
        }
        return out;
    };
    out.push(queue_check(pool));
    out.push(recovery_check(pool));
    out.push(lost_check(pool));
    out.push(snapshot_check(pool));
    out.push(egress_check(pool));
    out
}

/// The worst grade among `checks`.
#[must_use]
pub fn overall(checks: &[Check]) -> Grade {
    checks.iter().map(|c| c.status).max().unwrap_or(Grade::Pass)
}

fn readiness_check(readiness: Option<&Readiness>) -> Check {
    let Some(r) = readiness else {
        return unknown("readiness", "Readiness");
    };
    let (status, summary, remediation) = if let Some(error) = &r.error {
        (
            Grade::Fail,
            format!("the operations listener is unreachable: {error}"),
            Some(
                "Check that the BrowserX server is running and server.ops_url is right.".to_owned(),
            ),
        )
    } else if r.ready == Some(true) {
        (Grade::Pass, "the server reports ready".to_owned(), None)
    } else {
        (
            Grade::Fail,
            format!("the server is not ready: {}", r.problems.join("; ")),
            Some(
                "Read the problems: a missing Chromium needs BROWSERX_CHROMIUM_PATH or a launch profile executable; \
                 `draining` means the server is shutting down."
                    .to_owned(),
            ),
        )
    };
    Check {
        id: "readiness",
        status,
        summary,
        evidence: json!({ "live": r.live, "ready": r.ready, "problems": r.problems, "latency_ms": r.latency_ms }),
        remediation,
    }
}

fn queue_check(pool: &PoolSnapshot) -> Check {
    let refused = count(&pool.admissions, "queue_full") + count(&pool.admissions, "timeout");
    let (status, summary, remediation) = if refused > 0 {
        (
            Grade::Fail,
            format!("{refused} admissions were refused for lack of capacity in the window"),
            Some(
                "Raise pool.max_browsers or pool.queue_capacity, release idle sessions sooner, or shorten session TTLs."
                    .to_owned(),
            ),
        )
    } else if pool.queue_depth > 0 {
        (
            Grade::Warn,
            format!("{} admissions are waiting for capacity", pool.queue_depth),
            Some("Watch queue_depth: if it stays above zero, add capacity.".to_owned()),
        )
    } else {
        (Grade::Pass, "no admissions are waiting".to_owned(), None)
    };
    Check {
        id: "queue_saturation",
        status,
        summary,
        evidence: json!({ "queue_depth": pool.queue_depth, "admissions": pool.admissions, "window_secs": pool.window_secs }),
        remediation,
    }
}

fn recovery_check(pool: &PoolSnapshot) -> Check {
    let lost = count(&pool.recoveries, "lost");
    let recovered: u64 = pool
        .recoveries
        .iter()
        .filter(|(outcome, _)| outcome.as_str() != "lost")
        .map(|(_, n)| *n)
        .sum();
    let (status, summary, remediation) = if lost > 0 {
        (
            Grade::Fail,
            format!("{lost} browsers were lost for good in the window"),
            Some(
                "Browsers are dying and recovery gave up: check the host's memory and the launch profile flags; \
                 `explain_session` on a lost session shows its reason."
                    .to_owned(),
            ),
        )
    } else if recovered >= 5 {
        (
            Grade::Fail,
            format!("{recovered} browser recoveries in the window: browsers keep crashing"),
            Some("Look at memory pressure, `/dev/shm` size and Chromium flags; compare the launch profiles.".to_owned()),
        )
    } else if recovered > 0 {
        (
            Grade::Warn,
            format!("{recovered} browser recoveries in the window"),
            Some(
                "A crash was recovered. `fresh_process` means state was lost; use snapshot or profile persistence for sessions that must survive."
                    .to_owned(),
            ),
        )
    } else {
        (Grade::Pass, "no recoveries in the window".to_owned(), None)
    };
    Check {
        id: "recovery_rate",
        status,
        summary,
        evidence: json!({ "recoveries": pool.recoveries, "window_secs": pool.window_secs }),
        remediation,
    }
}

fn lost_check(pool: &PoolSnapshot) -> Check {
    let lost = pool.sessions_in("lost");
    let (status, summary, remediation) = if lost > 0 {
        (
            Grade::Warn,
            format!("{lost} sessions are in the terminal `lost` state"),
            Some(
                "Lost sessions cannot be resumed. Use `explain_session` to see why, and create a new session; \
                 recovery = \"restore\" avoids losing sessions to a single crash."
                    .to_owned(),
            ),
        )
    } else {
        (Grade::Pass, "no lost sessions".to_owned(), None)
    };
    Check {
        id: "lost_sessions",
        status,
        summary,
        evidence: json!({ "lost": lost, "sessions": pool.sessions }),
        remediation,
    }
}

fn snapshot_check(pool: &PoolSnapshot) -> Check {
    let failed = count(&pool.snapshots, "failed");
    let stale = count(&pool.snapshots, "stale");
    let (status, summary, remediation) = if failed > 0 {
        (
            Grade::Fail,
            format!("{failed} snapshot attempts failed in the window"),
            Some(
                "Check the state directory (space, permissions) and the snapshot key file; snapshot sessions are not recoverable until snapshots succeed."
                    .to_owned(),
            ),
        )
    } else if stale > 0 {
        (
            Grade::Warn,
            format!("{stale} snapshots were discarded as stale in the window"),
            Some("Stale snapshots mean a handoff or recovery raced a snapshot; this is usually harmless.".to_owned()),
        )
    } else {
        (Grade::Pass, "no snapshot failures".to_owned(), None)
    };
    Check {
        id: "snapshot_failures",
        status,
        summary,
        evidence: json!({ "snapshots": pool.snapshots, "window_secs": pool.window_secs }),
        remediation,
    }
}

fn egress_check(pool: &PoolSnapshot) -> Check {
    let (status, summary, remediation) = if pool.egress_refused > 0 {
        (
            Grade::Warn,
            format!(
                "{} browser connections were refused by the egress policy in the window",
                pool.egress_refused
            ),
            Some(
                "The policy is doing its job when the target was internal; if the destination is intended, add it to egress.allow_cidrs."
                    .to_owned(),
            ),
        )
    } else {
        (Grade::Pass, "no egress refusals".to_owned(), None)
    };
    Check {
        id: "egress_refusals",
        status,
        summary,
        evidence: json!({ "refused": pool.egress_refused, "window_secs": pool.window_secs }),
        remediation,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::collections::BTreeMap;

    use super::*;

    fn ready() -> Readiness {
        Readiness {
            live: Some(true),
            ready: Some(true),
            ..Readiness::default()
        }
    }

    fn pool(f: impl FnOnce(&mut PoolSnapshot)) -> PoolSnapshot {
        let mut pool = PoolSnapshot::default();
        f(&mut pool);
        pool
    }

    fn run(readiness: &Readiness, pool: &PoolSnapshot) -> (Verdict, Grade, Vec<Check>) {
        let inputs = Inputs {
            readiness: Some(readiness),
            pool: Some(pool),
            metrics_error: None,
        };
        let checks = checks(&inputs);
        (verdict(&inputs).0, overall(&checks), checks)
    }

    fn grade(checks: &[Check], id: &str) -> Grade {
        checks.iter().find(|c| c.id == id).unwrap().status
    }

    #[test]
    fn healthy_pool_passes_everything() {
        let (verdict, overall, checks) = run(&ready(), &pool(|_| {}));
        assert_eq!(verdict, Verdict::Ok);
        assert_eq!(overall, Grade::Pass);
        assert_eq!(checks.len(), 6);
        assert!(checks.iter().all(|c| c.remediation.is_none()));
    }

    #[test]
    fn queueing_is_saturation_not_degradation() {
        let queued = pool(|p| p.queue_depth = 2);
        let (verdict, overall, checks) = run(&ready(), &queued);
        assert_eq!(verdict, Verdict::Saturated);
        assert_eq!(overall, Grade::Warn);
        assert_eq!(grade(&checks, "queue_saturation"), Grade::Warn);
        let refused = pool(|p| {
            p.admissions = BTreeMap::from([("queue_full".to_owned(), 3)]);
        });
        let (_, overall, checks) = run(&ready(), &refused);
        assert_eq!(overall, Grade::Fail);
        assert_eq!(grade(&checks, "queue_saturation"), Grade::Fail);
    }

    #[test]
    fn lost_recoveries_failing_snapshots_and_unreadiness_degrade() {
        let lost = pool(|p| p.recoveries = BTreeMap::from([("lost".to_owned(), 1)]));
        assert_eq!(run(&ready(), &lost).0, Verdict::Degraded);
        let snapshots = pool(|p| p.snapshots = BTreeMap::from([("failed".to_owned(), 1)]));
        let (verdict, _, checks) = run(&ready(), &snapshots);
        assert_eq!(verdict, Verdict::Degraded);
        assert_eq!(grade(&checks, "snapshot_failures"), Grade::Fail);
        let not_ready = Readiness {
            ready: Some(false),
            problems: vec!["draining".into()],
            ..Readiness::default()
        };
        let (verdict, overall, _) = run(&not_ready, &pool(|_| {}));
        assert_eq!((verdict, overall), (Verdict::Degraded, Grade::Fail));
    }

    #[test]
    fn recovery_volume_sets_the_grade() {
        let some = pool(|p| p.recoveries = BTreeMap::from([("fresh_process".to_owned(), 2)]));
        assert_eq!(grade(&run(&ready(), &some).2, "recovery_rate"), Grade::Warn);
        let many =
            pool(|p| p.recoveries = BTreeMap::from([("restored_from_profile".to_owned(), 5)]));
        assert_eq!(grade(&run(&ready(), &many).2, "recovery_rate"), Grade::Fail);
    }

    #[test]
    fn missing_metrics_are_reported_as_unknown_never_as_healthy() {
        let inputs = Inputs {
            readiness: None,
            pool: None,
            metrics_error: Some("connection refused"),
        };
        let checks = checks(&inputs);
        assert!(checks.iter().all(|c| c.status == Grade::Warn));
        let (verdict, reasons) = verdict(&inputs);
        assert_eq!(verdict, Verdict::Degraded);
        assert!(reasons[0].contains("connection refused"));
    }

    #[test]
    fn lost_sessions_and_egress_refusals_warn() {
        let p = pool(|p| {
            p.sessions = BTreeMap::from([("lost".to_owned(), 2)]);
            p.egress_refused = 4;
        });
        let (verdict, _, checks) = run(&ready(), &p);
        assert_eq!(verdict, Verdict::Ok);
        assert_eq!(grade(&checks, "lost_sessions"), Grade::Warn);
        assert_eq!(grade(&checks, "egress_refusals"), Grade::Warn);
    }
}
