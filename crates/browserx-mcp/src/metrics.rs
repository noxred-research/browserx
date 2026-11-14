//! Prometheus text parsing and the background sampler that turns counters into windowed rates.
//!
//! The BrowserX operations listener exposes counters (`browserx_admissions_total`,
//! `browserx_recoveries_total`, ...) and gauges (`browserx_sessions`, `browserx_queue_depth`).
//! A single scrape cannot say whether recoveries are happening *now*, so the sampler keeps a
//! bounded ring of scrapes and differences the newest against the oldest one inside the
//! requested window.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::backend::Backend;

/// Scrapes kept in memory.
const MAX_SAMPLES: usize = 256;
/// Longest window a caller may ask for, in seconds.
pub const MAX_WINDOW_SECS: u64 = 3600;

/// One parsed series.
#[derive(Debug, Clone, PartialEq)]
struct Series {
    name: String,
    labels: Vec<(String, String)>,
    value: f64,
}

/// The series of one scrape.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MetricSet {
    series: Vec<Series>,
}

fn parse_labels(text: &str) -> Vec<(String, String)> {
    let mut labels = Vec::new();
    let mut rest = text;
    while let Some((key, after)) = rest.split_once("=\"") {
        let mut value = String::new();
        let mut chars = after.char_indices();
        let mut end = None;
        while let Some((index, c)) = chars.next() {
            match c {
                '\\' => {
                    if let Some((_, escaped)) = chars.next() {
                        value.push(match escaped {
                            'n' => '\n',
                            other => other,
                        });
                    }
                }
                '"' => {
                    end = Some(index);
                    break;
                }
                other => value.push(other),
            }
        }
        let Some(end) = end else { break };
        labels.push((key.trim().trim_start_matches(',').trim().to_owned(), value));
        rest = &after[end + 1..];
    }
    labels
}

impl MetricSet {
    /// Parses the Prometheus text exposition format; malformed lines are skipped.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut series = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (head, value) = match line.rsplit_once(' ') {
                Some(parts) => parts,
                None => continue,
            };
            let Ok(value) = value.trim().parse::<f64>() else {
                continue;
            };
            let (name, labels) = match head.split_once('{') {
                Some((name, rest)) => (
                    name.trim(),
                    parse_labels(rest.trim_end().trim_end_matches('}')),
                ),
                None => (head.trim(), Vec::new()),
            };
            series.push(Series {
                name: name.to_owned(),
                labels,
                value,
            });
        }
        Self { series }
    }

    /// The value of the unlabelled series `name`.
    #[must_use]
    pub fn scalar(&self, name: &str) -> Option<f64> {
        self.series
            .iter()
            .find(|s| s.name == name && s.labels.is_empty())
            .map(|s| s.value)
    }

    /// The values of `name` keyed by the value of label `label`.
    #[must_use]
    pub fn by_label(&self, name: &str, label: &str) -> BTreeMap<String, f64> {
        self.series
            .iter()
            .filter(|s| s.name == name)
            .filter_map(|s| {
                s.labels
                    .iter()
                    .find(|(k, _)| k == label)
                    .map(|(_, v)| (v.clone(), s.value))
            })
            .collect()
    }

    /// Whether the scrape holds any BrowserX series.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.series.is_empty()
    }
}

#[derive(Debug, Clone)]
struct Sample {
    at: Instant,
    set: MetricSet,
}

/// The pool's state now, and what changed inside the window.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PoolSnapshot {
    /// Sessions by status.
    pub sessions: BTreeMap<String, u64>,
    /// Running browsers by isolation.
    pub browsers: BTreeMap<String, u64>,
    /// Admissions waiting for capacity.
    pub queue_depth: u64,
    /// Open CDP relay connections.
    pub relay_connections: u64,
    /// Seconds between the two scrapes the deltas come from (`0` when there is only one).
    pub window_secs: f64,
    /// Admissions by result inside the window.
    pub admissions: BTreeMap<String, u64>,
    /// Recoveries by outcome inside the window.
    pub recoveries: BTreeMap<String, u64>,
    /// Snapshot attempts by result inside the window.
    pub snapshots: BTreeMap<String, u64>,
    /// Egress refusals inside the window.
    pub egress_refused: u64,
    /// Mean browser launch time over all launches since the worker started, in seconds.
    pub launch_seconds_avg: Option<f64>,
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn to_count(value: f64) -> u64 {
    if value.is_finite() && value > 0.0 {
        value.round() as u64
    } else {
        0
    }
}

fn delta(now: f64, before: f64) -> u64 {
    // A counter that went down was reset by a restart: everything it counts is new.
    to_count(if now >= before { now - before } else { now })
}

fn deltas(
    now: &BTreeMap<String, f64>,
    before: Option<&BTreeMap<String, f64>>,
) -> BTreeMap<String, u64> {
    now.iter()
        .map(|(label, value)| {
            let base = before.and_then(|b| b.get(label)).copied();
            (label.clone(), base.map_or(0, |base| delta(*value, base)))
        })
        .collect()
}

impl PoolSnapshot {
    /// Builds the view from the newest scrape and, when there is one, an older baseline.
    #[must_use]
    pub fn compute(newest: &MetricSet, baseline: Option<(&MetricSet, f64)>) -> Self {
        let counts = |name: &str, label: &str| -> BTreeMap<String, u64> {
            newest
                .by_label(name, label)
                .into_iter()
                .map(|(k, v)| (k, to_count(v)))
                .collect()
        };
        let windowed = |name: &str, label: &str| -> BTreeMap<String, u64> {
            let now = newest.by_label(name, label);
            deltas(
                &now,
                baseline.map(|(set, _)| set.by_label(name, label)).as_ref(),
            )
        };
        let count = newest
            .scalar("browserx_launch_seconds_count")
            .unwrap_or(0.0);
        let sum = newest.scalar("browserx_launch_seconds_sum").unwrap_or(0.0);
        Self {
            sessions: counts("browserx_sessions", "status"),
            browsers: counts("browserx_browsers", "isolation"),
            queue_depth: to_count(newest.scalar("browserx_queue_depth").unwrap_or(0.0)),
            relay_connections: to_count(newest.scalar("browserx_relay_connections").unwrap_or(0.0)),
            window_secs: baseline.map_or(0.0, |(_, secs)| secs),
            admissions: windowed("browserx_admissions_total", "result"),
            recoveries: windowed("browserx_recoveries_total", "outcome"),
            snapshots: windowed("browserx_snapshots_total", "result"),
            egress_refused: baseline.map_or(0, |(set, _)| {
                delta(
                    newest
                        .scalar("browserx_egress_refused_total")
                        .unwrap_or(0.0),
                    set.scalar("browserx_egress_refused_total").unwrap_or(0.0),
                )
            }),
            launch_seconds_avg: (count > 0.0).then(|| sum / count),
        }
    }

    /// Sessions in `status`.
    #[must_use]
    pub fn sessions_in(&self, status: &str) -> u64 {
        self.sessions.get(status).copied().unwrap_or(0)
    }
}

/// Keeps recent scrapes of `/metrics`.
#[derive(Debug)]
pub struct Sampler {
    backend: Backend,
    samples: Mutex<VecDeque<Sample>>,
}

impl Sampler {
    /// A sampler that scrapes through `backend`.
    #[must_use]
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            samples: Mutex::new(VecDeque::new()),
        }
    }

    /// Scrapes once.
    ///
    /// # Errors
    /// Why the scrape failed (`None` when the operations listener is not configured).
    pub async fn sample(&self) -> Option<Result<(), String>> {
        let probe = self.backend.probe_ops("/metrics").await?;
        if let Some(error) = probe.error {
            return Some(Err(error));
        }
        if probe.status != Some(200) {
            return Some(Err(format!("/metrics answered {:?}", probe.status)));
        }
        let set = MetricSet::parse(&probe.body);
        if set.is_empty() {
            return Some(Err("/metrics returned no series".into()));
        }
        self.push(Instant::now(), set);
        Some(Ok(()))
    }

    fn push(&self, at: Instant, set: MetricSet) {
        let mut samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        if samples.len() == MAX_SAMPLES {
            samples.pop_front();
        }
        samples.push_back(Sample { at, set });
    }

    /// The newest scrape and the oldest one at most `window` older than it.
    #[must_use]
    pub fn view(&self, window: Duration) -> Option<PoolSnapshot> {
        let samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        let newest = samples.back()?;
        let baseline = samples
            .iter()
            .find(|s| newest.at.duration_since(s.at) <= window && s.at < newest.at)
            .map(|s| (&s.set, newest.at.duration_since(s.at).as_secs_f64()));
        Some(PoolSnapshot::compute(&newest.set, baseline))
    }

    /// Scrapes every `interval` until `cancel` fires.
    pub fn spawn(self: std::sync::Arc<Self>, interval: Duration, cancel: CancellationToken) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancel.cancelled() => return,
                    () = tokio::time::sleep(interval) => {}
                }
                if let Some(Err(error)) = self.sample().await {
                    tracing::debug!(%error, "metrics sample failed");
                }
            }
        });
    }

    #[cfg(test)]
    pub(crate) fn push_for_test(&self, at: Instant, text: &str) {
        self.push(at, MetricSet::parse(text));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const SCRAPE: &str = "# HELP browserx_sessions x\n# TYPE browserx_sessions gauge\n\
browserx_sessions{status=\"idle\"} 2\nbrowserx_sessions{status=\"lost\"} 1\n\
browserx_queue_depth 3\n\
browserx_recoveries_total{outcome=\"fresh_process\"} 5\n\
browserx_recoveries_total{outcome=\"lost\"} 1\n\
browserx_snapshots_total{result=\"failed\"} 4\n\
browserx_egress_refused_total 7\n\
browserx_launch_seconds_sum 3\nbrowserx_launch_seconds_count 2\n";

    #[test]
    fn parses_scalars_and_labelled_series() {
        let set = MetricSet::parse(SCRAPE);
        assert_eq!(set.scalar("browserx_queue_depth"), Some(3.0));
        assert_eq!(set.by_label("browserx_sessions", "status")["lost"], 1.0);
        assert_eq!(set.scalar("missing"), None);
        assert!(MetricSet::parse("garbage\n# only comments\n").is_empty());
    }

    #[test]
    fn windowed_deltas_handle_resets() {
        let before = MetricSet::parse(SCRAPE);
        let after = MetricSet::parse(&SCRAPE.replace("fresh_process\"} 5", "fresh_process\"} 8"));
        let snap = PoolSnapshot::compute(&after, Some((&before, 60.0)));
        assert_eq!(snap.recoveries["fresh_process"], 3);
        assert_eq!(snap.recoveries["lost"], 0);
        assert_eq!(snap.egress_refused, 0);
        assert_eq!(snap.sessions_in("lost"), 1);
        assert_eq!(snap.launch_seconds_avg, Some(1.5));
        let reset = MetricSet::parse("browserx_egress_refused_total 2\n");
        let snap = PoolSnapshot::compute(&reset, Some((&before, 30.0)));
        assert_eq!(snap.egress_refused, 2);
    }

    #[tokio::test]
    async fn sampler_differences_newest_against_the_oldest_sample_inside_the_window() {
        let backend = Backend::new(
            "http://127.0.0.1:1",
            None,
            browserx_core::Secret::new("synthetic-api-key"),
            Duration::from_secs(1),
        )
        .unwrap();
        let sampler = Sampler::new(backend);
        assert!(sampler.view(Duration::from_secs(60)).is_none());
        let now = Instant::now();
        let early = now.checked_sub(Duration::from_secs(500)).unwrap_or(now);
        let mid = now.checked_sub(Duration::from_secs(50)).unwrap_or(now);
        sampler.push_for_test(early, "browserx_egress_refused_total 1\n");
        sampler.push_for_test(mid, "browserx_egress_refused_total 10\n");
        sampler.push_for_test(now, "browserx_egress_refused_total 13\n");
        let recent = sampler.view(Duration::from_secs(60)).unwrap();
        assert_eq!(recent.egress_refused, 3);
        let wide = sampler.view(Duration::from_secs(900)).unwrap();
        assert_eq!(wide.egress_refused, 12);
    }
}
