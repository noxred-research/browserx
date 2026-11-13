//! Counters the scheduler keeps for the metrics endpoint.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Upper bounds (seconds) of the browser launch histogram.
pub const LAUNCH_BUCKETS: [f64; 9] = [0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0];

#[derive(Default)]
pub(crate) struct Counter(AtomicU64);

impl Counter {
    pub(crate) fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }
    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
struct HistogramState {
    counts: [u64; LAUNCH_BUCKETS.len()],
    sum: f64,
    count: u64,
}

#[derive(Default)]
pub(crate) struct Metrics {
    pub adm_accepted: Counter,
    pub adm_queue_full: Counter,
    pub adm_timeout: Counter,
    pub adm_quota: Counter,
    pub adm_failed: Counter,
    pub rec_profile: Counter,
    pub rec_snapshot: Counter,
    pub rec_fresh: Counter,
    pub rec_lost: Counter,
    pub snap_ok: Counter,
    pub snap_failed: Counter,
    pub snap_stale: Counter,
    pub egress_refused_closed: Counter,
    pub relay_connections: AtomicI64,
    launch: Mutex<HistogramState>,
}

impl Metrics {
    pub(crate) fn relay_delta(&self, delta: i64) {
        self.relay_connections.fetch_add(delta, Ordering::Relaxed);
    }

    pub(crate) fn observe_launch(&self, seconds: f64) {
        let mut h = self
            .launch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        h.sum += seconds;
        h.count += 1;
        if let Some(i) = LAUNCH_BUCKETS.iter().position(|b| seconds <= *b) {
            h.counts[i] += 1;
        }
    }

    pub(crate) fn launch_histogram(&self) -> HistogramSnapshot {
        let h = self
            .launch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut cumulative = Vec::with_capacity(LAUNCH_BUCKETS.len());
        let mut running = 0u64;
        for c in h.counts {
            running += c;
            cumulative.push(running);
        }
        HistogramSnapshot {
            bounds: LAUNCH_BUCKETS.to_vec(),
            cumulative,
            sum: h.sum,
            count: h.count,
        }
    }
}

/// A cumulative histogram.
#[derive(Clone, Debug, Default)]
pub struct HistogramSnapshot {
    /// Bucket upper bounds in seconds.
    pub bounds: Vec<f64>,
    /// Cumulative count per bound.
    pub cumulative: Vec<u64>,
    /// Sum of observations in seconds.
    pub sum: f64,
    /// Number of observations.
    pub count: u64,
}

/// A point-in-time copy of every scheduler metric.
#[derive(Clone, Debug, Default)]
pub struct MetricsSnapshot {
    /// Sessions by lifecycle status name.
    pub sessions: BTreeMap<&'static str, u64>,
    /// Running browsers by isolation (`dedicated_browser` / `shared_browser`).
    pub browsers: BTreeMap<&'static str, u64>,
    /// Admission outcomes by result label.
    pub admissions: BTreeMap<&'static str, u64>,
    /// Admissions currently waiting.
    pub queue_depth: u64,
    /// Recoveries by outcome label (`restored_from_profile`, ..., `lost`).
    pub recoveries: BTreeMap<&'static str, u64>,
    /// Browser launch latency.
    pub launch_seconds: HistogramSnapshot,
    /// Open relay connections.
    pub relay_connections: u64,
    /// Snapshot attempts by result label (`ok`, `failed`, `stale`).
    pub snapshots: BTreeMap<&'static str, u64>,
    /// Connections refused by egress policy, across all forwarders.
    pub egress_refused: u64,
}
