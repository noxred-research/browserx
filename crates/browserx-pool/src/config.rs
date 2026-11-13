//! Scheduler configuration.

use std::collections::BTreeMap;
use std::time::Duration;

use browserx_core::{Error, Result};

/// Longest duration any setting may take (ten years). Larger values only
/// overflow time arithmetic; they never mean anything useful.
pub const MAX_CONFIG_DURATION: Duration = Duration::from_secs(10 * 365 * 24 * 3600);

/// Limits and intervals the scheduler enforces. Every duration is positive and
/// bounded, and every count is bounded; [`PoolConfig::validate`] rejects anything else.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Maximum number of browser processes (dedicated + shared, including ones being launched or torn down).
    pub max_browsers: usize,
    /// Maximum browser contexts per shared browser.
    pub max_contexts_per_browser: usize,
    /// Idle shared browsers kept running for fast allocation.
    pub warm_shared_browsers: usize,
    /// Maximum number of admissions waiting for capacity.
    pub queue_capacity: usize,
    /// How long an admission may wait for capacity before `Error::Capacity`.
    pub queue_timeout: Duration,
    /// A shared browser older than this takes no new contexts and retires when empty.
    pub browser_max_age: Duration,
    /// A shared browser that has served this many contexts retires when empty.
    pub browser_max_contexts_served: u64,
    /// Lease TTL applied when the request names none.
    pub default_ttl: Duration,
    /// Largest TTL a request may ask for (also bounds renewals).
    pub max_ttl: Duration,
    /// Largest absolute session lifetime a request may ask for; also the default.
    pub max_lifetime: Duration,
    /// Idle timeout applied when the request names none.
    pub default_idle_timeout: Duration,
    /// Interval between periodic snapshots of `snapshot`-persistence sessions.
    pub snapshot_interval: Duration,
    /// Snapshot versions kept per profile.
    pub snapshot_keep: usize,
    /// How long terminal leases stay queryable before they are purged.
    pub terminal_retention: Duration,
    /// Interval between browser health probes.
    pub probe_interval: Duration,
    /// Deadline of one health probe.
    pub probe_timeout: Duration,
    /// Consecutive unresponsive probes before a browser counts as lost.
    pub unresponsive_strikes: u32,
    /// Relaunch attempts per recovery before the session is declared lost.
    pub recovery_attempts: u32,
    /// Pause between relaunch attempts.
    pub recovery_backoff: Duration,
    /// Interval of the reaper, snapshotter and warm-pool tick.
    pub maintenance_interval: Duration,
    /// Deadline for browser operations that have no deadline of their own (launch, capture, restore).
    pub operation_timeout: Duration,
    /// Per-owner cap on non-terminal sessions when `owner_quotas` has no entry.
    pub default_owner_quota: usize,
    /// Per-owner caps on non-terminal sessions, by authenticated owner name.
    pub owner_quotas: BTreeMap<String, usize>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_browsers: 8,
            max_contexts_per_browser: 8,
            warm_shared_browsers: 0,
            queue_capacity: 64,
            queue_timeout: Duration::from_secs(30),
            browser_max_age: Duration::from_secs(3600),
            browser_max_contexts_served: 1000,
            default_ttl: Duration::from_secs(600),
            max_ttl: Duration::from_secs(3600),
            max_lifetime: Duration::from_secs(86_400),
            default_idle_timeout: Duration::from_secs(300),
            snapshot_interval: Duration::from_secs(60),
            snapshot_keep: 5,
            terminal_retention: Duration::from_secs(86_400),
            probe_interval: Duration::from_secs(5),
            probe_timeout: Duration::from_millis(3000),
            unresponsive_strikes: 3,
            recovery_attempts: 3,
            recovery_backoff: Duration::from_millis(500),
            maintenance_interval: Duration::from_secs(1),
            operation_timeout: Duration::from_secs(60),
            default_owner_quota: 16,
            owner_quotas: BTreeMap::new(),
        }
    }
}

impl PoolConfig {
    /// Rejects zero or contradictory limits.
    pub fn validate(&self) -> Result<()> {
        let bad = |what: &str| Err(Error::InvalidRequest(format!("pool config: {what}")));
        if self.max_browsers == 0 {
            return bad("max_browsers must be positive");
        }
        if self.max_contexts_per_browser == 0 {
            return bad("max_contexts_per_browser must be positive");
        }
        if self.warm_shared_browsers > self.max_browsers {
            return bad("warm_shared_browsers exceeds max_browsers");
        }
        if self.queue_timeout.is_zero()
            || self.default_ttl.is_zero()
            || self.max_ttl.is_zero()
            || self.max_lifetime.is_zero()
            || self.default_idle_timeout.is_zero()
            || self.snapshot_interval.is_zero()
            || self.probe_interval.is_zero()
            || self.probe_timeout.is_zero()
            || self.maintenance_interval.is_zero()
            || self.operation_timeout.is_zero()
        {
            return bad("durations must be positive");
        }
        if [
            self.queue_timeout,
            self.browser_max_age,
            self.default_ttl,
            self.max_ttl,
            self.max_lifetime,
            self.default_idle_timeout,
            self.snapshot_interval,
            self.terminal_retention,
            self.probe_interval,
            self.probe_timeout,
            self.recovery_backoff,
            self.maintenance_interval,
            self.operation_timeout,
        ]
        .iter()
        .any(|d| *d > MAX_CONFIG_DURATION)
        {
            return bad("durations must not exceed ten years");
        }
        if self.default_ttl > self.max_ttl {
            return bad("default_ttl exceeds max_ttl");
        }
        if self.snapshot_keep == 0 {
            return bad("snapshot_keep must be positive");
        }
        if self.unresponsive_strikes == 0 || self.recovery_attempts == 0 {
            return bad("unresponsive_strikes and recovery_attempts must be positive");
        }
        Ok(())
    }

    pub(crate) fn quota_for(&self, owner: &str) -> usize {
        self.owner_quotas
            .get(owner)
            .copied()
            .unwrap_or(self.default_owner_quota)
    }
}
