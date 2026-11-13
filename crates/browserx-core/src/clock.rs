//! Injected wall clock so expiry logic is testable without sleeping.

use std::sync::Mutex;

use time::OffsetDateTime;

/// Source of the current UTC time.
pub trait Clock: Send + Sync + 'static {
    /// Now, in UTC.
    fn now(&self) -> OffsetDateTime;
}

/// The real clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A manually advanced clock for tests.
#[derive(Debug)]
pub struct ManualClock {
    now: Mutex<OffsetDateTime>,
}

impl ManualClock {
    /// Starts at `start`.
    #[must_use]
    pub fn new(start: OffsetDateTime) -> Self {
        Self {
            now: Mutex::new(start),
        }
    }

    /// Moves time forward.
    pub fn advance(&self, by: time::Duration) {
        if let Ok(mut now) = self.now.lock() {
            *now += by;
        }
    }
}

impl Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        self.now
            .lock()
            .map(|n| *n)
            .unwrap_or_else(|p| *p.into_inner())
    }
}
