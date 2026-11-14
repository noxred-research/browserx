//! Fault injection for the evaluation harness's self-tests. Compiled only with the
//! `fault-injection` feature, which no release build enables: it exists so a test build can
//! switch one enforcement layer off and prove that the suite notices.

use std::sync::atomic::{AtomicU32, Ordering};

/// An enforcement layer that can be switched off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The profile decision and its approvals.
    Classifier = 1,
    /// The re-resolution of element references.
    StaleRef = 2,
    /// Secret redaction of results.
    Redaction = 4,
}

static ACTIVE: AtomicU32 = AtomicU32::new(0);

/// Switches `fault` on for the rest of the process.
pub fn enable(fault: Fault) {
    ACTIVE.fetch_or(fault as u32, Ordering::SeqCst);
}

/// Whether `fault` is on.
#[must_use]
pub fn active(fault: Fault) -> bool {
    ACTIVE.load(Ordering::SeqCst) & fault as u32 != 0
}
