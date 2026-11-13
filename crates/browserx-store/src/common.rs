//! Rules shared by every store implementation so they behave identically.

use browserx_core::{Error, Generation, Result, SessionLease, Snapshot};
use time::OffsetDateTime;

use crate::MAX_SEALED_BYTES;

/// Validates a compare-and-swap request against the stored generation.
///
/// The new lease may keep the generation or advance it by exactly one. Any other
/// value would let a caller skip fencing epochs.
pub(crate) fn check_cas(
    stored: Generation,
    expected: Generation,
    new: &SessionLease,
) -> Result<()> {
    if new.generation != expected && new.generation != expected.next() {
        return Err(Error::InvalidRequest(format!(
            "lease generation must stay {expected} or advance to {}, got {}",
            expected.next(),
            new.generation
        )));
    }
    if stored != expected {
        return Err(Error::StaleGeneration {
            expected,
            found: stored,
        });
    }
    Ok(())
}

/// Validates a snapshot before it is stored.
pub(crate) fn check_put(snapshot: &Snapshot) -> Result<()> {
    if snapshot.meta.version == 0 {
        return Err(Error::InvalidRequest("snapshot versions start at 1".into()));
    }
    if snapshot.sealed.len() > MAX_SEALED_BYTES {
        return Err(Error::InvalidRequest(format!(
            "snapshot is {} bytes; the limit is {MAX_SEALED_BYTES}",
            snapshot.sealed.len()
        )));
    }
    if u64::try_from(snapshot.sealed.len()).ok() != Some(snapshot.meta.size) {
        return Err(Error::InvalidRequest(
            "snapshot meta.size does not match payload length".into(),
        ));
    }
    Ok(())
}

/// Microseconds since the Unix epoch, saturating at the `i64` range.
pub(crate) fn micros(t: OffsetDateTime) -> i64 {
    let us = t.unix_timestamp_nanos() / 1000;
    i64::try_from(us).unwrap_or(if us < 0 { i64::MIN } else { i64::MAX })
}

/// A lease holds the upstream proxy password only so recovery can relaunch the
/// forwarder. A terminal lease (`lost`, `closed`) is never recovered, so the
/// password is dropped before the record is stored. Returns `None` when there
/// is nothing to scrub.
pub(crate) fn scrubbed_if_terminal(lease: &SessionLease) -> Option<SessionLease> {
    if !lease.status.is_terminal() {
        return None;
    }
    let has_password = lease
        .spec
        .proxy
        .as_ref()
        .is_some_and(|p| p.password.is_some());
    if !has_password {
        return None;
    }
    let mut copy = lease.clone();
    if let Some(proxy) = copy.spec.proxy.as_mut() {
        proxy.password = None;
    }
    Some(copy)
}
