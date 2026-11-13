//! The session capability ledger: the Rule of Two as a deterministic gate.
//!
//! Within one session an agent should have at most two of three properties:
//! **A** it ingested untrusted input, **B** it works with sensitive systems or data, **C** it can
//! change state or communicate outward. When all three meet, a consequential call needs a human
//! approval (`enforce`) or is refused (`strict`).
//!
//! The ledger keeps one entry per *handle*, a server-minted opaque id bound to the principal
//! that created it. Flags only ever turn on within a handle: nothing, and no model, clears one.
//! `reset_context` mints a fresh handle and retires the old one, which is the only way to start
//! again. The ledger is in memory: a restarted server treats every old handle as unknown.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use rand::Rng as _;
use serde_json::{Value, json};

use crate::config::RuleOfTwoMode;
use crate::grants::{PlanProgress, PlanVerdict};

/// Most handles kept; the oldest are retired first.
const MAX_HANDLES: usize = 256;
/// Most reasons kept per flag.
const MAX_REASONS: usize = 8;

/// One of the three properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flag {
    /// Untrusted input was ingested.
    A,
    /// Sensitive context is in play.
    B,
    /// A consequential capability is enabled.
    C,
}

impl Flag {
    /// `A`, `B` or `C`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
        }
    }
}

/// The three flags of a handle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    /// Untrusted input ingested.
    pub a: bool,
    /// Sensitive context.
    pub b: bool,
    /// Consequential capability enabled.
    pub c: bool,
}

impl Flags {
    /// All three at once.
    #[must_use]
    pub const fn all(self) -> bool {
        self.a && self.b && self.c
    }

    /// The flags as the JSON recorded in the audit log.
    #[must_use]
    pub fn to_value(self) -> Value {
        json!({ "A": self.a, "B": self.b, "C": self.c })
    }
}

/// What the Rule of Two asks for a consequential call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing special.
    Proceed,
    /// All three flags are on, the mode only warns: proceed and say so.
    Warn,
    /// All three flags are on: an approval is required.
    NeedApproval,
    /// All three flags are on and the mode is strict: refuse.
    Refuse,
}

#[derive(Debug)]
struct Entry {
    principal: String,
    flags: Flags,
    reasons: [Vec<String>; 3],
    plan: PlanProgress,
    calls: u64,
    first_call: Option<Instant>,
}

#[derive(Debug, Default)]
struct Inner {
    handles: HashMap<String, Entry>,
    defaults: HashMap<String, String>,
    order: VecDeque<String>,
}

/// The ledger.
#[derive(Debug)]
pub struct Ledger {
    mode: RuleOfTwoMode,
    c_enabled: bool,
    inner: Mutex<Inner>,
}

/// A handle that does not exist or belongs to another principal. The two cases are not told
/// apart, so a handle id reveals nothing about other principals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown handle")]
pub struct UnknownHandle;

/// A read-only copy of one handle's state.
#[derive(Debug, Clone)]
pub struct Status {
    /// The handle id.
    pub handle: String,
    /// The flags.
    pub flags: Flags,
    /// Which events set each flag.
    pub reasons: [Vec<String>; 3],
    /// Calls counted against the budget.
    pub calls: u64,
}

fn flag_index(flag: Flag) -> usize {
    match flag {
        Flag::A => 0,
        Flag::B => 1,
        Flag::C => 2,
    }
}

impl Ledger {
    /// A ledger. `c_enabled` says whether a consequential capability (`interact`, `evaluate`)
    /// is enabled: every new handle starts with C set accordingly.
    #[must_use]
    pub fn new(mode: RuleOfTwoMode, c_enabled: bool) -> Self {
        Self {
            mode,
            c_enabled,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The policy mode.
    #[must_use]
    pub fn mode(&self) -> RuleOfTwoMode {
        self.mode
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn mint(&self, inner: &mut Inner, principal: &str) -> String {
        let mut bytes = [0_u8; 12];
        rand::rng().fill_bytes(&mut bytes);
        let handle = format!("hnd_{}", hex::encode(bytes));
        let mut entry = Entry {
            principal: principal.to_owned(),
            flags: Flags {
                c: self.c_enabled,
                ..Flags::default()
            },
            reasons: [Vec::new(), Vec::new(), Vec::new()],
            plan: PlanProgress::default(),
            calls: 0,
            first_call: None,
        };
        if self.c_enabled {
            entry.reasons[2].push("a tool that changes pages is enabled".into());
        }
        inner.handles.insert(handle.clone(), entry);
        inner.order.push_back(handle.clone());
        while inner.order.len() > MAX_HANDLES {
            if let Some(old) = inner.order.pop_front() {
                inner.handles.remove(&old);
                inner.defaults.retain(|_, h| *h != old);
            }
        }
        handle
    }

    /// The principal's default handle, minted on first use.
    pub fn current(&self, principal: &str) -> String {
        let mut inner = self.lock();
        if let Some(handle) = inner.defaults.get(principal)
            && inner.handles.contains_key(handle)
        {
            return handle.clone();
        }
        let handle = self.mint(&mut inner, principal);
        inner.defaults.insert(principal.to_owned(), handle.clone());
        handle
    }

    /// Resolves an explicit handle for `principal`.
    ///
    /// # Errors
    /// [`UnknownHandle`] when the handle does not exist or belongs to another principal.
    pub fn resolve(&self, principal: &str, handle: Option<&str>) -> Result<String, UnknownHandle> {
        let Some(handle) = handle else {
            return Ok(self.current(principal));
        };
        let inner = self.lock();
        match inner.handles.get(handle) {
            Some(entry) if entry.principal == principal => Ok(handle.to_owned()),
            _ => Err(UnknownHandle),
        }
    }

    /// Retires the principal's handle and returns a fresh one with only C set by capability.
    pub fn reset(&self, principal: &str) -> String {
        let mut inner = self.lock();
        if let Some(old) = inner.defaults.remove(principal) {
            inner.handles.remove(&old);
            inner.order.retain(|h| *h != old);
        }
        let handle = self.mint(&mut inner, principal);
        inner.defaults.insert(principal.to_owned(), handle.clone());
        handle
    }

    /// Turns a flag on and records why (bounded). Never turns one off.
    pub fn mark(&self, handle: &str, flag: Flag, reason: &str) {
        let mut inner = self.lock();
        let Some(entry) = inner.handles.get_mut(handle) else {
            return;
        };
        match flag {
            Flag::A => entry.flags.a = true,
            Flag::B => entry.flags.b = true,
            Flag::C => entry.flags.c = true,
        }
        let reasons = &mut entry.reasons[flag_index(flag)];
        if reasons.len() < MAX_REASONS && !reasons.iter().any(|r| r == reason) {
            reasons.push(reason.chars().take(160).collect());
        }
    }

    /// The flags of a handle.
    #[must_use]
    pub fn flags(&self, handle: &str) -> Flags {
        self.lock()
            .handles
            .get(handle)
            .map(|e| e.flags)
            .unwrap_or_default()
    }

    /// A copy of a handle's state.
    #[must_use]
    pub fn status(&self, handle: &str) -> Option<Status> {
        self.lock().handles.get(handle).map(|e| Status {
            handle: handle.to_owned(),
            flags: e.flags,
            reasons: e.reasons.clone(),
            calls: e.calls,
        })
    }

    /// What the Rule of Two asks of a consequential call on `handle`.
    #[must_use]
    pub fn verdict(&self, handle: &str) -> Verdict {
        if !self.flags(handle).all() {
            return Verdict::Proceed;
        }
        match self.mode {
            RuleOfTwoMode::Off => Verdict::Proceed,
            RuleOfTwoMode::Warn => Verdict::Warn,
            RuleOfTwoMode::Enforce => Verdict::NeedApproval,
            RuleOfTwoMode::Strict => Verdict::Refuse,
        }
    }

    /// Counts one call and returns the calls so far and the seconds since the first.
    pub fn count_call(&self, handle: &str) -> (u64, u64) {
        let mut inner = self.lock();
        let Some(entry) = inner.handles.get_mut(handle) else {
            return (0, 0);
        };
        entry.calls = entry.calls.saturating_add(1);
        let first = *entry.first_call.get_or_insert_with(Instant::now);
        (entry.calls, first.elapsed().as_secs())
    }

    /// Checks a call against the plan without consuming a step.
    #[must_use]
    pub fn plan_check(
        &self,
        handle: &str,
        plan: &[crate::grants::PlanStep],
        tool: &str,
        origin: &str,
        class: &str,
    ) -> PlanVerdict {
        self.lock()
            .handles
            .get(handle)
            .map_or(PlanVerdict::Outside, |entry| {
                entry.plan.check(plan, tool, origin, class)
            })
    }

    /// Consumes a plan step.
    pub fn plan_consume(&self, handle: &str, plan_len: usize, index: usize) {
        if let Some(entry) = self.lock().handles.get_mut(handle) {
            entry.plan.consume(plan_len, index);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_fresh_read_only_handle_shows_untrusted_input_only_after_a_read() {
        let ledger = Ledger::new(RuleOfTwoMode::Enforce, false);
        let handle = ledger.current("stdio");
        assert_eq!(ledger.flags(&handle), Flags::default());
        ledger.mark(&handle, Flag::A, "page_snapshot");
        assert_eq!(
            ledger.flags(&handle),
            Flags {
                a: true,
                b: false,
                c: false
            }
        );
        assert_eq!(ledger.verdict(&handle), Verdict::Proceed);
        assert_eq!(ledger.current("stdio"), handle);
    }

    #[test]
    fn three_flags_make_a_consequential_call_an_approval_or_a_refusal() {
        for (mode, expected) in [
            (RuleOfTwoMode::Off, Verdict::Proceed),
            (RuleOfTwoMode::Warn, Verdict::Warn),
            (RuleOfTwoMode::Enforce, Verdict::NeedApproval),
            (RuleOfTwoMode::Strict, Verdict::Refuse),
        ] {
            let ledger = Ledger::new(mode, true);
            let handle = ledger.current("p");
            assert!(
                ledger.flags(&handle).c,
                "C is set by the enabled capability"
            );
            assert_eq!(ledger.verdict(&handle), Verdict::Proceed);
            ledger.mark(&handle, Flag::A, "read");
            ledger.mark(&handle, Flag::B, "private network");
            assert_eq!(ledger.verdict(&handle), expected, "{mode:?}");
        }
    }

    #[test]
    fn flags_never_turn_off_within_a_handle() {
        // A deterministic pseudo-random walk over events; the flags may only grow.
        let ledger = Ledger::new(RuleOfTwoMode::Enforce, false);
        let handle = ledger.current("p");
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut seen = Flags::default();
        for _ in 0..2000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            match state % 7 {
                0 => ledger.mark(&handle, Flag::A, "a"),
                1 => ledger.mark(&handle, Flag::B, "b"),
                2 => ledger.mark(&handle, Flag::C, "c"),
                3 => {
                    let _ = ledger.count_call(&handle);
                }
                4 => {
                    let _ = ledger.verdict(&handle);
                }
                5 => {
                    let _ = ledger.resolve("p", Some(&handle));
                }
                _ => {
                    let _ = ledger.resolve("other", Some(&handle));
                }
            }
            let now = ledger.flags(&handle);
            assert!(now.a >= seen.a && now.b >= seen.b && now.c >= seen.c);
            seen = now;
        }
    }

    #[test]
    fn handles_belong_to_their_principal_and_reset_retires_the_old_one() {
        let ledger = Ledger::new(RuleOfTwoMode::Enforce, true);
        let mine = ledger.current("alice");
        let theirs = ledger.current("bob");
        assert_ne!(mine, theirs);
        assert_eq!(ledger.resolve("alice", Some(&mine)), Ok(mine.clone()));
        // Another principal's handle and a made-up one look the same.
        assert_eq!(ledger.resolve("alice", Some(&theirs)), Err(UnknownHandle));
        assert_eq!(
            ledger.resolve("alice", Some("hnd_forged")),
            Err(UnknownHandle)
        );
        ledger.mark(&mine, Flag::A, "read");
        ledger.mark(&mine, Flag::B, "profile");
        let fresh = ledger.reset("alice");
        assert_ne!(fresh, mine);
        assert_eq!(ledger.resolve("alice", Some(&mine)), Err(UnknownHandle));
        assert_eq!(
            ledger.flags(&fresh),
            Flags {
                a: false,
                b: false,
                c: true
            }
        );
        assert_eq!(ledger.current("alice"), fresh);
    }

    #[test]
    fn a_new_ledger_does_not_know_old_handles() {
        let first = Ledger::new(RuleOfTwoMode::Enforce, false);
        let handle = first.current("p");
        let restarted = Ledger::new(RuleOfTwoMode::Enforce, false);
        assert_eq!(restarted.resolve("p", Some(&handle)), Err(UnknownHandle));
    }

    #[test]
    fn the_handle_table_is_bounded() {
        let ledger = Ledger::new(RuleOfTwoMode::Off, false);
        let first = ledger.current("p0");
        for n in 1..=MAX_HANDLES {
            let _ = ledger.current(&format!("p{n}"));
        }
        assert_eq!(ledger.resolve("p0", Some(&first)), Err(UnknownHandle));
    }

    #[test]
    fn reasons_and_calls_are_recorded() {
        let ledger = Ledger::new(RuleOfTwoMode::Warn, false);
        let handle = ledger.current("p");
        ledger.mark(&handle, Flag::B, "adopted session");
        ledger.mark(&handle, Flag::B, "adopted session");
        assert_eq!(ledger.count_call(&handle).0, 1);
        assert_eq!(ledger.count_call(&handle).0, 2);
        let status = ledger.status(&handle).unwrap();
        assert_eq!(status.reasons[1], vec!["adopted session".to_owned()]);
        assert_eq!(status.calls, 2);
    }
}
