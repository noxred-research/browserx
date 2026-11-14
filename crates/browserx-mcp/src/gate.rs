//! The deterministic gate in front of every action: action class and profile, the engagement
//! manifest, the scope grant and its plan, the Rule of Two and approvals.
//!
//! Nothing here asks a model. The order is fixed:
//!
//! 1. the effective profile is the configured one narrowed by the manifest (`observe` impact
//!    and `visit` hosts make it read-only; `probe` impact refuses destructive, credential,
//!    external and file actions);
//! 2. the grant's allowed action classes;
//! 3. protected requests of the manifest (never allowed, whatever the class);
//! 4. the profile's decision for the class: deny, approval or allow;
//! 5. the grant's plan (`outside_plan`);
//! 6. the Rule of Two for consequential calls;
//! 7. an approval, when one is needed, bound to the exact action by a digest.
//!
//! Before all of these, an interaction with a page (`Kind::Element`, `Kind::Evaluate`) must
//! happen on a read-write origin of the active grant (`origin_not_in_rw`).
//!
//! `reset_context` does not pass through the gate above: a model that could clear the ledger
//! could always step out of the Rule of Two. [`authorize_reset`] asks a human (`enforce`) or
//! refuses (`strict`) once the handle holds untrusted input or sensitive context.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::approvals::{ApprovalNeed, Approved, quote_for_human};
use crate::audit::canonical_json;
use crate::classifier::{ActionClass, Decision, Profile, decide};
use crate::config::RuleOfTwoMode;
use crate::ctx::Ctx;
use crate::error::{ToolError, ToolResult};
use crate::grants::PlanVerdict;
use crate::ledger::{Flag, Verdict};
use crate::manifest::{HostMode, Impact};

/// The state of one tool call: who calls, under which handle, with which approval.
pub struct Call<'a> {
    /// The tool.
    pub tool: &'static str,
    /// The authenticated principal.
    pub principal: &'a str,
    /// The ledger handle in use.
    pub handle: String,
    approved: Option<&'a Approved>,
    approval_used: AtomicBool,
    notes: Mutex<Map<String, Value>>,
}

impl<'a> Call<'a> {
    /// A call state.
    #[must_use]
    pub fn new(
        tool: &'static str,
        principal: &'a str,
        handle: String,
        approved: Option<&'a Approved>,
    ) -> Self {
        Self {
            tool,
            principal,
            handle,
            approved,
            approval_used: AtomicBool::new(false),
            notes: Mutex::new(Map::new()),
        }
    }

    /// Records a fact for the audit entry of this call.
    pub fn note(&self, key: &str, value: Value) {
        self.notes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.to_owned(), value);
    }

    /// The notes recorded so far.
    #[must_use]
    pub fn notes(&self) -> Map<String, Value> {
        self.notes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether the approval attached to this call covers exactly `digest`; usable once.
    fn take_approval(&self, digest: &str) -> bool {
        self.approved
            .is_some_and(|approved| approved.action_digest == digest)
            && !self.approval_used.swap(true, Ordering::SeqCst)
    }
}

/// What kind of call is being authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An interaction with an element, classified from the page.
    Element,
    /// Reading or navigating: the class is fixed by the tool.
    Plain,
    /// Running operator-enabled script.
    Evaluate,
}

/// The action to authorize.
#[derive(Debug, Clone)]
pub struct Subject {
    /// The tool.
    pub tool: &'static str,
    /// Kind of call.
    pub kind: Kind,
    /// The action class.
    pub class: ActionClass,
    /// The page URL the action happens on (`about:blank` when none).
    pub url: String,
    /// Description of the target element (ref, role, name), for the digest and the prompt.
    pub target: String,
    /// The request the action would send: `(METHOD, URL)`, for protected patterns.
    pub request: Option<(String, String)>,
    /// Digest of the arguments that matter (typed text, expression).
    pub args_digest: String,
    /// Rule ids that produced the class.
    pub rules: Vec<String>,
    /// The call changes state or communicates outward (C-class), for the Rule of Two.
    pub consequential: bool,
    /// A reason code that makes this action need an approval whatever its class.
    pub force_approval: Option<&'static str>,
}

impl Subject {
    /// A subject for a tool whose class is fixed (`read`, `navigate_in_scope`).
    #[must_use]
    pub fn plain(tool: &'static str, class: ActionClass, url: &str) -> Self {
        Self {
            tool,
            kind: Kind::Plain,
            class,
            url: url.to_owned(),
            target: String::new(),
            request: None,
            args_digest: String::new(),
            rules: Vec::new(),
            consequential: false,
            force_approval: None,
        }
    }
}

fn origin_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .map_or_else(|| "*".to_owned(), |u| u.origin().ascii_serialization())
}

fn narrower(a: Profile, b: Profile) -> Profile {
    let rank = |p: Profile| match p {
        Profile::ReadOnly => 0,
        Profile::TestEnvironment => 1,
        Profile::AuthorizedSecurityTest => 2,
    };
    if rank(a) <= rank(b) { a } else { b }
}

/// The profile after the manifest narrowed it for this page.
fn effective_profile(ctx: &Ctx, url: &str) -> (Profile, Vec<String>) {
    let mut profile = ctx.cfg.safety.profile;
    let mut why = Vec::new();
    if let Some(loaded) = ctx.scope.manifest().filter(|m| m.trusted()) {
        if loaded.manifest.impact == Impact::Observe {
            profile = narrower(profile, Profile::ReadOnly);
            why.push("manifest.impact.observe".to_owned());
        }
        if ctx.scope.host_mode(url) == Some(HostMode::Visit) {
            profile = narrower(profile, Profile::ReadOnly);
            why.push("manifest.host.visit".to_owned());
        }
    }
    (profile, why)
}

fn decision_for(ctx: &Ctx, subject: &Subject, profile: Profile) -> Decision {
    if subject.kind == Kind::Evaluate {
        return if profile == Profile::ReadOnly {
            Decision::Deny
        } else {
            Decision::Allow
        };
    }
    #[cfg(feature = "fault-injection")]
    if crate::faults::active(crate::faults::Fault::Classifier) {
        return Decision::Allow;
    }
    let mut decision = decide(profile, subject.class);
    if ctx
        .scope
        .manifest()
        .filter(|m| m.trusted())
        .is_some_and(|m| m.manifest.impact == Impact::Probe)
        && matches!(
            subject.class,
            ActionClass::Destructive
                | ActionClass::ExternalCommunication
                | ActionClass::FileTransfer
                | ActionClass::CredentialEntry
        )
    {
        decision = Decision::Deny;
    }
    decision
}

fn digest_of(ctx: &Ctx, subject: &Subject) -> String {
    let value = json!({
        "tool": subject.tool,
        "class": subject.class.name(),
        "url": subject.url,
        "target": subject.target,
        "args": subject.args_digest,
        "plan": ctx.scope.grant().and_then(|g| g.grant.plan_digest()),
        "grant": ctx.scope.grant().map(|g| g.digest.clone()),
    });
    hex::encode(Sha256::digest(canonical_json(&value).as_bytes()))
}

/// Marks flag B when a page is on a private network and the policy treats that as sensitive.
pub fn note_target(ctx: &Ctx, call: &Call<'_>, url: &str) {
    if !ctx.cfg.safety.rule_of_two.private_network_is_sensitive {
        return;
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return;
    };
    if is_private_host(&parsed) {
        ctx.ledger
            .mark(&call.handle, Flag::B, "a private-network target is in use");
    }
}

fn is_private_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => {
            let domain = domain.to_ascii_lowercase();
            domain == "localhost"
                || domain.ends_with(".localhost")
                || domain.ends_with(".local")
                || domain.ends_with(".internal")
                || domain.ends_with(".lan")
        }
        Some(url::Host::Ipv4(ip)) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64)
        }
        Some(url::Host::Ipv6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
        None => false,
    }
}

/// Authorizes the action or says why not.
///
/// # Errors
/// A refusal with a reason code, or an approval request that carries what a human is asked to
/// approve.
pub fn authorize(ctx: &Ctx, call: &Call<'_>, subject: &Subject) -> ToolResult<()> {
    let origin = origin_of(&subject.url);
    call.note("action_class", json!(subject.class.name()));
    if !subject.rules.is_empty() {
        call.note("action_rules", json!(subject.rules));
    }
    note_target(ctx, call, &subject.url);

    if matches!(subject.kind, Kind::Element | Kind::Evaluate)
        && let Some(grant) = ctx.scope.grant()
        && !grant.grant.can_write(&origin)
    {
        return Err(ToolError::refused_with(
            "origin_not_in_rw",
            format!(
                "{origin} is not a read-write origin of the scope grant: pages there can be read, not acted on"
            ),
        ));
    }
    if let Some(grant) = ctx.scope.grant()
        && subject.kind != Kind::Plain
        && !grant.grant.allows_action(subject.class.name())
    {
        return Err(ToolError::refused_with(
            "action_not_granted",
            format!(
                "the scope grant does not allow {} actions",
                subject.class.name()
            ),
        ));
    }
    if let Some(manifest) = ctx.scope.manifest().filter(|m| m.trusted())
        && let Some((method, raw)) = &subject.request
        && let Ok(url) = url::Url::parse(raw)
        && manifest.manifest.is_protected(method, &url)
    {
        return Err(ToolError::refused_with(
            "blocked_protected",
            format!(
                "{method} {origin}{} is a protected request of the engagement",
                url.path()
            ),
        ));
    }

    let (profile, narrowed_by) = effective_profile(ctx, &subject.url);
    let decision = decision_for(ctx, subject, profile);
    if decision == Decision::Deny {
        let code = if narrowed_by.iter().any(|w| w == "manifest.host.visit") {
            "visit_only"
        } else if narrowed_by.iter().any(|w| w == "manifest.impact.observe") {
            "impact_ceiling"
        } else {
            "profile_denied"
        };
        return Err(ToolError::refused_with(
            code,
            format!(
                "{} actions are refused under the {} profile{}",
                subject.class.name(),
                serde_json::to_value(profile)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default(),
                if narrowed_by.is_empty() {
                    String::new()
                } else {
                    format!(" (narrowed by {})", narrowed_by.join(", "))
                }
            ),
        ));
    }

    let mut plan_step = None;
    if let Some(grant) = ctx.scope.grant()
        && !grant.grant.plan.is_empty()
    {
        match ctx.ledger.plan_check(
            &call.handle,
            &grant.grant.plan,
            subject.tool,
            &origin,
            subject.class.name(),
        ) {
            PlanVerdict::Matches(index) => plan_step = Some(index),
            PlanVerdict::Outside => {
                return Err(ToolError::refused_with(
                    "outside_plan",
                    format!(
                        "{} on {origin} is not a step of the approved plan (digest {})",
                        subject.tool,
                        grant.grant.plan_digest().unwrap_or_default()
                    ),
                ));
            }
            PlanVerdict::NoPlan => {}
        }
    }

    let mut reasons: Vec<String> = Vec::new();
    if decision == Decision::Approval {
        reasons.push(format!("profile.{}", subject.class.name()));
    }
    if let Some(code) = subject.force_approval {
        reasons.push(code.to_owned());
    }
    if subject.consequential {
        match ctx.ledger.verdict(&call.handle) {
            Verdict::Proceed => {}
            Verdict::Warn => call.note("rule_of_two", json!("warn")),
            Verdict::NeedApproval => reasons.push("rule_of_two".to_owned()),
            Verdict::Refuse => {
                return Err(ToolError::refused_with(
                    "rule_of_two",
                    "untrusted input, sensitive context and a consequential capability are all present in this session, and the policy is strict: the call is refused. Only the operator can start a fresh session context (restart the server); reset_context is refused too.",
                ));
            }
        }
    }
    if !reasons.is_empty() {
        demand_approval(ctx, call, subject, subject.class.name(), origin, reasons)?;
    }
    if let (Some(index), Some(grant)) = (plan_step, ctx.scope.grant()) {
        ctx.ledger
            .plan_consume(&call.handle, grant.grant.plan.len(), index);
    }
    Ok(())
}

/// Lets the call run when the approval it carries covers exactly this action; otherwise answers
/// with the approval request a human is asked about.
fn demand_approval(
    ctx: &Ctx,
    call: &Call<'_>,
    subject: &Subject,
    class: &str,
    origin: String,
    reasons: Vec<String>,
) -> ToolResult<()> {
    let digest = digest_of(ctx, subject);
    if !call.take_approval(&digest) {
        let summary = if subject.target.is_empty() {
            format!("{} on {}.", subject.tool, subject.url)
        } else {
            format!(
                "{} on {} at {}.",
                subject.tool,
                quote_for_human(&subject.target, 80),
                subject.url
            )
        };
        return Err(ToolError::approval_required(ApprovalNeed {
            action_digest: digest,
            tool: subject.tool.to_owned(),
            class: class.to_owned(),
            origin,
            reasons,
            summary,
            plan_digest: ctx.scope.grant().and_then(|g| g.grant.plan_digest()),
            grant_digest: ctx.scope.grant().map(|g| g.digest.clone()),
        }));
    }
    call.note("approved", json!(true));
    Ok(())
}

/// Authorizes `reset_context`. A fresh handle clears the Rule of Two flags, so a model that
/// could reset on its own could drop the untrusted input or the sensitive context it holds and
/// then run the consequential call it was refused. While the handle holds either flag, the
/// reset needs a human approval (`enforce`) and is refused under `strict`; `warn` and `off`
/// leave it free, as they leave the Rule of Two itself.
///
/// # Errors
/// A refusal under `strict`, or the approval request under `enforce`.
pub fn authorize_reset(ctx: &Ctx, call: &Call<'_>) -> ToolResult<()> {
    let flags = ctx.ledger.flags(&call.handle);
    if !(flags.a || flags.b) {
        return Ok(());
    }
    match ctx.ledger.mode() {
        RuleOfTwoMode::Off => Ok(()),
        RuleOfTwoMode::Warn => {
            call.note("rule_of_two", json!("warn"));
            Ok(())
        }
        RuleOfTwoMode::Strict => Err(ToolError::refused_with(
            "reset_refused",
            "this session holds untrusted input or sensitive context and the policy is strict: a model cannot clear it with reset_context. The operator starts a fresh session context by restarting the server.",
        )),
        RuleOfTwoMode::Enforce => {
            let mut subject = Subject::plain("reset_context", ActionClass::Read, "about:blank");
            subject.target = "the session context".to_owned();
            demand_approval(
                ctx,
                call,
                &subject,
                "context_reset",
                "the session".to_owned(),
                vec!["reset_context".to_owned()],
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::testing::ctx_from;

    const BROWSE: &str =
        "[mcp]\ncapabilities = [\"browse\", \"interact\"]\n[browse]\nrequire_scope = false\n";

    fn call<'a>(ctx: &Ctx, approved: Option<&'a Approved>) -> Call<'a> {
        Call::new("click", "stdio", ctx.ledger.current("stdio"), approved)
    }

    fn subject(class: ActionClass) -> Subject {
        let mut s = Subject::plain("click", class, "https://app.example.test/");
        s.kind = Kind::Element;
        s.consequential = true;
        s.target = "button Delete".into();
        s
    }

    #[test]
    fn the_profile_table_decides_allow_approval_and_deny() {
        let (ctx, _dir) = ctx_from(&format!("{BROWSE}[safety.rule_of_two]\nmode = \"off\"\n"));
        let c = call(&ctx, None);
        assert!(authorize(&ctx, &c, &subject(ActionClass::SubmitStateChange)).is_ok());
        let need = authorize(&ctx, &c, &subject(ActionClass::Destructive)).unwrap_err();
        assert_eq!(need.kind, crate::error::FailKind::ApprovalRequired);
        let denied = authorize(&ctx, &c, &subject(ActionClass::Payment)).unwrap_err();
        assert_eq!(denied.reason(), Some("profile_denied"));
    }

    #[test]
    fn an_approval_covers_exactly_one_action_once() {
        let (ctx, _dir) = ctx_from(&format!("{BROWSE}[safety.rule_of_two]\nmode = \"off\"\n"));
        let need = authorize(&ctx, &call(&ctx, None), &subject(ActionClass::Destructive))
            .unwrap_err()
            .approval
            .unwrap();
        let approved = Approved {
            action_digest: need.action_digest.clone(),
        };
        let c = call(&ctx, Some(&approved));
        assert!(authorize(&ctx, &c, &subject(ActionClass::Destructive)).is_ok());
        // The same call state cannot spend it twice.
        assert!(authorize(&ctx, &c, &subject(ActionClass::Destructive)).is_err());
        // A different element or page is a different action.
        let c = call(&ctx, Some(&approved));
        let mut other = subject(ActionClass::Destructive);
        other.url = "https://app.example.test/other".into();
        let again = authorize(&ctx, &c, &other).unwrap_err();
        assert_ne!(again.approval.unwrap().action_digest, need.action_digest);
    }

    #[test]
    fn three_flags_turn_a_harmless_action_into_an_approval_request_or_a_refusal() {
        for (mode, refused) in [("enforce", false), ("strict", true)] {
            let (ctx, _dir) = ctx_from(&format!(
                "{BROWSE}[safety.rule_of_two]\nmode = \"{mode}\"\n"
            ));
            let c = call(&ctx, None);
            assert!(authorize(&ctx, &c, &subject(ActionClass::FormEdit)).is_ok());
            ctx.ledger.mark(&c.handle, Flag::A, "page read");
            // A loopback target is sensitive by default: B turns on through note_target.
            let mut s = subject(ActionClass::FormEdit);
            s.url = "http://127.0.0.1:8080/".into();
            let err = authorize(&ctx, &c, &s).unwrap_err();
            if refused {
                assert_eq!(err.reason(), Some("rule_of_two"));
            } else {
                assert_eq!(err.kind, crate::error::FailKind::ApprovalRequired);
                assert!(
                    err.approval
                        .unwrap()
                        .reasons
                        .contains(&"rule_of_two".to_owned())
                );
            }
        }
    }

    #[test]
    fn evaluate_is_allowed_unless_the_profile_is_read_only() {
        let (ctx, _dir) = ctx_from(&format!("{BROWSE}[safety.rule_of_two]\nmode = \"off\"\n"));
        let mut s = subject(ActionClass::Unknown);
        s.kind = Kind::Evaluate;
        s.tool = "evaluate_js";
        assert!(authorize(&ctx, &call(&ctx, None), &s).is_ok());
        let (ctx, _dir) = ctx_from(&format!(
            "{BROWSE}[safety]\nprofile = \"read_only\"\n[safety.rule_of_two]\nmode = \"off\"\n"
        ));
        assert_eq!(
            authorize(&ctx, &call(&ctx, None), &s).unwrap_err().reason(),
            Some("profile_denied")
        );
    }

    #[test]
    fn a_reset_is_free_until_the_handle_holds_untrusted_input_or_sensitive_context() {
        for mode in ["off", "warn", "enforce", "strict"] {
            for flag in [Flag::A, Flag::B] {
                let (ctx, _dir) = ctx_from(&format!(
                    "{BROWSE}[safety.rule_of_two]\nmode = \"{mode}\"\nprivate_network_is_sensitive = false\n"
                ));
                let c = call(&ctx, None);
                assert!(
                    authorize_reset(&ctx, &c).is_ok(),
                    "{mode}: nothing seen yet"
                );
                ctx.ledger.mark(&c.handle, flag, "seen");
                let outcome = authorize_reset(&ctx, &call(&ctx, None));
                match mode {
                    "off" | "warn" => assert!(outcome.is_ok(), "{mode}"),
                    "strict" => assert_eq!(
                        outcome.unwrap_err().reason(),
                        Some("reset_refused"),
                        "{flag:?}"
                    ),
                    _ => {
                        let need = outcome.unwrap_err().approval.unwrap();
                        assert_eq!(need.reasons, vec!["reset_context".to_owned()]);
                        let approved = Approved {
                            action_digest: need.action_digest,
                        };
                        assert!(authorize_reset(&ctx, &call(&ctx, Some(&approved))).is_ok());
                        // An approval of another action does not cover the reset.
                        let other = Approved {
                            action_digest: "0".repeat(64),
                        };
                        assert!(authorize_reset(&ctx, &call(&ctx, Some(&other))).is_err());
                    }
                }
            }
        }
    }

    #[test]
    fn private_hosts_are_recognized() {
        for private in [
            "http://127.0.0.1/",
            "http://localhost:3000/",
            "http://10.1.2.3/",
            "http://192.168.0.5/",
            "http://169.254.1.1/",
            "http://100.64.0.1/",
            "http://[::1]/",
            "http://[fd00::1]/",
            "http://db.internal/",
        ] {
            assert!(
                is_private_host(&url::Url::parse(private).unwrap()),
                "{private}"
            );
        }
        for public in [
            "https://example.test/",
            "http://8.8.8.8/",
            "http://100.128.0.1/",
        ] {
            assert!(
                !is_private_host(&url::Url::parse(public).unwrap()),
                "{public}"
            );
        }
    }
}
