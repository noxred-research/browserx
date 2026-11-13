//! Signed scope grants: what a session may read, where it may act and which steps it may take.
//!
//! A grant is a TOML document with a detached signature (same scheme as the manifest, domain
//! [`DOMAIN`]). It names read-only origins, read-write origins, allowed tools and action
//! classes, budgets, a validity window and an optional plan: an ordered list of
//! `{tool, origin, action_class, max_count}` steps. Page content can change data but not which
//! tools run, because a call outside the plan is refused (`outside_plan`).
//!
//! * Content of origins outside the read-only and read-write sets is never returned.
//! * Navigation targets built by the model must be read-write origins, or origins that were
//!   literally seen as a link or form action on a readable page. A URL that carries a
//!   secret-looking value to anything but a read-write origin is refused
//!   (`origin_not_in_rw`); to a read-write origin it needs an approval (exfiltration guard).
//! * A model may *propose* a grant. A proposal can only narrow the ceiling (the manifest, the
//!   configured origins or the active grant); it is inert until the operator signs it.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::crypto::{CryptoError, OperatorKeys};
use crate::manifest::{HostMode, Manifest};

/// Domain separation of the grant signature.
pub const DOMAIN: &[u8] = b"browserx/scope-grant/v1\0";

/// Most URLs remembered as observed.
const MAX_OBSERVED: usize = 20_000;

/// Why a grant could not be read or accepted.
#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// The cause.
        #[source]
        source: std::io::Error,
    },
    /// The TOML is malformed or inconsistent.
    #[error("invalid grant: {0}")]
    Invalid(String),
}

fn invalid(message: impl Into<String>) -> GrantError {
    GrantError::Invalid(message.into())
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct BudgetsRaw {
    calls: Option<u64>,
    time_secs: Option<u64>,
    /// Not supported yet: refused when present.
    #[serde(skip_serializing)]
    cost_usd: Option<toml::Value>,
}

/// One step of a plan.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlanStep {
    /// Tool name.
    pub tool: String,
    /// Origin the step acts on, or `*`.
    #[serde(default = "star")]
    pub origin: String,
    /// Action class, or `*`.
    #[serde(default = "star")]
    pub action_class: String,
    /// How often the step may run.
    #[serde(default = "one")]
    pub max_count: u32,
}

fn star() -> String {
    "*".into()
}
fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct GrantMeta {
    engagement: String,
    #[serde(default = "star")]
    principal: String,
    #[serde(default)]
    ro_origins: Vec<String>,
    #[serde(default)]
    rw_origins: Vec<String>,
    #[serde(default)]
    allowed_tools: Vec<String>,
    #[serde(default)]
    allowed_actions: Vec<String>,
    not_before: Option<String>,
    not_after: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct RawGrant {
    grant: GrantMeta,
    #[serde(default)]
    budgets: BudgetsRaw,
    #[serde(default)]
    plan: Vec<PlanStep>,
}

/// Budgets of a grant.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Budgets {
    /// Tool calls that touch pages.
    pub calls: Option<u64>,
    /// Seconds from the first call of a handle.
    pub time_secs: Option<u64>,
}

/// A parsed, validated grant.
#[derive(Debug, Clone)]
pub struct Grant {
    /// Engagement id the grant belongs to.
    pub engagement: String,
    /// Principal the grant applies to (`*` for any).
    pub principal: String,
    /// Origins whose content may be returned.
    pub ro_origins: BTreeSet<String>,
    /// Origins where actions are allowed (their content may also be returned).
    pub rw_origins: BTreeSet<String>,
    /// Tools allowed; empty means every enabled tool.
    pub allowed_tools: BTreeSet<String>,
    /// Action classes allowed; empty means every class the profile allows.
    pub allowed_actions: BTreeSet<String>,
    /// Earliest permitted time.
    pub not_before: Option<OffsetDateTime>,
    /// Latest permitted time.
    pub not_after: Option<OffsetDateTime>,
    /// Budgets.
    pub budgets: Budgets,
    /// The plan; empty means no plan constraint.
    pub plan: Vec<PlanStep>,
    raw: RawGrant,
}

fn origin_of(text: &str) -> Result<String, GrantError> {
    crate::config::normalize_origin(text).map_err(|e| invalid(e.to_string()))
}

fn parse_time(name: &str, raw: Option<&String>) -> Result<Option<OffsetDateTime>, GrantError> {
    raw.map(|text| {
        OffsetDateTime::parse(text, &Rfc3339)
            .map_err(|e| invalid(format!("grant.{name}: {e} (use RFC 3339)")))
    })
    .transpose()
}

impl Grant {
    /// Parses and validates grant text.
    ///
    /// # Errors
    /// When the TOML is malformed or a value is out of range.
    pub fn parse(text: &str) -> Result<Self, GrantError> {
        let raw: RawGrant = toml::from_str(text).map_err(|e| invalid(e.to_string()))?;
        Self::from_raw(raw)
    }

    fn from_raw(mut raw: RawGrant) -> Result<Self, GrantError> {
        if raw.budgets.cost_usd.is_some() {
            return Err(invalid(
                "budgets.cost_usd is not supported yet: remove it (no tool spends model budget under a grant)",
            ));
        }
        let meta = raw.grant.clone();
        if meta.engagement.trim().is_empty() {
            return Err(invalid("grant.engagement must not be empty"));
        }
        let ro_origins: BTreeSet<String> = meta
            .ro_origins
            .iter()
            .map(|o| origin_of(o))
            .collect::<Result<_, _>>()?;
        let rw_origins: BTreeSet<String> = meta
            .rw_origins
            .iter()
            .map(|o| origin_of(o))
            .collect::<Result<_, _>>()?;
        let not_before = parse_time("not_before", meta.not_before.as_ref())?;
        let not_after = parse_time("not_after", meta.not_after.as_ref())?;
        if let (Some(from), Some(to)) = (not_before, not_after)
            && from >= to
        {
            return Err(invalid("grant.not_before must be earlier than not_after"));
        }
        for action in &meta.allowed_actions {
            if crate::classifier::ActionClass::parse(action).is_none() {
                return Err(invalid(format!(
                    "grant.allowed_actions: unknown class {action:?}"
                )));
            }
        }
        if raw.plan.len() > 256 {
            return Err(invalid("a plan has at most 256 steps"));
        }
        for step in &raw.plan {
            if step.tool.is_empty() || step.max_count == 0 || step.max_count > 100_000 {
                return Err(invalid(
                    "plan steps need a tool and 0 < max_count <= 100000",
                ));
            }
            if step.action_class != "*"
                && crate::classifier::ActionClass::parse(&step.action_class).is_none()
            {
                return Err(invalid(format!(
                    "plan: unknown action class {:?}",
                    step.action_class
                )));
            }
        }
        // A step's origin is compared with the origin of the page, which is always in the
        // normalized form (`https://app.test`, never `https://App.test:443/`).
        for step in &mut raw.plan {
            if step.origin != "*" {
                step.origin = origin_of(&step.origin)?;
            }
        }
        raw.grant.ro_origins = ro_origins.iter().cloned().collect();
        raw.grant.rw_origins = rw_origins.iter().cloned().collect();
        let budgets = Budgets {
            calls: raw.budgets.calls,
            time_secs: raw.budgets.time_secs,
        };
        if budgets.calls == Some(0) || budgets.time_secs == Some(0) {
            return Err(invalid("budgets must be positive"));
        }
        Ok(Self {
            engagement: meta.engagement,
            principal: meta.principal,
            ro_origins,
            rw_origins,
            allowed_tools: meta.allowed_tools.into_iter().collect(),
            allowed_actions: meta.allowed_actions.into_iter().collect(),
            not_before,
            not_after,
            budgets,
            plan: raw.plan.clone(),
            raw,
        })
    }

    /// The canonical TOML of the grant (what an operator signs after review).
    ///
    /// # Errors
    /// When the grant cannot be serialized.
    pub fn to_toml(&self) -> Result<String, GrantError> {
        toml::to_string_pretty(&self.raw).map_err(|e| invalid(e.to_string()))
    }

    /// SHA-256 over the plan, recorded in the audit log and bound into approvals.
    #[must_use]
    pub fn plan_digest(&self) -> Option<String> {
        plan_digest(&self.plan)
    }

    /// Whether the grant applies to `principal`.
    #[must_use]
    pub fn applies_to(&self, principal: &str) -> bool {
        self.principal == "*" || self.principal == principal
    }

    /// The time window verdict at `now`: `Ok` or the refusal reason.
    ///
    /// # Errors
    /// A message naming the bound that is violated.
    pub fn check_window(&self, now: OffsetDateTime) -> Result<(), String> {
        if let Some(from) = self.not_before
            && now < from
        {
            return Err(format!(
                "the scope grant starts at {}",
                from.format(&Rfc3339).unwrap_or_default()
            ));
        }
        if let Some(to) = self.not_after
            && now > to
        {
            return Err(format!(
                "the scope grant ended at {}",
                to.format(&Rfc3339).unwrap_or_default()
            ));
        }
        Ok(())
    }

    /// Whether `origin` may be read (read-only or read-write).
    #[must_use]
    pub fn can_read(&self, origin: &str) -> bool {
        self.ro_origins.contains(origin) || self.rw_origins.contains(origin)
    }

    /// Whether actions are allowed on `origin`.
    #[must_use]
    pub fn can_write(&self, origin: &str) -> bool {
        self.rw_origins.contains(origin)
    }

    /// Whether a tool is allowed (monitoring tools are the caller's concern).
    #[must_use]
    pub fn allows_tool(&self, tool: &str) -> bool {
        self.allowed_tools.is_empty() || self.allowed_tools.contains(tool)
    }

    /// Whether an action class is allowed.
    #[must_use]
    pub fn allows_action(&self, class: &str) -> bool {
        self.allowed_actions.is_empty() || self.allowed_actions.contains(class)
    }

    /// Checks that this grant (or proposal) does not widen `ceiling`. Returns every violation.
    #[must_use]
    pub fn violations_against(&self, ceiling: &Ceiling<'_>) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(engagement) = ceiling.engagement
            && self.engagement != engagement
        {
            out.push(format!(
                "the grant names engagement {:?}, not {engagement:?}",
                self.engagement
            ));
        }
        for (set, write) in [(&self.ro_origins, false), (&self.rw_origins, true)] {
            for origin in set {
                if let Some(why) = ceiling.refuses_origin(origin, write) {
                    out.push(why);
                }
            }
        }
        if let (Some(limit), Some(mine)) = (ceiling.max_calls, self.budgets.calls)
            && mine > limit
        {
            out.push(format!("budgets.calls {mine} exceeds the ceiling {limit}"));
        }
        if ceiling.max_calls.is_some() && self.budgets.calls.is_none() {
            out.push("budgets.calls must be set when the ceiling sets limits.max_calls".into());
        }
        if let Some(limit) = ceiling.not_after {
            match self.not_after {
                Some(mine) if mine <= limit => {}
                _ => out.push("not_after must be set and not later than the ceiling".into()),
            }
        }
        if let Some(base) = ceiling.grant {
            self.violations_against_grant(base, &mut out);
            if !base.allowed_tools.is_empty()
                && (self.allowed_tools.is_empty()
                    || !self.allowed_tools.is_subset(&base.allowed_tools))
            {
                out.push("allowed_tools widens the active grant".into());
            }
            if !base.allowed_actions.is_empty()
                && (self.allowed_actions.is_empty()
                    || !self.allowed_actions.is_subset(&base.allowed_actions))
            {
                out.push("allowed_actions widens the active grant".into());
            }
        }
        out
    }

    /// What this grant (or proposal) does not narrow of the active grant `base`: budgets, the
    /// start of the window and the plan. A plan narrows when every step is covered by a step of
    /// the active plan (same tool, an origin and action class the base step names or `*`) and,
    /// summed per base step, asks for no more runs than it allows.
    fn violations_against_grant(&self, base: &Grant, out: &mut Vec<String>) {
        for (name, mine, limit) in [
            ("calls", self.budgets.calls, base.budgets.calls),
            ("time_secs", self.budgets.time_secs, base.budgets.time_secs),
        ] {
            match (mine, limit) {
                (_, None) => {}
                (Some(mine), Some(limit)) if mine <= limit => {}
                (Some(mine), Some(limit)) => out.push(format!(
                    "budgets.{name} {mine} exceeds the active grant's {limit}"
                )),
                (None, Some(limit)) => out.push(format!(
                    "budgets.{name} must be set: the active grant limits it to {limit}"
                )),
            }
        }
        if let Some(from) = base.not_before
            && !self.not_before.is_some_and(|mine| mine >= from)
        {
            out.push("not_before must be set and not earlier than the active grant's".into());
        }
        if base.plan.is_empty() {
            return;
        }
        if self.plan.is_empty() {
            out.push(
                "the plan is missing: the active grant has one, and a proposal must keep to it"
                    .into(),
            );
            return;
        }
        let mut asked = vec![0_u64; base.plan.len()];
        for (number, step) in self.plan.iter().enumerate() {
            let covering = base.plan.iter().position(|allowed| {
                allowed.tool == step.tool
                    && (allowed.origin == "*" || allowed.origin == step.origin)
                    && (allowed.action_class == "*" || allowed.action_class == step.action_class)
            });
            match covering {
                Some(index) => {
                    asked[index] = asked[index].saturating_add(u64::from(step.max_count));
                }
                None => out.push(format!(
                    "plan step {} ({} on {} as {}) is not a step of the active plan",
                    number + 1,
                    step.tool,
                    step.origin,
                    step.action_class
                )),
            }
        }
        for (index, total) in asked.iter().enumerate() {
            let allowed = u64::from(base.plan[index].max_count);
            if *total > allowed {
                out.push(format!(
                    "the plan asks for {total} runs of step {} of the active plan, which allows {allowed}",
                    index + 1
                ));
            }
        }
    }
}

/// What a grant may not exceed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ceiling<'a> {
    /// The engagement id the grant must name.
    pub engagement: Option<&'a str>,
    /// The manifest: its hosts bound the origins.
    pub manifest: Option<&'a Manifest>,
    /// Configured origins (`browse.allowed_origins`); empty means no extra bound.
    pub origins: &'a [String],
    /// The active grant, when a proposal narrows it.
    pub grant: Option<&'a Grant>,
    /// `limits.max_calls` of the manifest.
    pub max_calls: Option<u64>,
    /// The manifest's `not_after`.
    pub not_after: Option<OffsetDateTime>,
}

impl Ceiling<'_> {
    fn refuses_origin(&self, origin: &str, write: bool) -> Option<String> {
        let parsed = url::Url::parse(origin).ok()?;
        if let Some(manifest) = self.manifest {
            match manifest.host_mode(&parsed) {
                Some(HostMode::Attack) => {}
                Some(HostMode::Visit) if !write => {}
                Some(HostMode::Visit) => {
                    return Some(format!(
                        "{origin} is visit-only in the manifest and cannot be read-write"
                    ));
                }
                Some(HostMode::Blocked) | None => {
                    return Some(format!("{origin} is not permitted by the manifest"));
                }
            }
        }
        if !self.origins.is_empty() && !self.origins.iter().any(|o| o == origin) {
            return Some(format!("{origin} is outside the configured origins"));
        }
        if let Some(base) = self.grant {
            let allowed = if write {
                base.can_write(origin)
            } else {
                base.can_read(origin)
            };
            if !allowed {
                return Some(format!("{origin} is outside the active grant"));
            }
        }
        None
    }
}

/// SHA-256 over a plan's canonical JSON; `None` for an empty plan.
#[must_use]
pub fn plan_digest(plan: &[PlanStep]) -> Option<String> {
    if plan.is_empty() {
        return None;
    }
    let value = serde_json::to_value(plan).unwrap_or(Value::Null);
    Some(hex::encode(Sha256::digest(
        crate::audit::canonical_json(&value).as_bytes(),
    )))
}

/// How the grant's signature stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// Verified; the key id.
    Valid(String),
    /// No signature file.
    Missing,
    /// The signature did not verify.
    Invalid(String),
}

/// A grant with its signature state and content digest.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The grant.
    pub grant: Grant,
    /// SHA-256 of the file bytes, recorded in the audit log.
    pub digest: String,
    /// Signature state.
    pub signature: Signature,
}

impl Loaded {
    /// Reads and verifies a grant and its detached signature.
    ///
    /// # Errors
    /// When the file cannot be read or parsed.
    pub fn load(
        path: &Path,
        signature_path: &Path,
        keys: &OperatorKeys,
    ) -> Result<Self, GrantError> {
        let bytes = std::fs::read(path).map_err(|source| GrantError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("the grant is not UTF-8"))?;
        let grant = Grant::parse(text)?;
        let signature = match std::fs::read_to_string(signature_path) {
            Ok(line) => match keys.verify(&line, DOMAIN, &bytes) {
                Ok(key_id) => Signature::Valid(key_id),
                Err(CryptoError::Mismatch) => {
                    Signature::Invalid("the signature does not match the grant".into())
                }
                Err(other) => Signature::Invalid(other.to_string()),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Signature::Missing,
            Err(e) => Signature::Invalid(format!("cannot read the signature: {e}")),
        };
        Ok(Self {
            grant,
            digest: hex::encode(Sha256::digest(&bytes)),
            signature,
        })
    }

    /// Whether the signature verified.
    #[must_use]
    pub fn trusted(&self) -> bool {
        matches!(self.signature, Signature::Valid(_))
    }
}

/// Signs grant text under `key_id`.
///
/// # Errors
/// When the key id is unknown.
pub fn sign(keys: &OperatorKeys, key_id: &str, bytes: &[u8]) -> Result<String, CryptoError> {
    keys.sign(key_id, DOMAIN, bytes)
}

/// The active grant plus the URLs observed on readable pages.
#[derive(Debug)]
pub struct Active {
    /// The verified grant.
    pub grant: Grant,
    /// SHA-256 of the file.
    pub digest: String,
    observed: Mutex<Observed>,
}

#[derive(Debug, Default)]
struct Observed {
    set: HashSet<String>,
    order: VecDeque<String>,
}

fn observed_key(url: &url::Url) -> String {
    let mut copy = url.clone();
    copy.set_fragment(None);
    copy.as_str().to_owned()
}

impl Active {
    /// Wraps a verified grant.
    #[must_use]
    pub fn new(grant: Grant, digest: String) -> Self {
        Self {
            grant,
            digest,
            observed: Mutex::new(Observed::default()),
        }
    }

    /// Records URLs seen as links or form actions on a readable page.
    pub fn observe<'a>(&self, urls: impl IntoIterator<Item = &'a str>) {
        let mut observed = self.observed.lock().unwrap_or_else(PoisonError::into_inner);
        for raw in urls {
            let Ok(url) = url::Url::parse(raw) else {
                continue;
            };
            if !matches!(url.scheme(), "http" | "https") {
                continue;
            }
            let key = observed_key(&url);
            if observed.set.insert(key.clone()) {
                observed.order.push_back(key);
                if observed.order.len() > MAX_OBSERVED
                    && let Some(old) = observed.order.pop_front()
                {
                    observed.set.remove(&old);
                }
            }
        }
    }

    /// Whether `url` was literally seen on a readable page.
    #[must_use]
    pub fn was_observed(&self, url: &url::Url) -> bool {
        self.observed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set
            .contains(&observed_key(url))
    }
}

/// Whether a value looks like a credential: a known prefix, a JWT, a long hex string or a long
/// high-entropy token.
#[must_use]
pub fn looks_secret(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 20 {
        return false;
    }
    const PREFIXES: [&str; 12] = [
        "bxk_",
        "bxt_",
        "bxm_",
        "sk-",
        "ghp_",
        "gho_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "ASIA",
        "Bearer ",
    ];
    if PREFIXES.iter().any(|p| value.starts_with(p)) {
        return true;
    }
    if value.starts_with("eyJ") && value.matches('.').count() == 2 {
        return true;
    }
    let token_chars = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '='));
    if !token_chars {
        return false;
    }
    if value.len() >= 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    entropy_bits_per_char(value) >= 3.6
        && value.chars().any(|c| c.is_ascii_digit())
        && value.chars().any(|c| c.is_ascii_alphabetic())
}

fn entropy_bits_per_char(text: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let mut total = 0_u32;
    for c in text.chars() {
        *counts.entry(c).or_insert(0_u32) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total = f64::from(total);
    counts
        .values()
        .map(|n| {
            let p = f64::from(*n) / total;
            -p * p.log2()
        })
        .sum()
}

/// Whether `text`, or any piece of it between the separators that hold `key=value` lists
/// (`=`, `&`, `;`, `,`), once percent-decoded, looks like a credential.
fn text_carries_secret(text: &str) -> bool {
    let decoded = crate::manifest::percent_decode(text);
    looks_secret(&decoded)
        || looks_secret(text)
        || decoded.split(['=', '&', ';', ',']).any(looks_secret)
}

/// Whether a URL carries a secret-looking value in a query key or value, a path segment or the
/// fragment, as written or percent-decoded (`sk%2D...`).
#[must_use]
pub fn url_carries_secret(url: &url::Url) -> bool {
    url.query_pairs()
        .any(|(key, value)| looks_secret(&key) || looks_secret(&value))
        || url
            .path_segments()
            .is_some_and(|mut segments| segments.any(text_carries_secret))
        || url.fragment().is_some_and(text_carries_secret)
}

/// Progress through a plan, per handle: steps run in order, earlier steps close when a later
/// one is used, and every step has a count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanProgress {
    next: usize,
    used: Vec<u32>,
}

/// The outcome of a plan check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanVerdict {
    /// No plan applies.
    NoPlan,
    /// The call matches step `index`.
    Matches(usize),
    /// The call is not in the plan.
    Outside,
}

impl PlanProgress {
    /// Checks a call (`tool`, the origin it acts on, its action class) against `plan` without
    /// consuming anything.
    #[must_use]
    pub fn check(&self, plan: &[PlanStep], tool: &str, origin: &str, class: &str) -> PlanVerdict {
        if plan.is_empty() {
            return PlanVerdict::NoPlan;
        }
        for (index, step) in plan.iter().enumerate().skip(self.next) {
            let used = self.used.get(index).copied().unwrap_or(0);
            if step.tool == tool
                && (step.origin == "*" || step.origin == origin)
                && (step.action_class == "*" || step.action_class == class)
                && used < step.max_count
            {
                return PlanVerdict::Matches(index);
            }
        }
        PlanVerdict::Outside
    }

    /// Consumes one use of step `index`; earlier steps close.
    pub fn consume(&mut self, plan_len: usize, index: usize) {
        if self.used.len() < plan_len {
            self.used.resize(plan_len, 0);
        }
        if let Some(slot) = self.used.get_mut(index) {
            *slot = slot.saturating_add(1);
        }
        self.next = self.next.max(index);
    }
}

/// A proposal rendered for the operator.
#[must_use]
pub fn proposal_summary(grant: &Grant, violations: &[String]) -> Value {
    json!({
        "active": false,
        "narrows_the_ceiling": violations.is_empty(),
        "violations": violations,
        "ro_origins": grant.ro_origins,
        "rw_origins": grant.rw_origins,
        "allowed_tools": grant.allowed_tools,
        "allowed_actions": grant.allowed_actions,
        "plan_digest": grant.plan_digest(),
        "next": "A proposal does nothing until the operator reviews and signs it with `browserx mcp grant sign`.",
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const SAMPLE: &str = r#"
[grant]
engagement = "eng-1"
principal = "*"
ro_origins = ["https://cdn.example.test"]
rw_origins = ["https://app.example.test"]
allowed_tools = ["open_page", "page_snapshot", "click"]
allowed_actions = ["read", "navigate_in_scope"]
not_after = "2099-01-01T00:00:00Z"

[budgets]
calls = 50
time_secs = 600

[[plan]]
tool = "open_page"
origin = "https://app.example.test"
action_class = "navigate_in_scope"
max_count = 2

[[plan]]
tool = "page_snapshot"
max_count = 5

[[plan]]
tool = "click"
action_class = "navigate_in_scope"
max_count = 1
"#;

    fn keys() -> OperatorKeys {
        let mut keys = OperatorKeys::new();
        keys.insert("op1", vec![5; 32]).unwrap();
        keys
    }

    #[test]
    fn a_signed_grant_loads_and_a_forged_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grant.toml");
        let sig = dir.path().join("grant.toml.sig");
        std::fs::write(&path, SAMPLE).unwrap();
        std::fs::write(&sig, sign(&keys(), "op1", SAMPLE.as_bytes()).unwrap()).unwrap();
        let loaded = Loaded::load(&path, &sig, &keys()).unwrap();
        assert!(loaded.trusted());
        assert!(loaded.grant.can_write("https://app.example.test"));
        assert!(loaded.grant.can_read("https://cdn.example.test"));
        assert!(!loaded.grant.can_write("https://cdn.example.test"));
        assert!(loaded.grant.plan_digest().is_some());

        // Flip one byte of the body: the signature no longer matches.
        std::fs::write(&path, SAMPLE.replace("calls = 50", "calls = 59")).unwrap();
        let forged = Loaded::load(&path, &sig, &keys()).unwrap();
        assert!(!forged.trusted());
        std::fs::remove_file(&sig).unwrap();
        assert_eq!(
            Loaded::load(&path, &sig, &keys()).unwrap().signature,
            Signature::Missing
        );
    }

    #[test]
    fn proposals_may_only_narrow_the_ceiling() {
        let base = Grant::parse(SAMPLE).unwrap();
        let ceiling = Ceiling {
            engagement: Some("eng-1"),
            grant: Some(&base),
            ..Ceiling::default()
        };
        let narrower = Grant::parse(
            &SAMPLE
                .replace(
                    "allowed_tools = [\"open_page\", \"page_snapshot\", \"click\"]",
                    "allowed_tools = [\"open_page\"]",
                )
                .replace(
                    "rw_origins = [\"https://app.example.test\"]",
                    "rw_origins = []\n",
                ),
        )
        .unwrap();
        assert_eq!(narrower.violations_against(&ceiling), Vec::<String>::new());
        let wider = Grant::parse(&SAMPLE.replace(
            "ro_origins = [\"https://cdn.example.test\"]",
            "ro_origins = [\"https://cdn.example.test\", \"https://evil.test\"]",
        ))
        .unwrap();
        let violations = wider.violations_against(&ceiling);
        assert!(
            violations.iter().any(|v| v.contains("evil.test")),
            "{violations:?}"
        );
        let more_tools = Grant::parse(&SAMPLE.replace(
            "allowed_tools = [\"open_page\", \"page_snapshot\", \"click\"]",
            "allowed_tools = [\"open_page\", \"evaluate_js\"]",
        ))
        .unwrap();
        assert!(!more_tools.violations_against(&ceiling).is_empty());
        let no_limit = Grant::parse(&SAMPLE.replace(
            "allowed_tools = [\"open_page\", \"page_snapshot\", \"click\"]",
            "",
        ))
        .unwrap();
        assert!(!no_limit.violations_against(&ceiling).is_empty());
    }

    #[test]
    fn proposals_cannot_loosen_budgets_the_window_or_the_plan() {
        let base = Grant::parse(SAMPLE).unwrap();
        let ceiling = Ceiling {
            engagement: Some("eng-1"),
            grant: Some(&base),
            ..Ceiling::default()
        };
        let violations = |text: &str| Grant::parse(text).unwrap().violations_against(&ceiling);
        assert_eq!(violations(SAMPLE), Vec::<String>::new());

        for (what, text) in [
            ("more calls", SAMPLE.replace("calls = 50", "calls = 51")),
            ("no calls budget", SAMPLE.replace("calls = 50\n", "")),
            (
                "more time",
                SAMPLE.replace("time_secs = 600", "time_secs = 601"),
            ),
            ("no time budget", SAMPLE.replace("time_secs = 600\n", "")),
            (
                "no plan",
                SAMPLE.split("[[plan]]").next().unwrap().to_owned(),
            ),
            (
                "a step that is not in the plan",
                SAMPLE.replace("tool = \"click\"", "tool = \"evaluate_js\""),
            ),
            (
                "a step on another origin",
                SAMPLE.replace(
                    "origin = \"https://app.example.test\"",
                    "origin = \"https://cdn.example.test\"",
                ),
            ),
            (
                "a step on any origin where the plan names one",
                SAMPLE.replace("origin = \"https://app.example.test\"", "origin = \"*\""),
            ),
            (
                "a step of another class",
                SAMPLE.replace(
                    "action_class = \"navigate_in_scope\"\nmax_count = 2",
                    "action_class = \"destructive\"\nmax_count = 2",
                ),
            ),
            (
                "a step that runs more often",
                SAMPLE.replace("max_count = 5", "max_count = 6"),
            ),
            (
                "two steps that share one step of the plan",
                format!(
                    "{SAMPLE}\n[[plan]]\ntool = \"open_page\"\norigin = \"https://app.example.test\"\naction_class = \"navigate_in_scope\"\nmax_count = 1\n"
                ),
            ),
        ] {
            assert!(!violations(&text).is_empty(), "{what} must not narrow");
        }

        // Fewer calls, fewer steps and a smaller count do narrow.
        let narrower = SAMPLE
            .replace("calls = 50", "calls = 10")
            .replace("max_count = 5", "max_count = 2");
        let narrower = narrower.split("[[plan]]\ntool = \"click\"").next().unwrap();
        assert_eq!(violations(narrower), Vec::<String>::new());

        // The start of the window cannot move earlier either.
        let started = Grant::parse(&SAMPLE.replace(
            "not_after =",
            "not_before = \"2030-01-01T00:00:00Z\"\nnot_after =",
        ))
        .unwrap();
        let ceiling = Ceiling {
            grant: Some(&started),
            ..Ceiling::default()
        };
        assert!(!base.violations_against(&ceiling).is_empty());
        let earlier = Grant::parse(&SAMPLE.replace(
            "not_after =",
            "not_before = \"2029-01-01T00:00:00Z\"\nnot_after =",
        ))
        .unwrap();
        assert!(!earlier.violations_against(&ceiling).is_empty());
        let later = Grant::parse(&SAMPLE.replace(
            "not_after =",
            "not_before = \"2031-01-01T00:00:00Z\"\nnot_after =",
        ))
        .unwrap();
        assert!(later.violations_against(&ceiling).is_empty());
    }

    #[test]
    fn plan_origins_are_stored_in_the_form_pages_report() {
        let grant = Grant::parse(&SAMPLE.replace(
            "origin = \"https://app.example.test\"",
            "origin = \"https://App.Example.test:443/\"",
        ))
        .unwrap();
        assert_eq!(grant.plan[0].origin, "https://app.example.test");
        assert_eq!(
            PlanProgress::default().check(
                &grant.plan,
                "open_page",
                "https://app.example.test",
                "navigate_in_scope"
            ),
            PlanVerdict::Matches(0)
        );
        assert!(
            grant
                .to_toml()
                .unwrap()
                .contains("origin = \"https://app.example.test\"")
        );
        assert!(
            Grant::parse(&SAMPLE.replace(
                "origin = \"https://app.example.test\"",
                "origin = \"nonsense\""
            ))
            .is_err()
        );
    }

    #[test]
    fn manifest_ceiling_bounds_origins_and_modes() {
        let manifest = Manifest::parse(
            r#"
[engagement]
id = "eng-1"
operator = "a"
authorization_note = "n"
[[scope]]
host = "app.example.test"
mode = "attack"
[[scope]]
host = "cdn.example.test"
mode = "visit"
[limits]
max_calls = 100
"#,
        )
        .unwrap();
        let ceiling = Ceiling {
            engagement: Some("eng-1"),
            manifest: Some(&manifest),
            max_calls: manifest.limits.max_calls,
            ..Ceiling::default()
        };
        assert_eq!(
            Grant::parse(SAMPLE).unwrap().violations_against(&ceiling),
            Vec::<String>::new()
        );
        let rw_visit = Grant::parse(&SAMPLE.replace(
            "rw_origins = [\"https://app.example.test\"]",
            "rw_origins = [\"https://cdn.example.test\"]",
        ))
        .unwrap();
        assert!(
            rw_visit
                .violations_against(&ceiling)
                .iter()
                .any(|v| v.contains("visit-only"))
        );
        let over_budget = Grant::parse(&SAMPLE.replace("calls = 50", "calls = 500")).unwrap();
        assert!(!over_budget.violations_against(&ceiling).is_empty());
    }

    #[test]
    fn plan_steps_run_in_order_with_counts() {
        let grant = Grant::parse(SAMPLE).unwrap();
        let mut progress = PlanProgress::default();
        let app = "https://app.example.test";
        let verdict =
            |p: &PlanProgress, tool: &str, class: &str| p.check(&grant.plan, tool, app, class);
        assert_eq!(
            verdict(&progress, "open_page", "navigate_in_scope"),
            PlanVerdict::Matches(0)
        );
        assert_eq!(
            verdict(&progress, "evaluate_js", "unknown"),
            PlanVerdict::Outside
        );
        assert_eq!(
            verdict(&progress, "click", "destructive"),
            PlanVerdict::Outside
        );
        progress.consume(3, 0);
        progress.consume(3, 0);
        assert_eq!(
            verdict(&progress, "open_page", "navigate_in_scope"),
            PlanVerdict::Outside
        );
        assert_eq!(
            verdict(&progress, "page_snapshot", "read"),
            PlanVerdict::Matches(1)
        );
        progress.consume(3, 2);
        // Using the click step closed the earlier ones.
        assert_eq!(
            verdict(&progress, "page_snapshot", "read"),
            PlanVerdict::Outside
        );
        assert_eq!(
            verdict(&progress, "click", "navigate_in_scope"),
            PlanVerdict::Outside
        );
        assert_eq!(
            PlanProgress::default().check(&[], "x", app, "read"),
            PlanVerdict::NoPlan
        );
    }

    #[test]
    fn secret_shaped_values_are_recognized() {
        for secret in [
            "bxk_test_0123456789abcdef",
            "sk-0123456789abcdefghij",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk",
            "0123456789abcdef0123456789abcdef",
            "Zk3Hq9XpL2vB7nTr5WcYd8Ae",
        ] {
            assert!(looks_secret(secret), "{secret}");
        }
        for plain in [
            "hello",
            "a-fairly-long-readable-slug",
            "2026-11-13",
            "aaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(!looks_secret(plain), "{plain}");
        }
        let url = url::Url::parse("https://evil.test/?q=bxk_test_0123456789abcdef").unwrap();
        assert!(url_carries_secret(&url));
        assert!(!url_carries_secret(
            &url::Url::parse("https://a.test/search?q=boots").unwrap()
        ));
    }

    #[test]
    fn secrets_are_found_in_query_keys_and_in_encoded_paths_and_fragments() {
        let token = ["Zk3Hq9XpL2vB", "7nTr5WcYd8Ae"].concat();
        let bxk = ["bxk", "test", "0123456789abcdef"].join("_");
        let leaky_owned = [
            format!("https://evil.test/#access_token={token}"),
            format!("https://evil.test/a;key={bxk}"),
        ];
        for leaky in leaky_owned.iter().map(String::as_str).chain([
            "https://evil.test/?sk-0123456789abcdefghij",
            "https://evil.test/?sk-0123456789abcdefghij=1",
            "https://evil.test/?bxk_test_0123456789abcdef=",
            "https://evil.test/sk%2D0123456789abcdefghij",
            "https://evil.test/a/%62xk_test_0123456789abcdef/b",
            "https://evil.test/#sk%2D0123456789abcdefghij",
            "https://evil.test/?q=sk%2D0123456789abcdefghij",
        ]) {
            assert!(
                url_carries_secret(&url::Url::parse(leaky).unwrap()),
                "{leaky}"
            );
        }
        for harmless in [
            "https://a.test/search?q=boots&page=2#top",
            "https://a.test/a-fairly-long-readable-slug/",
            "https://a.test/?utm_source=newsletter&utm_medium=email",
            "https://a.test/docs#installing-on-linux",
        ] {
            assert!(
                !url_carries_secret(&url::Url::parse(harmless).unwrap()),
                "{harmless}"
            );
        }
    }

    #[test]
    fn observed_urls_ignore_fragments_and_are_bounded() {
        let active = Active::new(Grant::parse(SAMPLE).unwrap(), "d".into());
        active.observe([
            "https://app.example.test/a#top",
            "javascript:alert(1)",
            "not a url",
        ]);
        assert!(active.was_observed(&url::Url::parse("https://app.example.test/a").unwrap()));
        assert!(!active.was_observed(&url::Url::parse("https://app.example.test/b").unwrap()));
    }

    #[test]
    fn a_cost_budget_is_refused_not_ignored() {
        let error = Grant::parse(&SAMPLE.replace("calls = 50", "calls = 50\ncost_usd = 2.0"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("cost_usd") && error.contains("not supported yet"),
            "{error}"
        );
    }

    #[test]
    fn malformed_grants_are_rejected() {
        for bad in [
            SAMPLE.replace("\"navigate_in_scope\"]", "\"teleport\"]"),
            SAMPLE.replace("max_count = 2", "max_count = 0"),
            SAMPLE.replace("calls = 50", "calls = 0"),
            SAMPLE.replace("https://cdn.example.test", "https://cdn.example.test/path"),
            SAMPLE.replace("[grant]", "[grant]\nextra = 1"),
        ] {
            assert!(Grant::parse(&bad).is_err(), "{bad}");
        }
    }
}
