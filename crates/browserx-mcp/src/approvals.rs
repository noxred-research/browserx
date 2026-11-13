//! Human approvals for consequential calls.
//!
//! A tool that needs an approval does not run. It answers in one of two ways:
//!
//! * **Multi round-trip request** (protocol `2026-07-28`, client declared `elicitation`): the
//!   result is `input_required` with an elicitation form and an opaque `requestState`. The
//!   state is an AES-256-GCM box under a per-process random key, bound to the principal, the
//!   tool, a digest of the request, the digest of the action to approve, an expiry and a random
//!   nonce. The client shows the form, retries the same request with the user's answer and
//!   the state, and the server verifies the state, consumes its nonce (single use, enforced
//!   here: a signed state alone does not make an approval single use) and runs the call once.
//!   Tampered state or state sealed for another principal is refused; consumed or expired state
//!   yields a fresh request.
//! * **Out-of-band** (any other client): the result is a structured refusal with an approval id
//!   and a pending record on disk. The operator approves the id with `browserx mcp approvals
//!   approve`, which signs the record with the operator key; the client retries with
//!   `approval_id`. The signed record is single use across processes: it is renamed before the
//!   call runs.
//!
//! `confirm: true` is an intent flag the model sets about its own call. It never counts as an
//! approval: what needs a human is decided by the action class and the ledger.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use rand::Rng as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::audit::canonical_json;
use crate::crypto::{CryptoError, OperatorKeys, StateBox};

/// Domain separation of the sealed state.
const STATE_DOMAIN: &[u8] = b"browserx/mrtr-state/v1\0";
/// Domain separation of the operator's approval signature.
pub const APPROVAL_DOMAIN: &[u8] = b"browserx/approval/v1\0";
/// Most unexpired nonces remembered.
const MAX_CONSUMED: usize = 8192;
/// Most pending out-of-band approvals.
const MAX_PENDING: usize = 256;

/// Why an approval could not be recorded or granted.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    /// The approvals directory could not be used.
    #[error("approvals directory: {0}")]
    Io(#[from] std::io::Error),
    /// Too many requests are waiting.
    #[error("too many approval requests are pending")]
    TooManyPending,
    /// The record is missing, expired or malformed.
    #[error("approval {0}: {1}")]
    Record(String, String),
    /// The signature could not be made.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// What a human is asked to approve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalNeed {
    /// Digest of the exact action (tool, class, page URL, element, arguments).
    pub action_digest: String,
    /// The tool.
    pub tool: String,
    /// The action class.
    pub class: String,
    /// The origin the action happens on.
    pub origin: String,
    /// Why an approval is needed (rule ids).
    pub reasons: Vec<String>,
    /// A short description for the human; page-derived text in it is quoted and bounded.
    pub summary: String,
    /// Digest of the active plan, bound into the approval.
    pub plan_digest: Option<String>,
    /// Digest of the active grant.
    pub grant_digest: Option<String>,
}

/// An approval that was granted for one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    /// The action digest that was approved. The gate recomputes the digest before it runs; a
    /// page that changed in between produces a different digest and a new request.
    pub action_digest: String,
}

/// The outcome of presenting approval evidence with a retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resume {
    /// Approved: run the call once.
    Approved(Approved),
    /// The human declined.
    Declined,
    /// The evidence is consumed, expired or missing: start a fresh request.
    Fresh,
    /// The out-of-band approval exists but is not signed yet.
    Pending(String),
    /// The evidence is invalid for this caller or request.
    Refused(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct StatePayload {
    v: u8,
    tool: String,
    request: String,
    action: String,
    exp: i64,
    nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Pending {
    id: String,
    principal: String,
    tool: String,
    request: String,
    action: String,
    class: String,
    origin: String,
    reasons: Vec<String>,
    summary: String,
    created: i64,
    expires: i64,
}

/// The approval engine.
#[derive(Debug)]
pub struct Approvals {
    state_box: StateBox,
    keys: Option<OperatorKeys>,
    dir: PathBuf,
    ttl_secs: i64,
    consumed: Mutex<HashMap<String, i64>>,
}

/// The digest binding an approval to a request: the tool and its arguments, without the
/// approval id the client adds on a retry.
#[must_use]
pub fn request_digest(tool: &str, arguments: &Value) -> String {
    let mut args = arguments.clone();
    if let Some(map) = args.as_object_mut() {
        map.remove("approval_id");
    }
    let canonical = canonical_json(&json!({ "tool": tool, "arguments": args }));
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

/// Replaces control characters and bounds length, for page-derived text shown to a human.
#[must_use]
pub fn quote_for_human(text: &str, max: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max)
        .collect();
    format!("\u{201c}{}\u{201d}", cleaned.trim())
}

fn valid_id(id: &str) -> bool {
    id.strip_prefix("apr_").is_some_and(|rest| {
        rest.len() == 24
            && rest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

impl Approvals {
    /// An engine with a fresh random sealing key.
    #[must_use]
    pub fn new(keys: Option<OperatorKeys>, dir: PathBuf, ttl_secs: u64) -> Self {
        Self::with_box(StateBox::random(), keys, dir, ttl_secs)
    }

    /// An engine with a given sealing box (tests).
    #[must_use]
    pub fn with_box(
        state_box: StateBox,
        keys: Option<OperatorKeys>,
        dir: PathBuf,
        ttl_secs: u64,
    ) -> Self {
        Self {
            state_box,
            keys,
            dir,
            ttl_secs: i64::try_from(ttl_secs).unwrap_or(300),
            consumed: Mutex::new(HashMap::new()),
        }
    }

    fn aad(principal: &str) -> Vec<u8> {
        let mut aad = STATE_DOMAIN.to_vec();
        aad.extend_from_slice(principal.as_bytes());
        aad
    }

    /// The elicitation request and sealed state for a multi round-trip approval.
    #[must_use]
    pub fn mrtr_request(
        &self,
        principal: &str,
        request: &str,
        need: &ApprovalNeed,
        now: i64,
    ) -> (Value, String) {
        let mut nonce = [0_u8; 16];
        rand::rng().fill_bytes(&mut nonce);
        let payload = StatePayload {
            v: 1,
            tool: need.tool.clone(),
            request: request.to_owned(),
            action: need.action_digest.clone(),
            exp: now.saturating_add(self.ttl_secs),
            nonce: hex::encode(nonce),
        };
        let plain = serde_json::to_vec(&payload).unwrap_or_default();
        let state = self.state_box.seal(&Self::aad(principal), &plain);
        let message = format!(
            "Approve this {} action by {}? {} Origin: {}. Reasons: {}.",
            need.class,
            need.tool,
            need.summary,
            need.origin,
            need.reasons.join(", ")
        );
        let requests = json!({
            "approval": {
                "method": "elicitation/create",
                "params": {
                    "mode": "form",
                    "message": message,
                    "requestedSchema": {
                        "type": "object",
                        "properties": {
                            "approve": {
                                "type": "boolean",
                                "title": "Approve this action",
                                "description": "Choose true to let the action run once."
                            }
                        },
                        "required": ["approve"]
                    }
                }
            }
        });
        (requests, state)
    }

    /// Verifies the evidence of a multi round-trip retry.
    #[must_use]
    pub fn mrtr_resume(
        &self,
        principal: &str,
        tool: &str,
        request: &str,
        state: &str,
        responses: Option<&Value>,
        now: i64,
    ) -> Resume {
        let Ok(plain) = self.state_box.open(&Self::aad(principal), state) else {
            return Resume::Refused(
                "the approval state is not valid for this caller: it was altered, issued to another principal or by another server process".into(),
            );
        };
        let Ok(payload) = serde_json::from_slice::<StatePayload>(&plain) else {
            return Resume::Refused("the approval state is malformed".into());
        };
        if payload.v != 1 || payload.tool != tool || payload.request != request {
            return Resume::Refused("the approval state belongs to a different request".into());
        }
        if payload.exp <= now {
            return Resume::Fresh;
        }
        let answer = responses.and_then(|r| r.get("approval"));
        let Some(answer) = answer else {
            return Resume::Fresh;
        };
        {
            let mut consumed = self.consumed.lock().unwrap_or_else(PoisonError::into_inner);
            if consumed.contains_key(&payload.nonce) {
                return Resume::Fresh;
            }
            if consumed.len() >= MAX_CONSUMED {
                consumed.retain(|_, exp| *exp > now);
                if consumed.len() >= MAX_CONSUMED {
                    return Resume::Refused("too many approvals are in flight".into());
                }
            }
            consumed.insert(payload.nonce.clone(), payload.exp);
        }
        let accepted = answer.get("action").and_then(Value::as_str) == Some("accept")
            && answer
                .get("content")
                .and_then(|c| c.get("approve"))
                .and_then(Value::as_bool)
                == Some(true);
        if accepted {
            Resume::Approved(Approved {
                action_digest: payload.action,
            })
        } else {
            Resume::Declined
        }
    }

    fn ensure_dir(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn pending_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.pending.json"))
    }

    fn approved_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.approved"))
    }

    /// Records a pending out-of-band approval and returns its id.
    ///
    /// # Errors
    /// When too many requests wait or the directory cannot be written.
    pub fn oob_request(
        &self,
        principal: &str,
        request: &str,
        need: &ApprovalNeed,
        now: i64,
    ) -> Result<String, ApprovalError> {
        self.ensure_dir()?;
        let mut live = 0;
        for entry in std::fs::read_dir(&self.dir)? {
            let path = entry?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.ends_with(".pending.json") {
                continue;
            }
            let expires = std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice::<Pending>(&b).ok())
                .map_or(0, |p| p.expires);
            if expires.saturating_add(3600) < now {
                let _ = std::fs::remove_file(&path);
                let _ = std::fs::remove_file(
                    path.with_file_name(name.replace(".pending.json", ".approved")),
                );
            } else if expires > now {
                live += 1;
            }
        }
        if live >= MAX_PENDING {
            return Err(ApprovalError::TooManyPending);
        }
        let mut id_bytes = [0_u8; 12];
        rand::rng().fill_bytes(&mut id_bytes);
        let id = format!("apr_{}", hex::encode(id_bytes));
        let record = Pending {
            id: id.clone(),
            principal: principal.to_owned(),
            tool: need.tool.clone(),
            request: request.to_owned(),
            action: need.action_digest.clone(),
            class: need.class.clone(),
            origin: need.origin.clone(),
            reasons: need.reasons.clone(),
            summary: need.summary.clone(),
            created: now,
            expires: now.saturating_add(self.ttl_secs),
        };
        let bytes = serde_json::to_vec_pretty(&record).map_err(std::io::Error::other)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(self.pending_path(&id))?;
        file.write_all(&bytes)?;
        Ok(id)
    }

    /// Verifies the evidence of an out-of-band retry (`approval_id`).
    #[must_use]
    pub fn oob_resume(
        &self,
        principal: &str,
        tool: &str,
        request: &str,
        id: &str,
        now: i64,
    ) -> Resume {
        if !valid_id(id) {
            return Resume::Refused("approval_id is not a valid approval id".into());
        }
        let Ok(pending_bytes) = std::fs::read(self.pending_path(id)) else {
            return Resume::Fresh;
        };
        let Ok(pending) = serde_json::from_slice::<Pending>(&pending_bytes) else {
            return Resume::Refused("the approval record is malformed".into());
        };
        if pending.principal != principal || pending.tool != tool || pending.request != request {
            return Resume::Refused(
                "the approval was requested by another caller or for another request".into(),
            );
        }
        if pending.expires <= now {
            return Resume::Fresh;
        }
        let Some(keys) = &self.keys else {
            return Resume::Refused(
                "no operator key is configured, so no approval can be verified".into(),
            );
        };
        let Ok(signature) = std::fs::read_to_string(self.approved_path(id)) else {
            return Resume::Pending(id.to_owned());
        };
        if keys
            .verify(&signature, APPROVAL_DOMAIN, &pending_bytes)
            .is_err()
        {
            return Resume::Refused("the approval signature does not verify".into());
        }
        // Single use across processes: whoever renames the file owns the approval.
        let used = self.dir.join(format!("{id}.used"));
        if std::fs::rename(self.approved_path(id), used).is_err() {
            return Resume::Fresh;
        }
        Resume::Approved(Approved {
            action_digest: pending.action,
        })
    }
}

/// One pending request, as the operator sees it.
#[derive(Debug, Clone, Serialize)]
pub struct PendingView {
    /// Approval id.
    pub id: String,
    /// Tool.
    pub tool: String,
    /// Action class.
    pub class: String,
    /// Origin.
    pub origin: String,
    /// Reasons.
    pub reasons: Vec<String>,
    /// Summary (page-derived text is quoted).
    pub summary: String,
    /// Unix expiry.
    pub expires: i64,
    /// Whether it is already approved.
    pub approved: bool,
}

/// Lists unexpired pending approvals in `dir`.
///
/// # Errors
/// When the directory cannot be read.
pub fn list_pending(dir: &Path, now: i64) -> Result<Vec<PendingView>, ApprovalError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let path = entry?.path();
        if !path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".pending.json"))
        {
            continue;
        }
        let Some(record) = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Pending>(&b).ok())
        else {
            continue;
        };
        if record.expires <= now {
            continue;
        }
        let approved = dir.join(format!("{}.approved", record.id)).exists();
        out.push(PendingView {
            id: record.id,
            tool: record.tool,
            class: record.class,
            origin: record.origin,
            reasons: record.reasons,
            summary: record.summary,
            expires: record.expires,
            approved,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// The operator signs a pending approval.
///
/// # Errors
/// When the id is unknown or expired, or the key id is unknown.
pub fn approve(
    dir: &Path,
    id: &str,
    keys: &OperatorKeys,
    key_id: &str,
    now: i64,
) -> Result<PendingView, ApprovalError> {
    if !valid_id(id) {
        return Err(ApprovalError::Record(
            id.into(),
            "not a valid approval id".into(),
        ));
    }
    let path = dir.join(format!("{id}.pending.json"));
    let bytes = std::fs::read(&path)
        .map_err(|_| ApprovalError::Record(id.into(), "no such pending approval".into()))?;
    let record: Pending = serde_json::from_slice(&bytes)
        .map_err(|_| ApprovalError::Record(id.into(), "the record is malformed".into()))?;
    if record.expires <= now {
        return Err(ApprovalError::Record(
            id.into(),
            "the request expired".into(),
        ));
    }
    let line = keys.sign(key_id, APPROVAL_DOMAIN, &bytes)?;
    let target = dir.join(format!("{id}.approved"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&target)
        .map_err(|_| ApprovalError::Record(id.into(), "already approved".into()))?;
    file.write_all(line.as_bytes())?;
    Ok(PendingView {
        id: record.id,
        tool: record.tool,
        class: record.class,
        origin: record.origin,
        reasons: record.reasons,
        summary: record.summary,
        expires: record.expires,
        approved: true,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn need() -> ApprovalNeed {
        ApprovalNeed {
            action_digest: "a".repeat(64),
            tool: "click".into(),
            class: "destructive".into(),
            origin: "https://app.example.test".into(),
            reasons: vec!["profile.test_environment.destructive.approval".into()],
            summary: quote_for_human("Delete account", 80),
            plan_digest: None,
            grant_digest: None,
        }
    }

    fn engine(dir: &Path) -> Approvals {
        let mut keys = OperatorKeys::new();
        keys.insert("op", vec![1; 32]).unwrap();
        Approvals::new(Some(keys), dir.to_path_buf(), 300)
    }

    fn accept() -> Value {
        json!({"approval": {"action": "accept", "content": {"approve": true}}})
    }

    #[test]
    fn a_round_trip_runs_once_and_every_misuse_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine(dir.path());
        let request = request_digest("click", &json!({"ref": "e1"}));
        let (requests, state) = engine.mrtr_request("stdio", &request, &need(), 1000);
        assert_eq!(requests["approval"]["method"], "elicitation/create");
        assert!(
            requests["approval"]["params"]["message"]
                .as_str()
                .unwrap()
                .contains("\u{201c}Delete account\u{201d}")
        );

        // Tampered state: refused.
        let mut bytes = state.clone().into_bytes();
        let at = bytes.len() / 2;
        bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(matches!(
            engine.mrtr_resume("stdio", "click", &request, &tampered, Some(&accept()), 1001),
            Resume::Refused(_)
        ));
        // Another principal: refused.
        assert!(matches!(
            engine.mrtr_resume(
                "http:other",
                "click",
                &request,
                &state,
                Some(&accept()),
                1001
            ),
            Resume::Refused(_)
        ));
        // Another request (different arguments): refused.
        let other = request_digest("click", &json!({"ref": "e2"}));
        assert!(matches!(
            engine.mrtr_resume("stdio", "click", &other, &state, Some(&accept()), 1001),
            Resume::Refused(_)
        ));
        // No answer yet: a fresh request, the state stays usable.
        assert_eq!(
            engine.mrtr_resume("stdio", "click", &request, &state, None, 1001),
            Resume::Fresh
        );
        // The genuine retry is approved exactly once.
        assert_eq!(
            engine.mrtr_resume("stdio", "click", &request, &state, Some(&accept()), 1002),
            Resume::Approved(Approved {
                action_digest: "a".repeat(64)
            })
        );
        assert_eq!(
            engine.mrtr_resume("stdio", "click", &request, &state, Some(&accept()), 1003),
            Resume::Fresh
        );
    }

    #[test]
    fn declines_and_expiry_do_not_approve() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine(dir.path());
        let request = request_digest("click", &json!({}));
        let (_, state) = engine.mrtr_request("p", &request, &need(), 1000);
        let decline = json!({"approval": {"action": "decline"}});
        assert_eq!(
            engine.mrtr_resume("p", "click", &request, &state, Some(&decline), 1001),
            Resume::Declined
        );
        let (_, state) = engine.mrtr_request("p", &request, &need(), 1000);
        let no = json!({"approval": {"action": "accept", "content": {"approve": false}}});
        assert_eq!(
            engine.mrtr_resume("p", "click", &request, &state, Some(&no), 1001),
            Resume::Declined
        );
        let (_, state) = engine.mrtr_request("p", &request, &need(), 1000);
        assert_eq!(
            engine.mrtr_resume("p", "click", &request, &state, Some(&accept()), 1301),
            Resume::Fresh
        );
        // State from another server process (another key) is refused.
        let (_, state) = engine.mrtr_request("p", &request, &need(), 1000);
        let restarted = Approvals::new(None, dir.path().to_path_buf(), 300);
        assert!(matches!(
            restarted.mrtr_resume("p", "click", &request, &state, Some(&accept()), 1001),
            Resume::Refused(_)
        ));
    }

    #[test]
    fn the_request_digest_ignores_the_approval_id_only() {
        let a = request_digest("click", &json!({"ref": "e1", "approval_id": "apr_x"}));
        let b = request_digest("click", &json!({"ref": "e1"}));
        assert_eq!(a, b);
        assert_ne!(b, request_digest("click", &json!({"ref": "e2"})));
        assert_ne!(b, request_digest("type_text", &json!({"ref": "e1"})));
    }

    #[test]
    fn out_of_band_approvals_need_the_operator_signature_and_are_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine(dir.path());
        let request = request_digest("click", &json!({"ref": "e1"}));
        let id = engine
            .oob_request("stdio", &request, &need(), 1000)
            .unwrap();
        assert!(valid_id(&id));
        assert_eq!(
            engine.oob_resume("stdio", "click", &request, &id, 1001),
            Resume::Pending(id.clone())
        );
        assert!(matches!(
            engine.oob_resume("http:other", "click", &request, &id, 1001),
            Resume::Refused(_)
        ));
        let pending = list_pending(dir.path(), 1001).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].approved);

        let mut keys = OperatorKeys::new();
        keys.insert("op", vec![1; 32]).unwrap();
        approve(dir.path(), &id, &keys, "op", 1002).unwrap();
        assert!(
            approve(dir.path(), &id, &keys, "op", 1002).is_err(),
            "approved twice"
        );
        assert_eq!(
            engine.oob_resume("stdio", "click", &request, &id, 1003),
            Resume::Approved(Approved {
                action_digest: "a".repeat(64)
            })
        );
        assert_eq!(
            engine.oob_resume("stdio", "click", &request, &id, 1004),
            Resume::Pending(id.clone()),
            "the used approval is gone: back to pending, never approved again"
        );
        assert!(matches!(
            engine.oob_resume("stdio", "click", &request, "apr_nothex", 1004),
            Resume::Refused(_)
        ));
    }

    #[test]
    fn a_forged_or_foreign_signature_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine(dir.path());
        let request = request_digest("click", &json!({}));
        let id = engine.oob_request("p", &request, &need(), 1000).unwrap();
        let mut other = OperatorKeys::new();
        other.insert("op", vec![2; 32]).unwrap();
        approve(dir.path(), &id, &other, "op", 1001).unwrap();
        assert!(matches!(
            engine.oob_resume("p", "click", &request, &id, 1002),
            Resume::Refused(_)
        ));
    }

    #[test]
    fn pending_requests_are_bounded_and_expire() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine(dir.path());
        for _ in 0..MAX_PENDING {
            engine.oob_request("p", "r", &need(), 1000).unwrap();
        }
        assert!(matches!(
            engine.oob_request("p", "r", &need(), 1000),
            Err(ApprovalError::TooManyPending)
        ));
        // Much later the old ones are gone and new requests work again.
        engine.oob_request("p", "r", &need(), 10_000).unwrap();
    }

    #[test]
    fn human_text_is_bounded_and_flattened() {
        let quoted = quote_for_human("Delete\naccount\u{7}!", 9);
        assert_eq!(quoted, "\u{201c}Delete ac\u{201d}");
    }
}
