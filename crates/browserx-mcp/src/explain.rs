//! Deterministic explanations: what a session's state means, and what an API error or relay
//! refusal means and what to do about it. The text is fixed; a model may rephrase it but the
//! facts come from this table.

use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

fn status_meaning(status: &str) -> &'static str {
    match status {
        "queued" => "The session is admitted and waiting for browser capacity.",
        "allocating" => "A browser is being launched or a context created for the session.",
        "active" => "A controller is attached: a CDP client holds a relay connection.",
        "idle" => {
            "The browser is running and no controller is attached. The session is released after its idle timeout unless a controller attaches."
        }
        "recovering" => "The browser was lost and a replacement is being launched and restored.",
        "draining" => {
            "Release was requested: the final snapshot and cleanup are running. No controller can attach any more."
        }
        "lost" => {
            "The browser was lost and the session could not be recovered (recovery disabled or failed). This state is final."
        }
        "closed" => "The session was released and cleaned up. This state is final.",
        _ => "Unknown status.",
    }
}

/// What a recovery outcome means for the state of the browser: `(meaning, survived, lost)`.
fn outcome_meaning(
    outcome: &str,
) -> (
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
) {
    match outcome {
        "resumed_same_process" => (
            "The same browser process is still alive. Only the controller changed.",
            &[
                "open pages",
                "JavaScript heaps",
                "open sockets",
                "cookies and storage",
            ],
            &[],
        ),
        "restored_from_profile" => (
            "The browser process was replaced. A new Chromium started on the same user-data directory.",
            &[
                "cookies and storage persisted to disk",
                "IndexedDB and cache on disk",
            ],
            &[
                "open pages and tabs",
                "JavaScript heaps",
                "open sockets",
                "in-memory-only (session) state",
            ],
        ),
        "restored_from_snapshot" => (
            "The browser process was replaced. The latest encrypted snapshot was replayed into a new browser.",
            &[
                "cookies",
                "per-origin localStorage",
                "the URLs of open pages (reopened, not their state)",
            ],
            &[
                "JavaScript heaps",
                "open sockets",
                "service-worker runtime",
                "cache",
                "form input and scroll positions",
            ],
        ),
        "fresh_process" => (
            "The browser process was replaced by an empty one. Nothing was restored.",
            &[],
            &["everything: pages, cookies, storage, JavaScript state"],
        ),
        _ => ("No recovery outcome has been reported.", &[], &[]),
    }
}

fn persistence_contract(mode: &str) -> &'static str {
    match mode {
        "ephemeral" => "Nothing survives the browser process; recovery starts an empty browser.",
        "snapshot" => {
            "Cookies and per-origin storage are captured into encrypted, versioned snapshots and replayed on recovery. Portable across workers; does not carry the JavaScript heap, open sockets, service workers or cache."
        }
        "profile" => {
            "A dedicated user-data directory under an exclusive lock. Highest fidelity on one worker; not portable."
        }
        _ => "Unknown persistence mode.",
    }
}

/// Explains a lease view (as returned by the BrowserX API).
#[must_use]
pub fn explain_session(view: &Value, now: OffsetDateTime) -> Value {
    let text = |key: &str| view.get(key).and_then(Value::as_str);
    let status = text("status").unwrap_or("unknown");
    let persistence = text("persistence").unwrap_or("unknown");
    let recovery_policy = text("recovery").unwrap_or("unknown");
    let last = text("last_recovery");
    let recoveries = view.get("recoveries").and_then(Value::as_u64).unwrap_or(0);
    let (meaning, survived, lost) = outcome_meaning(last.unwrap_or(""));

    let mut next = Vec::new();
    match status {
        "queued" | "allocating" => next.push(
            "Wait and call get_session again; admission is bounded by pool.queue_timeout_secs."
                .to_owned(),
        ),
        "recovering" => next.push(
            "Wait a few seconds and call get_session again; attaching also triggers recovery."
                .to_owned(),
        ),
        "lost" => {
            next.push("Create a new session; this one cannot be resumed.".to_owned());
            if persistence != "ephemeral" {
                next.push(
                    "Pass the same profile_id to create_session to bring the persisted state back."
                        .to_owned(),
                );
            }
            if recovery_policy == "none" {
                next.push("This session was created with recovery = none: a single crash ends it. Use recovery = restore for work that must survive.".to_owned());
            }
        }
        "closed" | "draining" => {
            next.push("Nothing to do; create a new session if you need a browser.".to_owned())
        }
        "active" | "idle" => {
            if matches!(last, Some(outcome) if outcome != "resumed_same_process") {
                next.push("The browser was replaced: reopen the pages you need (open_page) and re-take page_snapshot; earlier element refs are gone.".to_owned());
            }
            if let Some(expires) =
                text("expires_at").and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok())
            {
                let left = (expires - now).whole_seconds();
                if left <= 0 {
                    next.push(
                        "The lease has run past its expiry; the reaper releases it shortly."
                            .to_owned(),
                    );
                } else if left < 120 {
                    next.push(format!(
                        "The lease expires in {left} s: call renew_session to extend it."
                    ));
                }
            }
        }
        _ => {}
    }
    if let Some(reason) = text("reason") {
        next.push(format!("The server recorded this reason: {reason}"));
    }
    let summary = format!(
        "Session is {status}. {} It was last attached as: {}. The browser has been replaced {recoveries} time(s).",
        status_meaning(status),
        last.unwrap_or("never attached"),
    );
    json!({
        "session_id": text("session_id"),
        "status": status,
        "summary": summary,
        "status_meaning": status_meaning(status),
        "recovery": {
            "policy": recovery_policy,
            "last_outcome": last,
            "recoveries": recoveries,
            "meaning": meaning,
            "state_survived": survived,
            "state_lost": lost,
        },
        "persistence": { "mode": persistence, "contract": persistence_contract(persistence) },
        "isolation": text("isolation"),
        "generation": view.get("generation"),
        "reason": text("reason"),
        "expires_at": text("expires_at"),
        "next_steps": next,
    })
}

/// Explains a BrowserX error code, an MCP failure kind, or a relay refusal message.
#[must_use]
pub fn explain_error(code: &str, message: Option<&str>) -> Value {
    let lower_message = message.unwrap_or("").to_ascii_lowercase();
    let (title, meaning, actions): (&str, &str, &[&str]) = if lower_message
        .contains("host-protection policy")
    {
        (
            "Refused by the host-protection policy",
            "The CDP relay refuses commands that would turn the browser against the worker's host: navigation to file:, chrome: or devtools: pages, per-context proxy overrides, host file selection, tracing and memory dumps, closing the browser.",
            &[
                "Navigate only to http(s) URLs.",
                "Route egress through a named proxy route chosen at session creation, not through per-page proxy settings.",
                "Release a session through release_session, not by closing the browser.",
            ],
        )
    } else if lower_message.contains("shared session") || lower_message.contains("shared-session") {
        (
            "Refused in a shared-browser session",
            "A shared session gets a scoped relay confined to its own browser context; browser-level, system and cross-context commands are refused.",
            &[
                "Create the session with isolation = dedicated_browser if you need browser-level access.",
            ],
        )
    } else {
        match code {
            "invalid_request" => (
                "Invalid request",
                "The request is malformed or names an unsupported combination (for example profile persistence with shared isolation, or a proxy with shared isolation).",
                &[
                    "Check the arguments against the tool schema.",
                    "Use isolation = dedicated_browser for profile persistence or a proxy route.",
                ],
            ),
            "unauthorized" => (
                "Unauthorized",
                "The BrowserX API key is missing or wrong.",
                &[
                    "Check server.api_key_file in the MCP configuration; the key must match an entry in the server's auth.api_keys.",
                ],
            ),
            "forbidden" => (
                "Forbidden",
                "The credential is valid but does not grant this operation (wrong session token, or another owner's session).",
                &[
                    "Only sessions created by this server's API key can be driven; adopt others with [[adopt]] and their token file.",
                ],
            ),
            "not_found" => (
                "Not found",
                "No such session, profile or snapshot. Sessions disappear after their lease expires and the terminal retention period passes.",
                &[
                    "List sessions with list_sessions.",
                    "A session released or expired earlier cannot be found again.",
                ],
            ),
            "stale_generation" => (
                "Stale generation",
                "The lease moved on (recovery, handoff or renewal) between reading and writing. Another controller advanced it.",
                &[
                    "Re-read the session with get_session and retry with the current generation.",
                    "If a handoff happened, the previous token no longer works.",
                ],
            ),
            "conflict" => (
                "Conflict",
                "The lease's state forbids the operation (closed, draining, wrong status).",
                &[
                    "Read the status with explain_session.",
                    "A closed or lost session cannot be changed.",
                ],
            ),
            "capacity" => (
                "Capacity exhausted",
                "Admission was refused: the queue is full, the owner's session quota is reached, or the wait deadline passed.",
                &[
                    "Call pool_status to see saturation.",
                    "Release sessions you no longer need.",
                    "Ask the operator to raise pool.max_browsers or the key's max_sessions.",
                ],
            ),
            "profile_locked" => (
                "Profile locked",
                "Another browser holds the profile directory: profile persistence allows one browser per profile.",
                &[
                    "Release the session that uses this profile first.",
                    "Use persistence = snapshot for state that several sessions must share over time.",
                ],
            ),
            "browser" => (
                "Browser failure",
                "The browser runtime failed: launch, crash or a CDP protocol error.",
                &[
                    "Call explain_session and assess.",
                    "Check the launch profile and the host's memory.",
                    "Retry; recovery = restore relaunches a crashed browser.",
                ],
            ),
            "timeout" => (
                "Timed out",
                "A bounded operation ran out of time (launch, CDP command, navigation).",
                &[
                    "Retry once.",
                    "If it repeats, call assess: the host may be overloaded or the page too slow.",
                ],
            ),
            "storage" | "crypto" | "internal" => (
                "Server-side failure",
                "The BrowserX server failed internally (storage, snapshot encryption or an unexpected state). Details are in the server's logs, not in API responses.",
                &[
                    "Call health and assess.",
                    "Ask the operator to read the server logs.",
                ],
            ),
            "egress" => (
                "Egress failure",
                "The upstream proxy or the destination policy refused or failed the connection.",
                &[
                    "Check the proxy route's reachability.",
                    "If the destination is internal, the egress policy refuses it unless egress.allow_cidrs lists it.",
                ],
            ),
            "shutting_down" => (
                "Shutting down",
                "The server is draining and accepts no new sessions.",
                &[
                    "Wait for the server to restart; sessions with snapshot or profile persistence recover on startup.",
                ],
            ),
            "refused" => (
                "Refused by the MCP safety model",
                "The call was refused deterministically: capability not enabled, URL outside browse.allowed_origins, outside the engagement window, or a missing confirm.",
                &[
                    "Call capabilities to see what is enabled and in scope.",
                    "Only the operator can change scope; do not try to work around a refusal.",
                ],
            ),
            "rate_limited" => (
                "Rate limited",
                "The tool ran more often than its calls-per-minute limit.",
                &["Slow down; the message says how long to wait."],
            ),
            _ => (
                "Unknown error code",
                "This code is not one BrowserX defines.",
                &["Call explain_error with the `code` field of the error body."],
            ),
        }
    };
    json!({ "code": code, "title": title, "meaning": meaning, "what_to_do": actions })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-03-01T12:00:00Z", &Rfc3339).unwrap()
    }

    fn view(status: &str, last: Option<&str>) -> Value {
        json!({
            "session_id": "ses_0123", "status": status, "persistence": "snapshot",
            "recovery": "restore", "last_recovery": last, "recoveries": 1,
            "isolation": "dedicated_browser", "generation": 3,
            "expires_at": "2026-03-01T12:01:00Z", "reason": null
        })
    }

    #[test]
    fn recovery_outcomes_say_what_state_survived() {
        let resumed = explain_session(&view("active", Some("resumed_same_process")), now());
        assert_eq!(resumed["recovery"]["state_lost"], json!([]));
        let snapshot = explain_session(&view("active", Some("restored_from_snapshot")), now());
        let survived = snapshot["recovery"]["state_survived"].to_string();
        assert!(survived.contains("cookies") && survived.contains("localStorage"));
        assert!(
            snapshot["recovery"]["state_lost"]
                .to_string()
                .contains("JavaScript heaps")
        );
        let steps = snapshot["next_steps"].to_string();
        assert!(steps.contains("reopen the pages") && steps.contains("renew_session"));
        let fresh = explain_session(&view("idle", Some("fresh_process")), now());
        assert!(
            fresh["recovery"]["state_lost"]
                .to_string()
                .contains("everything")
        );
    }

    #[test]
    fn lost_sessions_point_to_profile_reuse() {
        let lost = explain_session(&view("lost", None), now());
        assert!(lost["next_steps"].to_string().contains("profile_id"));
        assert!(lost["summary"].as_str().unwrap().contains("never attached"));
    }

    #[test]
    fn errors_are_explained_by_code_and_by_relay_refusal_text() {
        for code in [
            "invalid_request",
            "unauthorized",
            "forbidden",
            "not_found",
            "stale_generation",
            "conflict",
            "capacity",
            "profile_locked",
            "browser",
            "timeout",
            "storage",
            "crypto",
            "internal",
            "egress",
            "shutting_down",
            "refused",
            "rate_limited",
        ] {
            let out = explain_error(code, None);
            assert_ne!(out["title"], "Unknown error code", "{code}");
            assert!(!out["what_to_do"].as_array().unwrap().is_empty());
        }
        assert_eq!(explain_error("nope", None)["title"], "Unknown error code");
        let refusal = explain_error(
            "browser",
            Some("refused by the host-protection policy: navigation to this URL scheme"),
        );
        assert_eq!(refusal["title"], "Refused by the host-protection policy");
    }
}
