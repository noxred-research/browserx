//! Model-assisted tools. They only advise: the model sees redacted, wrapped content and its
//! answer is validated; when it is unreachable or answers badly, a deterministic fallback runs
//! and the result says so.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::browse::{open, origin_of};
use super::monitor::assessment;
use super::{Args, Output, session_id};
use crate::ctx::Ctx;
use crate::error::{ToolError, ToolResult};
use crate::explain;
use crate::llm::{Llm, LlmError, SYSTEM_RULES};
use crate::safety::wrap_untrusted;
use crate::schema;

fn llm(ctx: &Ctx) -> ToolResult<&Llm> {
    ctx.llm
        .as_ref()
        .ok_or_else(|| ToolError::not_configured("no [ai] section is configured"))
}

/// What the result says about the model's part.
fn llm_note(outcome: &Result<(), LlmError>) -> Value {
    match outcome {
        Ok(()) => json!({ "used": true }),
        Err(error) => json!({ "used": false, "reason": error.to_string() }),
    }
}

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push('…');
    out
}

/// A deterministic summary: the title, the headings and the first substantial paragraphs.
pub(crate) fn extractive_summary(title: &str, text: &str) -> (String, Vec<String>) {
    let mut headings = Vec::new();
    let mut paragraphs = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(heading) = line.strip_prefix('#') {
            if headings.len() < 6 {
                headings.push(clip(heading.trim_start_matches('#').trim(), 120));
            }
        } else if paragraphs.len() < 3
            && line.chars().count() > 40
            && !line.starts_with(['-', '|', '`', '!'])
        {
            paragraphs.push(clip(line, 300));
        }
    }
    let lead = paragraphs.first().cloned().unwrap_or_default();
    let summary = if title.is_empty() {
        lead
    } else if lead.is_empty() {
        title.to_owned()
    } else {
        format!("{title}: {lead}")
    };
    let mut points = headings;
    points.extend(paragraphs.into_iter().skip(1));
    (summary, points)
}

pub(super) async fn summarize_page(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let llm = llm(ctx)?;
    let (handle, id, tab) = open(ctx, args).await?;
    let budget = llm.max_input_chars().min(ctx.cfg.browse.max_chars_cap);
    let page = handle.page_text(&tab, budget).await?;
    let origin = origin_of(&page.url);
    let (fallback_summary, fallback_points) = extractive_summary(&page.title, &page.text);
    let focus = args.str("focus").unwrap_or("the page's main content");
    let prompt = format!(
        "Summarize the page content below. Focus: {focus}.\n{}",
        wrap_untrusted(&origin, &ctx.redactor.text(&page.text))
    );
    let schema = json!({
        "type": "object",
        "properties": {
            "summary": {"type": "string", "maxLength": 2000},
            "key_points": {"type": "array", "items": {"type": "string", "maxLength": 300}, "maxItems": 8}
        },
        "required": ["summary", "key_points"],
        "additionalProperties": false
    });
    let answer = llm
        .complete_json("page_summary", SYSTEM_RULES, &prompt, &schema, true)
        .await;
    let (source, summary, points, note) = match answer {
        Ok(value) => (
            "llm",
            value["summary"].as_str().unwrap_or("").to_owned(),
            value["key_points"]
                .as_array()
                .map(|l| {
                    l.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            llm_note(&Ok(())),
        ),
        Err(error) => (
            "extractive_fallback",
            fallback_summary,
            fallback_points,
            llm_note(&Err(error)),
        ),
    };
    let mut body = format!(
        "url: {}\ntitle: {}\nsummary: {summary}\n",
        page.url, page.title
    );
    for point in &points {
        body.push_str(&format!("- {point}\n"));
    }
    Ok(Output::page(
        &json!({ "session_id": id, "tab_id": tab.id, "source": source, "llm": note, "advisory": true }),
        &origin,
        &body,
    ))
}

fn coerce(kind: &str, raw: &str) -> Option<Value> {
    let raw = raw.trim().trim_matches('*').trim();
    if raw.is_empty() {
        return None;
    }
    match kind {
        "integer" => {
            let digits: String = raw
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '-')
                .collect();
            digits.parse::<i64>().ok().map(Value::from)
        }
        "number" => {
            let cleaned: String = raw
                .chars()
                .filter(|c| c.is_ascii_digit() || matches!(c, '-' | '.'))
                .collect();
            cleaned
                .parse::<f64>()
                .ok()
                .and_then(|n| serde_json::Number::from_f64(n).map(Value::Number))
        }
        "boolean" => match raw.to_ascii_lowercase().as_str() {
            "yes" | "true" | "y" | "on" | "enabled" => Some(Value::Bool(true)),
            "no" | "false" | "n" | "off" | "disabled" => Some(Value::Bool(false)),
            _ => None,
        },
        "array" => Some(Value::Array(
            raw.split(',')
                .map(|part| Value::String(clip(part.trim(), 200)))
                .filter(|v| v != "")
                .collect(),
        )),
        _ => Some(Value::String(clip(raw, 500))),
    }
}

/// Finds `label: value` lines and `| label | value |` rows for each property of `schema`.
pub(crate) fn heuristic_extract(schema: &Value, text: &str) -> (Map<String, Value>, Vec<String>) {
    let mut data = Map::new();
    let mut missing = Vec::new();
    let empty = Map::new();
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let lines: Vec<String> = text
        .lines()
        .map(|l| {
            l.trim()
                .trim_start_matches(['-', '*', ' '])
                .replace("**", "")
        })
        .collect();
    for (name, definition) in properties {
        let kind = definition
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("string");
        let labels = [
            name.to_ascii_lowercase(),
            name.replace(['_', '-'], " ").to_ascii_lowercase(),
        ];
        let mut found = None;
        'lines: for line in &lines {
            let lower = line.to_ascii_lowercase();
            for label in &labels {
                if let Some(rest) = lower.strip_prefix(label.as_str()) {
                    let rest_original = &line[line.len() - rest.len()..];
                    if let Some(value) = rest_original.trim_start().strip_prefix([':', '=']) {
                        found = coerce(kind, value);
                    }
                }
                if found.is_none() && lower.starts_with('|') {
                    let cells: Vec<&str> = line
                        .split('|')
                        .map(str::trim)
                        .filter(|c| !c.is_empty())
                        .collect();
                    if cells.len() >= 2 && cells[0].eq_ignore_ascii_case(label) {
                        found = coerce(kind, cells[1]);
                    }
                }
                if found.is_some() {
                    break 'lines;
                }
            }
        }
        match found {
            Some(value) => {
                data.insert(name.clone(), value);
            }
            None => missing.push(name.clone()),
        }
    }
    (data, missing)
}

pub(super) async fn extract_data(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let llm = llm(ctx)?;
    let wanted = args
        .0
        .get("schema")
        .cloned()
        .ok_or_else(|| ToolError::invalid("`schema` is required"))?;
    if wanted.get("type").and_then(Value::as_str) != Some("object")
        || !wanted.get("properties").is_some_and(Value::is_object)
    {
        return Err(ToolError::invalid(
            "`schema` must be a JSON Schema of type object with properties",
        ));
    }
    let (handle, id, tab) = open(ctx, args).await?;
    let budget = llm.max_input_chars().min(ctx.cfg.browse.max_chars_cap);
    let page = handle.page_text(&tab, budget).await?;
    let origin = origin_of(&page.url);
    let instructions = args.str("instructions").unwrap_or("");
    let prompt = format!(
        "Extract the data described by the JSON Schema from the page content below. Use null or omit what the page does not state; never invent values. {instructions}\nSchema: {wanted}\n{}",
        wrap_untrusted(&origin, &ctx.redactor.text(&page.text))
    );
    let answer = llm
        .complete_json("page_extract", SYSTEM_RULES, &prompt, &wanted, false)
        .await
        .and_then(|value| {
            schema::check(&wanted, value).map_err(|issues| LlmError::Invalid(issues.join("; ")))
        });
    let (method, data, missing, note) = match answer {
        Ok(value) => ("llm", value, Vec::new(), llm_note(&Ok(()))),
        Err(error) => {
            let (found, missing) = heuristic_extract(&wanted, &page.text);
            (
                "heuristic_fallback",
                Value::Object(found),
                missing,
                llm_note(&Err(error)),
            )
        }
    };
    let body = serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string());
    Ok(Output::page(
        &json!({ "session_id": id, "tab_id": tab.id, "method": method, "llm": note, "missing": missing, "advisory": true }),
        &origin,
        &format!("url: {}\n{body}", page.url),
    ))
}

/// A plain narrative of the findings, used when no model narrates.
pub(crate) fn deterministic_narrative(report: &Value, session: Option<&Value>) -> String {
    let verdict = report["verdict"].as_str().unwrap_or("unknown");
    let mut text = format!("The pool verdict is {verdict}.");
    if let Some(checks) = report["checks"].as_array() {
        let issues: Vec<&Value> = checks.iter().filter(|c| c["status"] != "pass").collect();
        if issues.is_empty() {
            text.push_str(" Every check passes.");
        }
        for (index, check) in issues.iter().enumerate() {
            text.push_str(&format!(
                " ({}) {}{}",
                index + 1,
                check["summary"].as_str().unwrap_or(""),
                check["remediation"]
                    .as_str()
                    .map_or_else(String::new, |r| format!(" Do: {r}")),
            ));
        }
    }
    if let Some(session) = session {
        text.push_str(&format!(
            " Session: {}",
            session["summary"].as_str().unwrap_or("")
        ));
    }
    text
}

pub(super) async fn diagnose(ctx: &Arc<Ctx>, args: &Args) -> ToolResult {
    let llm = llm(ctx)?;
    let window = Duration::from_secs(args.u64("window_secs").unwrap_or(300).clamp(10, 3600));
    let report = assessment(ctx, window).await;
    let session = match args.str("session_id") {
        Some(_) => {
            let id = session_id(args)?;
            let view = ctx.backend.get_session(&id).await?;
            Some(explain::explain_session(&view, Ctx::now()))
        }
        None => None,
    };
    let findings = json!({ "assessment": report, "session": session });
    let schema = json!({
        "type": "object",
        "properties": {
            "narrative": {"type": "string", "maxLength": 1500},
            "priorities": {"type": "array", "items": {"type": "string", "maxLength": 200}, "maxItems": 5}
        },
        "required": ["narrative", "priorities"],
        "additionalProperties": false
    });
    let prompt = format!(
        "Explain these deterministic findings about a browser pool to an operator. Do not add facts that are not in the findings.\n{}",
        ctx.redactor.redacted(&findings)
    );
    let answer = llm
        .complete_json("pool_diagnosis", SYSTEM_RULES, &prompt, &schema, true)
        .await;
    let (source, narrative, priorities, note) = match answer {
        Ok(value) => (
            "llm",
            value["narrative"].as_str().unwrap_or("").to_owned(),
            value["priorities"].clone(),
            llm_note(&Ok(())),
        ),
        Err(error) => (
            "deterministic",
            deterministic_narrative(&report, session.as_ref()),
            json!([]),
            llm_note(&Err(error)),
        ),
    };
    let worst = report["overall"].as_str().unwrap_or("pass");
    Ok(Output::json(json!({
        "verdict": report["verdict"],
        "overall": report["overall"],
        "healthy": worst == "pass" && report["verdict"] == "ok",
        "reasons": report["reasons"],
        "checks": report["checks"],
        "session": session,
        "narrative": narrative,
        "priorities": priorities,
        "narrative_source": source,
        "llm": note,
        "findings_are_deterministic": true,
    })))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const PAGE: &str = "# Acme Widgets\n\nAcme builds widgets for industrial customers around the world since 1987.\n\n## Specs\n\n- Weight: 12 kg\n\nPrice: $1,249.50\nIn stock: yes\n**Model number**: AX-7\nColors: red, blue\n\n| Warranty | 24 |\n| --- | --- |\n";

    #[test]
    fn extractive_summary_uses_title_headings_and_lead_paragraph() {
        let (summary, points) = extractive_summary("Acme", PAGE);
        assert!(summary.starts_with("Acme: Acme builds widgets"));
        assert_eq!(points, vec!["Acme Widgets".to_owned(), "Specs".to_owned()]);
    }

    #[test]
    fn heuristic_extraction_coerces_types_and_lists_what_is_missing() {
        let schema = json!({"type": "object", "properties": {
            "price": {"type": "number"}, "in_stock": {"type": "boolean"}, "model_number": {"type": "string"},
            "weight": {"type": "string"}, "colors": {"type": "array"}, "warranty": {"type": "integer"}, "sku": {"type": "string"}
        }});
        let (data, missing) = heuristic_extract(&schema, PAGE);
        assert_eq!(data["price"], json!(1249.5));
        assert_eq!(data["in_stock"], json!(true));
        assert_eq!(data["model_number"], json!("AX-7"));
        assert_eq!(data["weight"], json!("12 kg"));
        assert_eq!(data["colors"], json!(["red", "blue"]));
        assert_eq!(data["warranty"], json!(24));
        assert_eq!(missing, vec!["sku".to_owned()]);
    }

    #[test]
    fn deterministic_narrative_lists_failing_checks_with_remediation() {
        let report = json!({"verdict": "saturated", "checks": [
            {"status": "pass", "summary": "fine"},
            {"status": "fail", "summary": "3 admissions refused", "remediation": "raise max_browsers"}
        ]});
        let text = deterministic_narrative(&report, None);
        assert!(
            text.contains("saturated")
                && text.contains("3 admissions refused")
                && text.contains("raise max_browsers")
        );
        assert!(!text.contains("fine"));
    }
}
