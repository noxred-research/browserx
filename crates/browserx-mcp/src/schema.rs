//! Validation of tool arguments against the JSON Schema subset the tools advertise.
//!
//! The schema sent to the client in `tools/list` is the schema enforced here, so what a tool
//! advertises is what it accepts. Supported keywords: `type` (`object`, `string`, `integer`,
//! `number`, `boolean`, `array`), `enum`, `properties`, `required`, `additionalProperties`
//! (`false`, `true` or a schema), `items`, `minimum`, `maximum`, `minLength`, `maxLength`,
//! `minItems` and `maxItems`.
//!
//! Tolerance is deliberate and narrow: `null` for an optional property counts as absent (models
//! send it often). Unknown properties are rejected, not dropped, so a misspelled `confirm` is
//! reported instead of silently ignored.

use serde_json::{Map, Value};

/// Most issues reported at once; the model fixes them in one round trip.
const MAX_ISSUES: usize = 8;

/// Checks `value` against `schema`; returns it with `null` members of optional properties
/// removed.
///
/// # Errors
/// Every violation found (at most eight), each prefixed with its JSON path.
pub fn check(schema: &Value, value: Value) -> Result<Value, Vec<String>> {
    let mut issues = Vec::new();
    let out = walk(schema, value, "arguments", &mut issues);
    if issues.is_empty() {
        Ok(out)
    } else {
        Err(issues)
    }
}

fn push(issues: &mut Vec<String>, message: String) {
    if issues.len() < MAX_ISSUES {
        issues.push(message);
    }
}

fn walk(schema: &Value, value: Value, path: &str, issues: &mut Vec<String>) -> Value {
    let Some(schema) = schema.as_object() else {
        return value;
    };
    if let Some(expected) = schema.get("type").and_then(Value::as_str)
        && !type_matches(expected, &value)
    {
        push(
            issues,
            format!("{path}: expected {expected}, got {}", kind(&value)),
        );
        return value;
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(&value)
    {
        let list: Vec<String> = allowed.iter().map(Value::to_string).collect();
        push(
            issues,
            format!("{path}: must be one of {}", list.join(", ")),
        );
        return value;
    }
    match value {
        Value::Object(map) => Value::Object(walk_object(schema, map, path, issues)),
        Value::Array(items) => Value::Array(walk_array(schema, items, path, issues)),
        Value::String(text) => {
            let length = text.chars().count();
            bound(
                schema,
                "minLength",
                length,
                path,
                issues,
                |n, limit| n >= limit,
                "at least",
            );
            bound(
                schema,
                "maxLength",
                length,
                path,
                issues,
                |n, limit| n <= limit,
                "at most",
            );
            Value::String(text)
        }
        Value::Number(number) => {
            if let Some(n) = number.as_f64() {
                if let Some(min) = schema.get("minimum").and_then(Value::as_f64)
                    && n < min
                {
                    push(issues, format!("{path}: must be at least {min}"));
                }
                if let Some(max) = schema.get("maximum").and_then(Value::as_f64)
                    && n > max
                {
                    push(issues, format!("{path}: must be at most {max}"));
                }
            }
            Value::Number(number)
        }
        other => other,
    }
}

fn bound(
    schema: &Map<String, Value>,
    key: &str,
    actual: usize,
    path: &str,
    issues: &mut Vec<String>,
    ok: impl Fn(usize, usize) -> bool,
    word: &str,
) {
    if let Some(limit) = schema
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|limit| usize::try_from(limit).ok())
        && !ok(actual, limit)
    {
        let what = if key.ends_with("Length") {
            "characters"
        } else {
            "items"
        };
        push(
            issues,
            format!("{path}: must have {word} {limit} {what}, has {actual}"),
        );
    }
}

fn walk_object(
    schema: &Map<String, Value>,
    map: Map<String, Value>,
    path: &str,
    issues: &mut Vec<String>,
) -> Map<String, Value> {
    let empty = Map::new();
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let additional = schema.get("additionalProperties");
    let mut out = Map::new();
    for (name, member) in map {
        let child = format!("{path}.{name}");
        match properties.get(&name) {
            Some(_) if member.is_null() && !required.contains(&name.as_str()) => {}
            Some(property) => {
                let checked = walk(property, member, &child, issues);
                out.insert(name, checked);
            }
            None => match additional {
                Some(Value::Bool(false)) => push(
                    issues,
                    format!(
                        "{child}: unknown property (accepted: {})",
                        properties.keys().cloned().collect::<Vec<_>>().join(", ")
                    ),
                ),
                Some(extra @ Value::Object(_)) => {
                    let checked = walk(extra, member, &child, issues);
                    out.insert(name, checked);
                }
                _ => {
                    out.insert(name, member);
                }
            },
        }
    }
    for name in required {
        if !out.contains_key(name) {
            push(issues, format!("{path}.{name}: required"));
        }
    }
    out
}

fn walk_array(
    schema: &Map<String, Value>,
    items: Vec<Value>,
    path: &str,
    issues: &mut Vec<String>,
) -> Vec<Value> {
    bound(
        schema,
        "minItems",
        items.len(),
        path,
        issues,
        |n, limit| n >= limit,
        "at least",
    );
    bound(
        schema,
        "maxItems",
        items.len(),
        path,
        issues,
        |n, limit| n <= limit,
        "at most",
    );
    match schema.get("items") {
        Some(item_schema) => items
            .into_iter()
            .enumerate()
            .map(|(index, item)| walk(item_schema, item, &format!("{path}[{index}]"), issues))
            .collect(),
        None => items,
    }
}

fn type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "object" => value.is_object(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use serde_json::json;

    use super::*;

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 1, "maxLength": 20},
                "limit": {"type": "integer", "minimum": 1, "maximum": 10},
                "mode": {"type": "string", "enum": ["a", "b"]},
                "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 2}
            },
            "required": ["url"],
            "additionalProperties": false
        })
    }

    #[test]
    fn accepts_valid_and_drops_nulls_of_optional_members() {
        let out = check(&schema(), json!({"url": "x", "limit": null, "mode": "a"})).unwrap();
        assert_eq!(out, json!({"url": "x", "mode": "a"}));
    }

    #[test]
    fn reports_every_kind_of_violation() {
        let issues = check(
            &schema(),
            json!({"limit": 11, "mode": "z", "tags": ["a", 1, "c"], "extra": true}),
        )
        .unwrap_err();
        let text = issues.join("\n");
        for expected in [
            "url: required",
            "at most 10",
            "one of",
            "expected string",
            "at most 2",
            "extra: unknown",
        ] {
            assert!(text.contains(expected), "{expected} missing in {text}");
        }
    }
}
