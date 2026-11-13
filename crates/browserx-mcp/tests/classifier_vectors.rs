//! The shared classifier vectors: the same JSON files are the contract for every implementation
//! of the action classification gate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use browserx_mcp::classifier::{
    ActionClass, Decision, Features, Intent, Profile, classify, decide, table,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    intent: Intent,
    features: Features,
    rw_origins: Vec<String>,
    expect_class: ActionClass,
}

fn load<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = format!(
        "{}/tests/vectors/classifier/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// An origin is inside the scope when the URL is that origin or below it.
fn inside(origins: &[String], url: &str) -> bool {
    origins.iter().any(|origin| {
        url == origin
            || ["/", "?", "#"]
                .iter()
                .any(|sep| url.starts_with(&format!("{origin}{sep}")))
    })
}

#[test]
fn every_case_gets_its_expected_class() {
    let cases: Vec<Case> = load("cases.json");
    assert!(cases.len() >= 30, "only {} cases", cases.len());
    let mut ids: Vec<&str> = cases.iter().map(|c| c.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), cases.len(), "case ids must be unique");
    let mut failures = Vec::new();
    for case in &cases {
        let got = classify(&case.features, case.intent, &|url| {
            inside(&case.rw_origins, url)
        });
        if got.class != case.expect_class {
            failures.push(format!(
                "{}: expected {:?}, got {:?} via {:?}",
                case.id, case.expect_class, got.class, got.rules
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_class_appears_in_the_cases() {
    let cases: Vec<Case> = load("cases.json");
    for class in ActionClass::ALL {
        assert!(
            cases.iter().any(|c| c.expect_class == class),
            "no vector expects {class:?}"
        );
    }
}

#[test]
fn the_decision_file_is_the_decision_table() {
    let file: BTreeMap<String, BTreeMap<String, Decision>> = load("decisions.json");
    assert_eq!(file.len(), Profile::ALL.len());
    let mut rows = 0;
    for (profile, row) in &file {
        let profile: Profile = serde_json::from_value(profile.clone().into()).unwrap();
        assert_eq!(row.len(), ActionClass::ALL.len());
        for (class, decision) in row {
            let class = ActionClass::parse(class).unwrap();
            assert_eq!(decide(profile, class), *decision, "{profile:?} {class:?}");
            rows += 1;
        }
    }
    assert_eq!(rows, table().len());
}
