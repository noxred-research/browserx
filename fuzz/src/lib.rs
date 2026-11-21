//! Fuzz target bodies. Each function takes raw bytes and must never panic; the invariants
//! below are asserted here so a violation is a crash the fuzzer records. The
//! `fuzz_targets/*.rs` binaries are thin wrappers: libFuzzer entry points under
//! `cfg(fuzzing)`, stdin readers otherwise (crash replay on stable).

use browserx_core::{LeaseToken, ProfileId, ProxyRoute, SessionId, SessionSpec};
use browserx_egress::fuzzing as egress;
use browserx_server::fuzzing as server;
use std::io::Read as _;

/// Runs `target` once over everything on stdin (the non-libFuzzer entry point).
pub fn run_stdin(target: fn(&[u8])) {
    let mut data = Vec::new();
    if std::io::stdin().read_to_end(&mut data).is_ok() {
        target(&data);
    }
}

fn is_blank(body: &[u8]) -> bool {
    body.iter().all(u8::is_ascii_whitespace)
}

/// `session_body`: the first byte picks the route, the rest is the request body. The body is
/// parsed like the handler parses it. An accepted create body is a valid spec that survives
/// being written out and read back; an accepted renew or handoff body keeps its numbers.
pub fn session_body(data: &[u8]) {
    let Some((route, body)) = data.split_first() else {
        return;
    };
    match route % 3 {
        0 => create_body(body),
        1 => renew_body(body),
        _ => handoff_body(body),
    }
}

fn create_body(body: &[u8]) {
    let parsed = server::create_session_body(body);
    if is_blank(body) {
        assert_eq!(
            parsed.as_ref().ok(),
            Some(&SessionSpec::default()),
            "an empty create body is the default spec"
        );
    }
    let Ok(spec) = parsed else {
        return;
    };
    let json = serde_json::to_vec(&spec).expect("a spec serializes");
    let again = server::create_session_body(&json)
        .unwrap_or_else(|e| panic!("accepted spec `{spec:?}` is refused after re-encoding: {e}"));
    assert_eq!(again, spec, "spec changed across a re-encode");
}

fn renew_body(body: &[u8]) {
    let parsed = server::renew_body(body);
    if is_blank(body) {
        assert!(parsed.is_err(), "an empty renew body names no generation");
    }
    let Ok((generation, ttl_secs)) = parsed else {
        return;
    };
    let json = serde_json::json!({ "generation": generation, "ttl_secs": ttl_secs }).to_string();
    assert_eq!(
        server::renew_body(json.as_bytes()).ok(),
        Some((generation, ttl_secs)),
        "renew body changed across a re-encode"
    );
}

fn handoff_body(body: &[u8]) {
    let parsed = server::handoff_body(body);
    if is_blank(body) {
        assert!(parsed.is_err(), "an empty handoff body names no generation");
    }
    let Ok(generation) = parsed else {
        return;
    };
    let json = serde_json::json!({ "generation": generation }).to_string();
    assert_eq!(
        server::handoff_body(json.as_bytes()).ok(),
        Some(generation),
        "handoff body changed across a re-encode"
    );
}

/// `id_parse`: session and profile ids accept the bare and the prefixed form and nothing
/// else; an accepted id re-parses from its own prefixed text. A lease token digest is always
/// 64 hex characters.
pub fn id_parse(data: &[u8]) {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(id) = ProfileId::parse(raw) {
        assert_eq!(
            ProfileId::parse(&id.prefixed()).ok(),
            Some(id),
            "profile id does not round-trip for `{raw}`"
        );
        let json = serde_json::json!({ "profile_id": raw }).to_string();
        let spec: SessionSpec = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("create field refuses an id the parser accepts: {e}"));
        assert_eq!(spec.profile_id, Some(id));
    }
    if let Ok(id) = SessionId::parse(raw) {
        assert_eq!(
            SessionId::parse(&id.prefixed()).ok(),
            Some(id),
            "session id does not round-trip for `{raw}`"
        );
    }
    let digest = LeaseToken::from_client(raw.to_owned()).digest();
    assert!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "token digest is not 64 hex characters"
    );
}

/// `egress_request`: what the loopback forwarder reads from a browser and from an upstream
/// proxy. A request head is split like the forwarder splits it (`CONNECT` takes an authority,
/// every other method an absolute-form target); a normalized destination always parses back
/// to itself, so the host the policy judged is the host that is dialed.
pub fn egress_request(data: &[u8]) {
    if let Ok((method, target, headers)) = egress::request_head(data) {
        assert!(!method.is_empty() && headers <= 128, "head limits");
        assert!(
            target.bytes().all(|b| b > 0x20 && b != 0x7f),
            "target holds a space or a control byte"
        );
        if method == "CONNECT" {
            check_authority(&target);
        } else {
            check_absolute(&target);
        }
    }
    if let Some(status) = egress::reply_status(data) {
        assert!(
            (100..=999).contains(&status),
            "status line gave {status}, not a three-digit code"
        );
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    check_authority(text);
    check_absolute(text);
    let _ = egress::cidr_accepted(text);
}

fn check_authority(text: &str) {
    if let Ok(normalized) = egress::connect_authority(text) {
        assert_eq!(
            egress::connect_authority(&normalized).ok().as_deref(),
            Some(normalized.as_str()),
            "authority `{text}` normalizes to `{normalized}`, which does not parse back to itself"
        );
    }
}

fn check_absolute(text: &str) {
    if let Ok((authority, _host_header, path)) = egress::absolute_target(text) {
        assert!(
            path.starts_with('/'),
            "origin-form path `{path}` for `{text}`"
        );
        assert!(
            !path.contains('#'),
            "fragment kept in origin-form path `{path}` for `{text}`"
        );
        check_authority(&authority);
    }
}

/// `proxy_route`: a `proxy` object of a create request. Admission and the forwarder's route
/// construction must agree: a route the forwarder builds has passed `validate`, and an
/// accepted route never carries credentials in its URL.
pub fn proxy_route(data: &[u8]) {
    let Ok(route) = serde_json::from_slice::<ProxyRoute>(data) else {
        return;
    };
    let validated = route.validate();
    let _ = route.render_username("sticky-key", data.len() as u64);
    if egress::upstream_route(&route, "sticky-key", data.len() as u64).is_ok() {
        assert!(validated.is_ok(), "route built without passing validate");
    }
    if validated.is_ok() {
        assert!(
            !route.url.contains('@'),
            "credentials left in an accepted url"
        );
    }
}
