//! The shared limiter against real Valkey and Redis containers. Both engines run the same test
//! body. Skipped (with a printed note) unless `BROWSERX_TEST_SERVICES=1` and podman are present.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/services.rs"]
mod services;

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use browserx_mcp::backends::cache::{
    Admission, Cache, CacheError, CacheSection, EngagementAdmission,
};
use browserx_mcp::crypto::OperatorKeys;
use browserx_mcp::manifest::{self, Limits};
use browserx_mcp::server::Transport;
use browserx_mcp::{Config, Ctx, McpError, Server};
use redis::AsyncCommands;
use serde_json::{Value, json};
use services::{Service, Spec};

const OP_KEY: &str = "0707070707070707070707070707070707070707070707070707070707070707";

struct Engine {
    name: &'static str,
    image: &'static str,
    server_bin: &'static str,
    cli: &'static str,
}

const VALKEY: Engine = Engine {
    name: "valkey",
    image: "docker.io/valkey/valkey:8.1.3-alpine",
    server_bin: "valkey-server",
    cli: "valkey-cli",
};

const REDIS: Engine = Engine {
    name: "redis",
    image: "docker.io/library/redis:8-alpine",
    server_bin: "redis-server",
    cli: "redis-cli",
};

fn section(port: u16, extra: &str) -> CacheSection {
    toml::from_str(&format!("url = \"redis://127.0.0.1:{port}\"\n{extra}")).unwrap()
}

fn cache(port: u16, extra: &str) -> Cache {
    Cache::new(&section(port, extra)).unwrap()
}

async fn start(engine: &Engine) -> Option<Service> {
    if !services::enabled(engine.name) {
        return None;
    }
    let service = Service::start(
        &Spec {
            image: engine.image,
            ports: &[6379],
            env: &[],
            tmpfs: &["/data"],
            command: &[engine.server_bin, "--save", "", "--appendonly", "no"],
            ready_within: Duration::from_secs(60),
        },
        |ports| async move { services::tcp_open(ports[0]).await },
    )
    .await?;
    wait_ready(&cache(service.ports[0], "")).await;
    Some(service)
}

async fn wait_ready(cache: &Cache) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while cache.probe().await.is_err() {
        assert!(Instant::now() < deadline, "the server never answered PING");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn cli(service: &Service, engine: &Engine, args: &[&str]) -> String {
    let mut command = vec![engine.cli];
    command.extend_from_slice(args);
    service.exec(&command).unwrap_or_default()
}

async fn raw(port: u16) -> redis::aio::MultiplexedConnection {
    redis::Client::open(format!("redis://127.0.0.1:{port}"))
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap()
}

fn podman(args: &[&str]) {
    let status = Command::new("podman")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "podman {args:?}");
}

async fn admitted(cache: &Cache, tool: &str, limit: u32) -> bool {
    matches!(
        cache.rate_limit(tool, limit).await.unwrap(),
        Admission::Admitted
    )
}

// --- scenarios -----------------------------------------------------------------------------

/// A limit of 3 per minute admits 3 calls across two handles, not 6.
async fn limit_is_shared(port: u16) {
    let one = cache(port, "key_prefix = \"shared-a:\"");
    let two = cache(port, "key_prefix = \"shared-a:\"");
    let mut admits = 0;
    for attempt in 0..6 {
        let handle = if attempt % 2 == 0 { &one } else { &two };
        if admitted(handle, "page_snapshot", 3).await {
            admits += 1;
        }
    }
    assert_eq!(admits, 3, "three admitted in total, not three per handle");
    let Admission::Wait(wait) = one.rate_limit("page_snapshot", 3).await.unwrap() else {
        panic!("the fourth call must wait");
    };
    assert!((1..=60).contains(&wait), "wait {wait}");
    // Another tool has its own window.
    assert!(admitted(&two, "list_sessions", 3).await);
    // The window key expires by itself.
    let mut conn = raw(port).await;
    let ttl: i64 = redis::cmd("PTTL")
        .arg("shared-a:rl:page_snapshot")
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!((1..=120_000).contains(&ttl), "pttl {ttl}");
    assert!(one.healthy() && !one.degraded());
    assert_eq!(one.fallback_total(), 0);
}

/// A second prefix on the same instance has its own counters.
async fn prefixes_are_independent(port: u16) {
    let a = cache(port, "key_prefix = \"ns-a:\"");
    let b = cache(port, "key_prefix = \"ns-b:\"");
    for _ in 0..3 {
        assert!(admitted(&a, "t", 3).await);
    }
    assert!(!admitted(&a, "t", 3).await);
    for _ in 0..3 {
        assert!(admitted(&b, "t", 3).await, "the other prefix is untouched");
    }
    assert!(!admitted(&b, "t", 3).await);
}

/// The window slides: a refused call is admitted once the window has passed.
async fn window_slides(port: u16) {
    let c = cache(port, "key_prefix = \"slide:\"");
    for _ in 0..2 {
        assert!(admitted(&c, "t", 2).await);
    }
    let Admission::Wait(wait) = c.rate_limit("t", 2).await.unwrap() else {
        panic!("must wait");
    };
    assert!((1..=60).contains(&wait));
    // The members carry their scores: moving them back in time is the server's own clock, so
    // age them by rewriting the scores instead of sleeping a minute.
    let mut conn = raw(port).await;
    let members: Vec<String> = conn.zrange("slide:rl:t", 0, -1).await.unwrap();
    assert_eq!(members.len(), 2);
    for member in members {
        let _: i64 = conn.zadd("slide:rl:t", member, 1_i64).await.unwrap();
    }
    assert!(admitted(&c, "t", 2).await, "old entries leave the window");
    let left: i64 = conn.zcard("slide:rl:t").await.unwrap();
    assert_eq!(left, 1);
}

/// `clear_namespace` deletes its own prefix only.
async fn clear_namespace_is_scoped(port: u16) {
    let a = cache(port, "key_prefix = \"clr-a:\"");
    let b = cache(port, "key_prefix = \"clr-b:\"");
    let mut conn = raw(port).await;
    assert!(admitted(&a, "t", 5).await);
    assert!(admitted(&b, "t", 5).await);
    // Enough keys that SCAN needs several steps.
    for n in 0..600 {
        let _: () = conn.set(format!("clr-a:junk:{n}"), n).await.unwrap();
    }
    let _: () = conn.set("foreign:keep", "1").await.unwrap();
    let _: () = conn.set("clr-a", "no colon, not ours").await.unwrap();
    let deleted = a.clear_namespace().await.unwrap();
    assert_eq!(deleted, 601, "600 junk keys and the window key");
    assert!(conn.exists::<_, bool>("foreign:keep").await.unwrap());
    assert!(conn.exists::<_, bool>("clr-a").await.unwrap());
    assert!(conn.exists::<_, bool>("clr-b:rl:t").await.unwrap());
    assert!(!conn.exists::<_, bool>("clr-a:rl:t").await.unwrap());
    assert_eq!(a.clear_namespace().await.unwrap(), 0);
    assert_eq!(b.clear_namespace().await.unwrap(), 1);
    assert!(conn.exists::<_, bool>("foreign:keep").await.unwrap());
}

/// Engagement budgets are shared and per engagement.
async fn engagement_budgets_are_shared(port: u16) {
    let one = cache(port, "key_prefix = \"eng:\"");
    let two = cache(port, "key_prefix = \"eng:\"");
    let budget = Limits {
        rps: None,
        max_calls: Some(3),
    };
    for handle in [&one, &two, &one] {
        assert_eq!(
            handle.engagement("eng-1", budget).await.unwrap(),
            EngagementAdmission::Admitted
        );
    }
    assert!(matches!(
        two.engagement("eng-1", budget).await.unwrap(),
        EngagementAdmission::BudgetExhausted { used: 4 }
    ));
    // Another engagement, and an id that is not key-safe, have their own counters.
    assert_eq!(
        two.engagement("eng-2", budget).await.unwrap(),
        EngagementAdmission::Admitted
    );
    assert_eq!(
        one.engagement("odd id: with * glob\n", budget)
            .await
            .unwrap(),
        EngagementAdmission::Admitted
    );
    let mut conn = raw(port).await;
    let ttl: i64 = conn.ttl("eng:eng:eng-1:calls").await.unwrap();
    assert!(ttl > 0, "the counter expires: {ttl}");
    let keys: Vec<String> = redis::cmd("SCAN")
        .arg(0)
        .arg("MATCH")
        .arg("eng:eng:h-*")
        .arg("COUNT")
        .arg(1000)
        .query_async::<(u64, Vec<String>)>(&mut conn)
        .await
        .unwrap()
        .1;
    assert!(!keys.is_empty(), "the odd id is stored under its digest");

    // Calls per second are shared too.
    let rate = Limits {
        rps: Some(2),
        max_calls: None,
    };
    assert_eq!(
        one.engagement("eng-rps", rate).await.unwrap(),
        EngagementAdmission::Admitted
    );
    assert_eq!(
        two.engagement("eng-rps", rate).await.unwrap(),
        EngagementAdmission::Admitted
    );
    assert_eq!(
        one.engagement("eng-rps", rate).await.unwrap(),
        EngagementAdmission::RateExceeded
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        two.engagement("eng-rps", rate).await.unwrap(),
        EngagementAdmission::Admitted
    );
    // Both limits at once: a call refused by the rate does not spend budget.
    let both = Limits {
        rps: Some(1),
        max_calls: Some(2),
    };
    assert_eq!(
        one.engagement("eng-both", both).await.unwrap(),
        EngagementAdmission::Admitted
    );
    assert_eq!(
        two.engagement("eng-both", both).await.unwrap(),
        EngagementAdmission::RateExceeded
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        two.engagement("eng-both", both).await.unwrap(),
        EngagementAdmission::Admitted
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(matches!(
        one.engagement("eng-both", both).await.unwrap(),
        EngagementAdmission::BudgetExhausted { used: 3 }
    ));
}

/// An ACL user with a password works; a wrong password is a typed error that never echoes it.
async fn acl_user_and_wrong_password(port: u16, service: &Service, engine: &Engine) {
    let password = "pw-for-acl-user-7f3a";
    let reply = cli(
        service,
        engine,
        &[
            "ACL",
            "SETUSER",
            "bxuser",
            "on",
            &format!(">{password}"),
            "~acl:*",
            "+@all",
            "-@dangerous",
            "+eval",
            "+scan",
            "+ping",
        ],
    );
    assert!(reply.contains("OK"), "ACL SETUSER: {reply}");
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("pw");
    std::fs::write(&file, format!("{password}\n")).unwrap();
    let mut section = section(
        port,
        "key_prefix = \"acl:\"\nusername = \"bxuser\"\npassword_file = \"pw\"",
    );
    section.resolve_paths(dir.path());
    let good = Cache::new(&section).unwrap();
    assert!(admitted(&good, "t", 2).await);
    assert!(good.healthy());
    assert_eq!(good.clear_namespace().await.unwrap(), 1);

    let wrong_dir = tempfile::tempdir().unwrap();
    let wrong_pw = "definitely-the-wrong-password";
    std::fs::write(wrong_dir.path().join("pw"), wrong_pw).unwrap();
    let mut wrong = section.clone();
    wrong.password_file = Some(wrong_dir.path().join("pw"));
    let bad = Cache::new(&wrong).unwrap();
    let error = bad.rate_limit("t", 2).await.unwrap_err();
    assert!(matches!(error, CacheError::Auth(_)), "{error:?}");
    let text = format!("{error} {error:?} {bad:?} {:?}", bad.status());
    assert!(
        !text.contains(wrong_pw) && !text.contains(password),
        "{text}"
    );
    assert!(bad.degraded());
    assert_eq!(bad.fallback_total(), 1);

    // The right user may not touch keys outside its ACL pattern: a typed refusal, not a panic.
    let mut outside = section.clone();
    outside.key_prefix = "not-acl:".into();
    let denied = Cache::new(&outside).unwrap();
    let error = denied.rate_limit("t", 2).await.unwrap_err();
    assert!(
        matches!(&error, CacheError::Auth(what) if what == "NOPERM"),
        "{error:?}"
    );
    assert!(!format!("{error}").contains(password));
}

/// A cache that cannot be reached at all: required refuses to start, optional starts degraded.
async fn unreachable_cache_at_startup() {
    let dead = |extra: &str| {
        format!(
            "[cache]\nurl = \"redis://127.0.0.1:1\"\nkey_prefix = \"dead:\"\nconnect_timeout_ms = 300\ncommand_timeout_ms = 200\n{extra}"
        )
    };
    let (ctx, _dir) = ctx_with(&dead("required = true"), None);
    let error = ctx.check_cache().await.unwrap_err();
    assert!(matches!(error, McpError::Cache(_)), "{error:?}");
    assert!(error.to_string().contains("cache.required"), "{error}");

    let (ctx, _dir) = ctx_with(&dead(""), None);
    ctx.check_cache().await.unwrap();
    let cache = ctx.cache.as_ref().unwrap();
    assert!(cache.degraded() && !cache.healthy());
    // The in-memory limiter answers, and still enforces the limit.
    for _ in 0..2 {
        assert!(ctx.admit("t", 2).await.is_ok());
    }
    assert!(ctx.admit("t", 2).await.is_err());
    assert!(cache.fallback_total() >= 3);
}

/// Pausing the container is an outage that hangs commands: fallback holds the limit, and the
/// cache recovers when the container does.
async fn outage_and_recovery(port: u16, service: &Service) {
    let text = format!(
        "[cache]\nurl = \"redis://127.0.0.1:{port}\"\nkey_prefix = \"outage:\"\nconnect_timeout_ms = 500\ncommand_timeout_ms = 300\n"
    );
    let (ctx, _dir) = ctx_with(&text, None);
    ctx.check_cache().await.unwrap();
    let cache = Arc::clone(ctx.cache.as_ref().unwrap());
    assert!(cache.healthy());
    // Two of three calls are spent through the cache.
    assert!(ctx.admit("burst", 3).await.is_ok());
    assert!(ctx.admit("burst", 3).await.is_ok());
    // A second server shares the window.
    let (other, _other_dir) = ctx_with(&text, None);
    assert!(other.admit("burst", 3).await.is_ok());
    assert!(other.admit("burst", 3).await.is_err(), "three in total");

    podman(&["pause", service.name()]);
    let started = Instant::now();
    // The limit is never relaxed: this server spent two calls, one more fits, the next does not.
    assert!(ctx.admit("burst", 3).await.is_ok(), "one slot left locally");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(cache.degraded() && !cache.healthy());
    assert!(
        ctx.admit("burst", 3).await.is_err(),
        "the limit still holds"
    );
    // A tool this server never used starts from zero in memory, bounded by the same limit.
    assert!(ctx.admit("fresh", 1).await.is_ok());
    assert!(ctx.admit("fresh", 1).await.is_err());
    assert!(cache.fallback_total() >= 4, "{}", cache.fallback_total());
    // While degraded the calls do not wait for the timeout each.
    let burst = Instant::now();
    for _ in 0..20 {
        let _ = ctx.admit("fresh", 1).await;
    }
    assert!(
        burst.elapsed() < Duration::from_secs(2),
        "{:?}",
        burst.elapsed()
    );

    // `capabilities` says so, without address or password.
    let server = Server::new(Arc::clone(&ctx));
    let caps = tool(&server, "capabilities", json!({})).await;
    assert_eq!(
        caps["structuredContent"]["cache"],
        json!({
            "configured": true, "healthy": false, "degraded": true,
            "key_prefix": "outage:",
            "fallback_total": cache.fallback_total(),
        })
    );
    assert!(!caps.to_string().contains(&port.to_string()));

    podman(&["unpause", service.name()]);
    let deadline = Instant::now() + Duration::from_secs(15);
    while !cache.healthy() {
        assert!(Instant::now() < deadline, "the cache never recovered");
        let _ = ctx.admit("recover", 100).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(!cache.degraded());
    // The shared window is back: the three calls of "burst" are still counted there.
    assert!(ctx.admit("burst", 3).await.is_err());
    let caps = tool(&server, "capabilities", json!({})).await;
    assert_eq!(caps["structuredContent"]["cache"]["healthy"], true);
    assert_eq!(caps["structuredContent"]["cache"]["degraded"], false);
}

/// The whole path: two MCP contexts on one prefix share a tool limit and an engagement budget.
async fn end_to_end_two_servers(port: u16) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("operator.keys"), format!("op = {OP_KEY}\n")).unwrap();
    let keys = OperatorKeys::load(&dir.path().join("operator.keys")).unwrap();
    let manifest_text = "[engagement]\nid = \"eng-e2e\"\noperator = \"alice\"\nauthorization_note = \"ticket 42\"\n\
                         not_after = \"2099-01-01T00:00:00Z\"\n[[scope]]\nhost = \"app.example.test\"\nmode = \"attack\"\n\
                         [limits]\nmax_calls = 2\n";
    std::fs::write(dir.path().join("engagement.toml"), manifest_text).unwrap();
    std::fs::write(
        dir.path().join("engagement.toml.sig"),
        manifest::sign(&keys, "op", manifest_text.as_bytes()).unwrap(),
    )
    .unwrap();
    let text = format!(
        "[operator]\nkeys_file = \"operator.keys\"\n[manifest]\npath = \"engagement.toml\"\n\
         [mcp]\ncapabilities = [\"browse\"]\n[browse]\nrequire_scope = false\n\
         [limits.per_minute]\nexplain_error = 2\n\
         [cache]\nurl = \"redis://127.0.0.1:{port}\"\nkey_prefix = \"e2e:\"\n"
    );
    let (a, _a) = ctx_with(&text, Some(dir.path()));
    let (b, _b) = ctx_with(&text, Some(dir.path()));
    a.check_cache().await.unwrap();
    b.check_cache().await.unwrap();
    let (sa, sb) = (Server::new(a), Server::new(b));

    // A tool limit of two per minute across both servers.
    let args = json!({"code": "capacity"});
    let first = tool(&sa, "explain_error", args.clone()).await;
    let second = tool(&sb, "explain_error", args.clone()).await;
    let third = tool(&sa, "explain_error", args.clone()).await;
    let fourth = tool(&sb, "explain_error", args).await;
    assert_eq!(first["isError"], false, "{first}");
    assert_eq!(second["isError"], false, "{second}");
    for refused in [&third, &fourth] {
        assert_eq!(refused["isError"], true, "{refused}");
        assert_eq!(
            refused["structuredContent"]["error"]["kind"], "rate_limited",
            "{refused}"
        );
    }

    // An engagement budget of two page calls across both servers. The calls themselves fail
    // (there is no browser), after the budget was counted.
    let page = json!({"session_id": "ses_00000000000000000000000000000001"});
    let one = tool(&sa, "page_snapshot", page.clone()).await;
    let two = tool(&sb, "page_snapshot", page.clone()).await;
    let three = tool(&sa, "page_snapshot", page.clone()).await;
    let four = tool(&sb, "page_snapshot", page).await;
    for allowed in [&one, &two] {
        assert_ne!(
            reason(allowed).as_deref(),
            Some("budget_exhausted"),
            "{allowed}"
        );
    }
    for refused in [&three, &four] {
        assert_eq!(
            reason(refused).as_deref(),
            Some("budget_exhausted"),
            "{refused}"
        );
    }
    let caps = tool(&sa, "capabilities", json!({})).await;
    let cache = &caps["structuredContent"]["cache"];
    assert_eq!(cache["configured"], true);
    assert_eq!(cache["healthy"], true);
    assert_eq!(cache["key_prefix"], "e2e:");
    let mut conn = raw(port).await;
    let used: i64 = conn.get("e2e:eng:eng-e2e:calls").await.unwrap();
    assert_eq!(
        used, 4,
        "every call spends the shared budget, including the refused ones"
    );
}

/// TLS with a private certificate authority: `tls_ca_file` makes the server trusted, and
/// without it the certificate is refused.
async fn tls_with_private_ca(engine: &Engine) {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let run = |args: &[&str]| {
        let out = Command::new("openssl")
            .args(args)
            .current_dir(d)
            .stdin(Stdio::null())
            .output();
        matches!(out, Ok(out) if out.status.success())
    };
    let made = run(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "2",
        "-subj",
        "/CN=bx-test-ca",
    ]) && run(&[
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "srv.key",
        "-out",
        "srv.csr",
        "-subj",
        "/CN=127.0.0.1",
    ]) && {
        std::fs::write(d.join("ext"), "subjectAltName=IP:127.0.0.1\n").unwrap();
        run(&[
            "x509",
            "-req",
            "-in",
            "srv.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "srv.pem",
            "-days",
            "2",
            "-extfile",
            "ext",
        ])
    };
    if !made {
        eprintln!("SKIP: openssl is not available, TLS scenario not run");
        return;
    }
    let cert = std::fs::read_to_string(d.join("srv.pem")).unwrap();
    let key = std::fs::read_to_string(d.join("srv.key")).unwrap();
    let ca = std::fs::read_to_string(d.join("ca.pem")).unwrap();
    let script = format!(
        "printf '%s' \"$TLS_CERT\" > /tmp/srv.pem; printf '%s' \"$TLS_KEY\" > /tmp/srv.key; printf '%s' \"$TLS_CA\" > /tmp/ca.pem; \
         exec {} --save '' --appendonly no --port 0 --tls-port 6379 --tls-cert-file /tmp/srv.pem --tls-key-file /tmp/srv.key \
         --tls-ca-cert-file /tmp/ca.pem --tls-auth-clients no",
        engine.server_bin
    );
    let env = [
        format!("TLS_CERT={cert}"),
        format!("TLS_KEY={key}"),
        format!("TLS_CA={ca}"),
    ];
    let env_refs: Vec<&str> = env.iter().map(String::as_str).collect();
    let Some(service) = Service::start(
        &Spec {
            image: engine.image,
            ports: &[6379],
            env: &env_refs,
            tmpfs: &["/data", "/tmp"],
            command: &["sh", "-c", &script],
            ready_within: Duration::from_secs(60),
        },
        |ports| async move { services::tcp_open(ports[0]).await },
    )
    .await
    else {
        return;
    };
    let port = service.ports[0];
    let tls = |extra: &str| {
        toml::from_str::<CacheSection>(&format!(
            "url = \"rediss://127.0.0.1:{port}\"\nkey_prefix = \"tls:\"\nconnect_timeout_ms = 1500\n{extra}"
        ))
        .unwrap()
    };
    // Without the CA the certificate is not trusted: unreachable, so degraded.
    let untrusted = Cache::new(&tls("")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut trusted_ok = false;
    let mut with_ca = tls("");
    with_ca.tls_ca_file = Some(d.join("ca.pem"));
    let trusted = Cache::new(&with_ca).unwrap();
    while Instant::now() < deadline {
        if trusted.probe().await.is_ok() {
            trusted_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(trusted_ok, "the CA file must make the server trusted");
    assert!(admitted(&trusted, "t", 1).await);
    assert!(!admitted(&trusted, "t", 1).await);
    let error = untrusted.probe().await.unwrap_err();
    assert!(
        matches!(error, CacheError::Unreachable(_) | CacheError::Timeout(_)),
        "{error:?}"
    );
    assert!(untrusted.degraded());
    // A CA file that is not a certificate is refused at load.
    std::fs::write(d.join("junk.pem"), "not a certificate").unwrap();
    let mut junk = tls("");
    junk.tls_ca_file = Some(d.join("junk.pem"));
    assert!(matches!(
        Cache::new(&junk).unwrap_err(),
        CacheError::Config(_)
    ));
}

// --- helpers for the MCP-level scenarios ---------------------------------------------------

fn ctx_with(cache_and_extra: &str, dir: Option<&Path>) -> (Arc<Ctx>, Option<tempfile::TempDir>) {
    let (dir_path, owned) = match dir {
        Some(dir) => (dir.to_path_buf(), None),
        None => {
            let owned = tempfile::tempdir().unwrap();
            (owned.path().to_path_buf(), Some(owned))
        }
    };
    std::fs::write(dir_path.join("key"), "bxk_synthetic\n").unwrap();
    let audit = format!("audit-{}.jsonl", rand::random::<u32>());
    let text = format!(
        "[server]\nurl = \"http://127.0.0.1:1\"\napi_key_file = \"key\"\n[audit]\npath = \"{audit}\"\n{cache_and_extra}"
    );
    let config = Config::parse(&text, &dir_path).unwrap();
    (Ctx::build(config).unwrap(), owned)
}

async fn tool(server: &Server, name: &str, arguments: Value) -> Value {
    server
        .handle(
            "tools/call",
            Some(json!({"name": name, "arguments": arguments})),
            &Transport {
                name: "stdio",
                remote: None,
                principal: None,
            },
        )
        .await
        .unwrap()
}

fn reason(result: &Value) -> Option<String> {
    result["structuredContent"]["error"]["detail"]["reason"]
        .as_str()
        .map(str::to_owned)
}

async fn suite(engine: &Engine) {
    let Some(service) = start(engine).await else {
        return;
    };
    let port = service.ports[0];
    let name = engine.name;
    eprintln!("{name}: limit_is_shared");
    limit_is_shared(port).await;
    eprintln!("{name}: prefixes_are_independent");
    prefixes_are_independent(port).await;
    eprintln!("{name}: window_slides");
    window_slides(port).await;
    eprintln!("{name}: clear_namespace_is_scoped");
    clear_namespace_is_scoped(port).await;
    eprintln!("{name}: engagement_budgets_are_shared");
    engagement_budgets_are_shared(port).await;
    eprintln!("{name}: acl_user_and_wrong_password");
    acl_user_and_wrong_password(port, &service, engine).await;
    eprintln!("{name}: unreachable_cache_at_startup");
    unreachable_cache_at_startup().await;
    eprintln!("{name}: end_to_end_two_servers");
    end_to_end_two_servers(port).await;
    eprintln!("{name}: outage_and_recovery");
    outage_and_recovery(port, &service).await;
    drop(service);
    eprintln!("{name}: tls_with_private_ca");
    tls_with_private_ca(engine).await;
}

#[tokio::test]
async fn valkey_shares_limits_between_servers() {
    suite(&VALKEY).await;
}

#[tokio::test]
async fn redis_shares_limits_between_servers() {
    suite(&REDIS).await;
}

#[test]
fn config_in_mcp_toml_is_validated_at_load() {
    let base = |cache: &str| {
        format!(
            "[server]\nurl = \"http://127.0.0.1:1\"\napi_key_file = \"key\"\n[audit]\npath = \"audit.jsonl\"\n[cache]\n{cache}"
        )
    };
    let dir = Path::new("/tmp");
    let good = Config::parse(&base("url = \"redis://127.0.0.1:6379\""), dir).unwrap();
    assert_eq!(good.cache.as_ref().unwrap().key_prefix, "browserx:");
    for (why, cache) in [
        ("password in url", "url = \"redis://u:p@127.0.0.1:6379\""),
        (
            "unknown key",
            "url = \"redis://127.0.0.1:6379\"\nsurprise = 1",
        ),
        (
            "remote plaintext",
            "url = \"redis://cache.example.test:6379\"",
        ),
        ("missing url", "key_prefix = \"a:\""),
        (
            "bad prefix",
            "url = \"redis://127.0.0.1:6379\"\nkey_prefix = \"a\"",
        ),
    ] {
        assert!(Config::parse(&base(cache), dir).is_err(), "{why}");
    }
    // Relative secret files resolve against the configuration directory.
    let cfg = Config::parse(
        &base("url = \"rediss://cache.example.test:6380\"\npassword_file = \"pw\""),
        Path::new("/etc/bx"),
    )
    .unwrap();
    assert_eq!(
        cfg.cache.unwrap().password_file.as_deref(),
        Some(Path::new("/etc/bx/pw"))
    );
}
