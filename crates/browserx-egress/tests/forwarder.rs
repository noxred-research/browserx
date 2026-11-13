//! End-to-end forwarder behavior against fake upstreams on loopback.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use browserx_core::{Error, ProxyRoute, Secret};
use browserx_egress::{EgressPolicy, Forwarder, ForwarderOptions};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

fn allow_loopback() -> EgressPolicy {
    EgressPolicy {
        block_private: true,
        allow_cidrs: vec!["127.0.0.0/8".into()],
    }
}

/// The fake upstream proxies listen on `127.0.0.2`; this policy lets the
/// forwarder reach them and nothing else on the loopback range.
fn allow_proxy_only() -> EgressPolicy {
    EgressPolicy {
        block_private: true,
        allow_cidrs: vec!["127.0.0.2/32".into()],
    }
}

fn route(url: String, user: Option<&str>, pass: Option<&str>) -> ProxyRoute {
    ProxyRoute {
        url,
        username: user.map(Into::into),
        password: pass.map(Secret::new),
    }
}

fn basic(user: &str, pass: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")))
}

async fn start(upstream: Option<ProxyRoute>, policy: EgressPolicy) -> Forwarder {
    Forwarder::start(upstream, "sess-key".into(), 3, policy)
        .await
        .unwrap()
}

// ---------------------------------------------------------------- direct

#[tokio::test]
async fn direct_connect_tunnels_and_counts_bytes() {
    let origin = OriginServer::start(Origin::Echo).await;
    let fwd = start(None, allow_loopback()).await;
    assert_eq!(
        fwd.proxy_server(),
        format!("http://127.0.0.1:{}", fwd.local_addr().port())
    );
    assert!(fwd.local_addr().ip().is_loopback());

    let (status, mut tunnel) = connect_via(&fwd, &origin.addr.to_string()).await;
    assert_eq!(status, 200);
    echo_roundtrip(&mut tunnel, b"hello tunnel").await;
    echo_roundtrip(&mut tunnel, &vec![7u8; 100_000]).await;
    drop(tunnel);

    tokio::time::sleep(Duration::from_millis(100)).await;
    let stats = fwd.stats();
    assert_eq!(stats.connections, 1);
    assert_eq!(stats.refused, 0);
    assert_eq!(stats.bytes_up, 100_012);
    assert_eq!(stats.bytes_down, 100_012);
    fwd.shutdown().await;
}

#[tokio::test]
async fn direct_plain_http_is_rewritten_to_origin_form() {
    let origin = OriginServer::start(Origin::Http).await;
    let fwd = start(None, allow_loopback()).await;
    let url = format!("http://{}/path/x?y=1", origin.addr);
    let response = exchange(
        &fwd,
        format!("GET {url} HTTP/1.1\r\nHost: wrong.invalid\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("hello-world"));

    let seen = origin.requests.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let expected_host = format!("Host: {}\r\n", origin.addr);
    assert!(
        seen[0].starts_with("GET /path/x?y=1 HTTP/1.1\r\n"),
        "{}",
        seen[0]
    );
    assert!(seen[0].contains(&expected_host), "{}", seen[0]);
    assert!(seen[0].contains("Accept: */*\r\n"));
    assert!(seen[0].contains("Connection: close\r\n"));
    assert!(!seen[0].contains("Proxy-Connection") && !seen[0].contains("wrong.invalid"));
    fwd.shutdown().await;
}

#[tokio::test]
async fn direct_refuses_private_destinations_by_default() {
    let origin = OriginServer::start(Origin::Echo).await;
    let fwd = start(None, EgressPolicy::default()).await;

    let (status, _) = connect_via(&fwd, &origin.addr.to_string()).await;
    assert_eq!(status, 403);
    let (status, _) = connect_via(&fwd, "169.254.169.254:80").await;
    assert_eq!(status, 403);
    let (status, _) = connect_via(&fwd, "[::1]:80").await;
    assert_eq!(status, 403);
    let (status, _) = connect_via(&fwd, "2130706433:80").await;
    assert_eq!(status, 403);
    let (status, _) = connect_via(&fwd, "localhost:80").await;
    assert_eq!(status, 403);
    let response = exchange(
        &fwd,
        format!("GET http://{}/ HTTP/1.1\r\nHost: x\r\n\r\n", origin.addr).as_bytes(),
    )
    .await;
    assert_eq!(status_of(&response), 403);
    assert!(response.contains("blocked by egress policy"));

    let stats = fwd.stats();
    assert_eq!(stats.refused, 6);
    assert_eq!(stats.connections, 0);
    fwd.shutdown().await;
}

#[tokio::test]
async fn allow_list_must_cover_the_destination() {
    let origin = OriginServer::start(Origin::Echo).await;
    let elsewhere = EgressPolicy {
        block_private: true,
        allow_cidrs: vec!["10.0.0.0/8".into()],
    };
    let fwd = start(None, elsewhere).await;
    let (status, _) = connect_via(&fwd, &origin.addr.to_string()).await;
    assert_eq!(status, 403);
    fwd.shutdown().await;

    let single = EgressPolicy {
        block_private: true,
        allow_cidrs: vec!["127.0.0.1".into()],
    };
    let fwd = start(None, single).await;
    let (status, mut tunnel) = connect_via(&fwd, &origin.addr.to_string()).await;
    assert_eq!(status, 200);
    echo_roundtrip(&mut tunnel, b"ok").await;
    fwd.shutdown().await;

    let open = EgressPolicy {
        block_private: false,
        allow_cidrs: vec![],
    };
    let fwd = start(None, open).await;
    let (status, _) = connect_via(&fwd, &origin.addr.to_string()).await;
    assert_eq!(status, 200);
    fwd.shutdown().await;
}

#[tokio::test]
async fn direct_unreachable_destination_is_bad_gateway() {
    let closed = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let fwd = start(None, allow_loopback()).await;
    let (status, _) = connect_via(&fwd, &closed.to_string()).await;
    assert_eq!(status, 502);
    assert_eq!(fwd.stats().refused, 0);
    fwd.shutdown().await;
}

#[tokio::test]
async fn half_close_and_pipelined_bytes_are_preserved() {
    let origin = OriginServer::start(Origin::CountThenReply).await;
    let fwd = start(None, allow_loopback()).await;
    let mut s = TcpStream::connect(fwd.local_addr()).await.unwrap();
    // bytes pipelined behind the CONNECT head must reach the destination
    let mut req =
        format!("CONNECT {a} HTTP/1.1\r\nHost: {a}\r\n\r\n", a = origin.addr).into_bytes();
    req.extend_from_slice(b"early");
    s.write_all(&req).await.unwrap();
    let (status, _) = read_status(&mut s).await;
    assert_eq!(status, 200);
    s.write_all(b"-late").await.unwrap();
    s.shutdown().await.unwrap();
    let mut reply = String::new();
    timeout(STEP, s.read_to_string(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, "got 10");
    fwd.shutdown().await;
}

// ---------------------------------------------------------------- HTTP upstream

#[tokio::test]
async fn http_upstream_connect_with_rendered_credentials() {
    let proxy = ConnectProxy::start(ConnectOpts {
        expect_auth: Some(basic("pool-sess-key-g3", "synthetic-secret")),
        ..ConnectOpts::default()
    })
    .await;
    let r = route(
        proxy.url("http"),
        Some("pool-{session}-g{generation}"),
        Some("synthetic-secret"),
    );
    let fwd = start(Some(r), allow_proxy_only()).await;

    // the destination name is resolved by the upstream, so the local policy lets it through
    let (status, mut tunnel) = connect_via(&fwd, "site.test:443").await;
    assert_eq!(status, 200);
    echo_roundtrip(&mut tunnel, b"through upstream").await;

    let seen = proxy.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "site.test:443");
    assert_eq!(
        seen[0].proxy_authorization.as_deref(),
        Some(basic("pool-sess-key-g3", "synthetic-secret").as_str())
    );
    fwd.shutdown().await;
}

#[tokio::test]
async fn http_upstream_without_credentials_sends_no_auth_header() {
    let proxy = ConnectProxy::start(ConnectOpts::default()).await;
    let fwd = start(
        Some(route(proxy.url("http"), None, None)),
        allow_proxy_only(),
    )
    .await;
    let (status, _) = connect_via(&fwd, "site.test:443").await;
    assert_eq!(status, 200);
    let seen = proxy.seen.lock().unwrap().clone();
    assert!(seen[0].proxy_authorization.is_none());
    assert!(
        seen[0]
            .head
            .starts_with("CONNECT site.test:443 HTTP/1.1\r\n")
    );
    fwd.shutdown().await;
}

#[tokio::test]
async fn plain_http_becomes_connect_plus_origin_form_request() {
    let proxy = ConnectProxy::start(ConnectOpts {
        origin: Origin::Http,
        ..ConnectOpts::default()
    })
    .await;
    let r = route(proxy.url("http"), Some("u-{session}"), Some("p"));
    let fwd = start(Some(r), allow_proxy_only()).await;

    let response = exchange(
        &fwd,
        b"GET http://site.test:8080/a/b?c=d HTTP/1.1\r\nHost: site.test:8080\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\nUser-Agent: synthetic\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("hello-world"));

    // the gateway saw a CONNECT, not an absolute-form GET
    let seen = proxy.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "site.test:8080");
    assert_eq!(
        seen[0].proxy_authorization.as_deref(),
        Some(basic("u-sess-key", "p").as_str())
    );
    // inside the tunnel: origin-form, no proxy headers from the browser
    let inner = proxy.origin_requests.lock().unwrap().clone();
    assert_eq!(inner.len(), 1);
    assert!(
        inner[0].starts_with("GET /a/b?c=d HTTP/1.1\r\n"),
        "{}",
        inner[0]
    );
    assert!(inner[0].contains("Host: site.test:8080\r\n"));
    assert!(inner[0].contains("User-Agent: synthetic\r\n"));
    assert!(inner[0].contains("Connection: close\r\n"));
    assert!(!inner[0].contains("Proxy-") && !inner[0].contains("Zm9vOmJhcg=="));
    fwd.shutdown().await;
}

#[tokio::test]
async fn server_first_bytes_after_connect_reach_the_client() {
    let proxy = ConnectProxy::start(ConnectOpts {
        greeting: b"SERVER-HELLO".to_vec(),
        ..ConnectOpts::default()
    })
    .await;
    let fwd = start(
        Some(route(proxy.url("http"), None, None)),
        allow_proxy_only(),
    )
    .await;
    let (status, mut tunnel) = connect_via(&fwd, "site.test:25").await;
    assert_eq!(status, 200);
    let mut hello = [0u8; 12];
    timeout(STEP, tunnel.read_exact(&mut hello))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&hello, b"SERVER-HELLO");
    fwd.shutdown().await;
}

#[tokio::test]
async fn http_upstream_failures_map_to_bad_gateway_without_leaking_secrets() {
    let wrong_auth = ConnectProxy::start(ConnectOpts {
        expect_auth: Some(basic("someone-else", "x")),
        ..ConnectOpts::default()
    })
    .await;
    let fwd = start(
        Some(route(
            wrong_auth.url("http"),
            Some("user"),
            Some("synthetic-secret"),
        )),
        allow_proxy_only(),
    )
    .await;
    let response = exchange(
        &fwd,
        b"CONNECT site.test:443 HTTP/1.1\r\nHost: site.test:443\r\n\r\n",
    )
    .await;
    assert_eq!(status_of(&response), 502);
    assert!(response.contains("rejected the credentials"));
    assert!(!response.contains("synthetic-secret") && !response.contains("user"));
    fwd.shutdown().await;

    let denies = ConnectProxy::start(ConnectOpts {
        reject_status: Some(403),
        ..ConnectOpts::default()
    })
    .await;
    let fwd = start(
        Some(route(denies.url("http"), None, None)),
        allow_proxy_only(),
    )
    .await;
    let response = exchange(
        &fwd,
        b"CONNECT site.test:443 HTTP/1.1\r\nHost: site.test:443\r\n\r\n",
    )
    .await;
    assert_eq!(status_of(&response), 502);
    assert!(response.contains("status 403"));
    fwd.shutdown().await;

    let dead = {
        let l = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let fwd = start(
        Some(route(format!("http://{dead}"), None, None)),
        allow_proxy_only(),
    )
    .await;
    let (status, _) = connect_via(&fwd, "site.test:443").await;
    assert_eq!(status, 502);
    fwd.shutdown().await;
}

#[tokio::test]
async fn http_upstream_literals_and_localhost_are_checked_locally() {
    let proxy = ConnectProxy::start(ConnectOpts::default()).await;
    let fwd = start(
        Some(route(proxy.url("http"), None, None)),
        allow_proxy_only(),
    )
    .await;
    for target in [
        "10.1.2.3:80",
        "127.0.0.1:80",
        "localhost:80",
        "app.localhost:80",
        "0x7f.1:80",
        "[fd00::1]:80",
    ] {
        let (status, _) = connect_via(&fwd, target).await;
        assert_eq!(status, 403, "{target}");
    }
    assert!(
        proxy.seen.lock().unwrap().is_empty(),
        "refused destinations must not reach the upstream"
    );
    assert_eq!(fwd.stats().refused, 6);
    // a public literal goes through
    let (status, _) = connect_via(&fwd, "93.184.216.34:80").await;
    assert_eq!(status, 200);
    assert_eq!(proxy.seen.lock().unwrap().len(), 1);
    fwd.shutdown().await;
}

#[tokio::test]
async fn upstream_that_never_answers_times_out() {
    let proxy = ConnectProxy::start(ConnectOpts {
        blackhole: true,
        ..ConnectOpts::default()
    })
    .await;
    let options = ForwarderOptions {
        connect_timeout: Duration::from_millis(300),
        ..ForwarderOptions::default()
    };
    let fwd = Forwarder::start_with(
        Some(route(proxy.url("http"), None, None)),
        "k".into(),
        1,
        allow_proxy_only(),
        options,
    )
    .await
    .unwrap();
    let (status, _) = connect_via(&fwd, "site.test:443").await;
    assert_eq!(status, 504);
    fwd.shutdown().await;
}

/// The upstream proxy address comes from the tenant, so it is policy-checked
/// like any destination, and a refusal looks exactly like any other failure.
#[tokio::test]
async fn upstream_proxy_address_is_policy_checked_and_failures_look_alike() {
    const UNAVAILABLE: &str = "upstream proxy is unavailable";
    // A live listener on a policy-blocked address: it must never be dialed.
    let internal = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_port = internal.local_addr().unwrap().port();
    // The same port number closed, on an address the policy allows.
    let dead = {
        let l = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
        l.local_addr().unwrap().port()
    };

    for scheme in ["http", "socks5", "socks5h"] {
        let mut bodies = Vec::new();
        for (host, port) in [
            ("127.0.0.1", internal_port), // blocked by policy, listener alive
            ("127.0.0.1", dead),          // blocked by policy, port closed
            ("localhost", internal_port), // name resolving to loopback
            ("127.0.0.2", dead),          // allowed by policy, port closed
            ("[::1]", dead),              // blocked IPv6 literal
            ("169.254.169.254", 80),      // metadata address
        ] {
            let policy = if host == "127.0.0.2" {
                allow_proxy_only()
            } else {
                EgressPolicy::default()
            };
            let fwd = start(
                Some(route(format!("{scheme}://{host}:{port}"), None, None)),
                policy,
            )
            .await;
            let response = exchange(
                &fwd,
                b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: 93.184.216.34:443\r\n\r\n",
            )
            .await;
            assert_eq!(status_of(&response), 502, "{scheme} {host}: {response}");
            assert!(
                response.contains(UNAVAILABLE),
                "{scheme} {host}: {response}"
            );
            bodies.push(response);
            fwd.shutdown().await;
        }
        assert!(
            bodies.windows(2).all(|w| w[0] == w[1]),
            "{scheme}: refused, closed and unreachable upstreams must answer identically"
        );
    }
    // none of the blocked attempts reached the live internal listener
    assert!(
        timeout(Duration::from_millis(200), internal.accept())
            .await
            .is_err(),
        "a policy-blocked upstream proxy was dialed"
    );
}

/// An operator who runs an internal proxy opts in through `allow_cidrs`.
#[tokio::test]
async fn upstream_proxy_on_an_allowed_private_address_still_works() {
    let proxy = ConnectProxy::start(ConnectOpts::default()).await;
    let fwd = start(
        Some(route(proxy.url("http"), None, None)),
        allow_proxy_only(),
    )
    .await;
    let (status, _) = connect_via(&fwd, "site.test:443").await;
    assert_eq!(status, 200);
    assert_eq!(proxy.seen.lock().unwrap().len(), 1);
    fwd.shutdown().await;
}

// ---------------------------------------------------------------- HTTPS upstream

fn tls_material() -> (String, std::sync::Arc<rustls::ServerConfig>) {
    let key = rcgen::generate_simple_self_signed(vec!["127.0.0.2".to_owned()]).unwrap();
    let pem = key.cert.pem();
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.signing_key.serialize_der().into()),
        )
        .unwrap();
    (pem, std::sync::Arc::new(cfg))
}

#[tokio::test]
async fn https_upstream_uses_tls_and_trusts_only_configured_roots() {
    let (pem, server_cfg) = tls_material();
    let proxy = ConnectProxy::start(ConnectOpts {
        tls: Some(server_cfg),
        expect_auth: Some(basic("tls-user", "tls-pass")),
        ..ConnectOpts::default()
    })
    .await;
    let r = route(proxy.url("https"), Some("tls-user"), Some("tls-pass"));

    let trusting = Forwarder::start_with(
        Some(r.clone()),
        "k".into(),
        1,
        allow_proxy_only(),
        ForwarderOptions {
            extra_root_pem: Some(pem),
            ..ForwarderOptions::default()
        },
    )
    .await
    .unwrap();
    let (status, mut tunnel) = connect_via(&trusting, "site.test:443").await;
    assert_eq!(status, 200);
    echo_roundtrip(&mut tunnel, b"over tls").await;
    assert_eq!(proxy.seen.lock().unwrap().len(), 1);
    trusting.shutdown().await;

    // without the private root the handshake must fail closed
    let strict = start(Some(r), allow_proxy_only()).await;
    let (status, _) = connect_via(&strict, "site.test:443").await;
    assert_eq!(status, 502);
    assert_eq!(
        proxy.seen.lock().unwrap().len(),
        1,
        "no CONNECT may be sent over an untrusted channel"
    );
    strict.shutdown().await;
}

// ---------------------------------------------------------------- SOCKS5 upstream

#[tokio::test]
async fn socks5_with_credentials_resolves_locally_and_sends_the_address() {
    let proxy = SocksProxy::start(SocksOpts {
        require_auth: Some(("sock-sess-key-3".into(), "sock-pass".into())),
        ..SocksOpts::default()
    })
    .await;
    let r = route(
        proxy.url("socks5"),
        Some("sock-{session}-{generation}"),
        Some("sock-pass"),
    );
    let fwd = start(Some(r), allow_proxy_only()).await;

    let (status, mut tunnel) = connect_via(&fwd, "93.184.216.34:443").await;
    assert_eq!(status, 200);
    echo_roundtrip(&mut tunnel, b"via socks").await;
    drop(tunnel);

    let (status, mut tunnel) = connect_via(&fwd, "[2606:4700:4700::1111]:853").await;
    assert_eq!(status, 200);
    echo_roundtrip(&mut tunnel, b"v6").await;

    let seen = proxy.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].methods, vec![0, 2]);
    assert_eq!(
        seen[0].creds,
        Some(("sock-sess-key-3".to_owned(), "sock-pass".to_owned()))
    );
    assert_eq!(
        (seen[0].atyp, seen[0].host.as_str(), seen[0].port),
        (1, "93.184.216.34", 443)
    );
    assert_eq!(
        (seen[1].atyp, seen[1].host.as_str(), seen[1].port),
        (4, "2606:4700:4700::1111", 853)
    );

    // local DNS: names that resolve to private addresses are refused before any SOCKS traffic
    let (status, _) = connect_via(&fwd, "localhost:80").await;
    assert_eq!(status, 403);
    let (status, _) = connect_via(&fwd, "10.0.0.5:80").await;
    assert_eq!(status, 403);
    assert_eq!(proxy.seen.lock().unwrap().len(), 2);
    fwd.shutdown().await;
}

#[tokio::test]
async fn socks5_without_credentials_offers_only_no_auth() {
    let proxy = SocksProxy::start(SocksOpts::default()).await;
    let fwd = start(
        Some(route(proxy.url("socks5"), None, None)),
        allow_proxy_only(),
    )
    .await;
    let (status, _) = connect_via(&fwd, "93.184.216.34:80").await;
    assert_eq!(status, 200);
    assert_eq!(proxy.seen.lock().unwrap()[0].methods, vec![0]);
    assert!(proxy.seen.lock().unwrap()[0].creds.is_none());
    fwd.shutdown().await;
}

#[tokio::test]
async fn socks5h_sends_hostnames_and_checks_only_literals() {
    let proxy = SocksProxy::start(SocksOpts {
        origin: Origin::Http,
        ..SocksOpts::default()
    })
    .await;
    let fwd = start(
        Some(route(proxy.url("socks5h"), None, None)),
        allow_proxy_only(),
    )
    .await;

    let (status, mut tunnel) = connect_via(&fwd, "Remote.Example.test:8443").await;
    assert_eq!(status, 200);
    tunnel.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut out = String::new();
    timeout(STEP, tunnel.read_to_string(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert!(out.ends_with("hello-world"));
    {
        let seen = proxy.seen.lock().unwrap().clone();
        assert_eq!(
            (seen[0].atyp, seen[0].host.as_str(), seen[0].port),
            (3, "remote.example.test", 8443)
        );
    }
    for target in ["10.0.0.5:80", "localhost:80", "[::1]:80"] {
        let (status, _) = connect_via(&fwd, target).await;
        assert_eq!(status, 403, "{target}");
    }
    assert_eq!(proxy.seen.lock().unwrap().len(), 1);
    fwd.shutdown().await;
}

#[tokio::test]
async fn socks5_failures_map_to_bad_gateway() {
    let refuses = SocksProxy::start(SocksOpts {
        reply: 5,
        ..SocksOpts::default()
    })
    .await;
    let fwd = start(
        Some(route(refuses.url("socks5"), None, None)),
        allow_proxy_only(),
    )
    .await;
    let response = exchange(&fwd, b"CONNECT 93.184.216.34:80 HTTP/1.1\r\n\r\n").await;
    assert_eq!(status_of(&response), 502);
    assert!(response.contains("connection refused"));
    fwd.shutdown().await;

    let strict = SocksProxy::start(SocksOpts {
        require_auth: Some(("right".into(), "right".into())),
        ..SocksOpts::default()
    })
    .await;
    let fwd = start(
        Some(route(
            strict.url("socks5"),
            Some("wrong"),
            Some("synthetic-secret"),
        )),
        allow_proxy_only(),
    )
    .await;
    let response = exchange(&fwd, b"CONNECT 93.184.216.34:80 HTTP/1.1\r\n\r\n").await;
    assert_eq!(status_of(&response), 502);
    assert!(response.contains("rejected the credentials"));
    assert!(!response.contains("synthetic-secret"));
    fwd.shutdown().await;

    // the proxy demands auth but none is configured
    let fwd = start(
        Some(route(strict.url("socks5"), None, None)),
        allow_proxy_only(),
    )
    .await;
    let (status, _) = connect_via(&fwd, "93.184.216.34:80").await;
    assert_eq!(status, 502);
    fwd.shutdown().await;
}

// ---------------------------------------------------------------- bounds and hygiene

#[tokio::test]
async fn malformed_and_unsupported_requests_are_refused() {
    let fwd = start(None, allow_loopback()).await;
    for (raw, want) in [
        (&b"GARBAGE\r\n\r\n"[..], 400),
        (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", 400),
        (
            b"GET https://example.test/ HTTP/1.1\r\nHost: x\r\n\r\n",
            400,
        ),
        (b"CONNECT example.test HTTP/1.1\r\n\r\n", 400),
        (b"CONNECT user@example.test:443 HTTP/1.1\r\n\r\n", 400),
        (b"GET http://exa mple.test/ HTTP/1.1\r\n\r\n", 400),
        (b"GET http://example.test/ HTTP/2\r\n\r\n", 400),
    ] {
        let response = exchange(&fwd, raw).await;
        assert_eq!(
            status_of(&response),
            want,
            "{:?} -> {response}",
            String::from_utf8_lossy(raw)
        );
    }
    let mut huge = b"GET http://example.test/ HTTP/1.1\r\nX-Pad: ".to_vec();
    huge.extend(std::iter::repeat_n(b'a', 20_000));
    huge.extend_from_slice(b"\r\n\r\n");
    assert_eq!(status_of(&exchange(&fwd, &huge).await), 431);
    assert_eq!(fwd.stats().connections, 0);
    fwd.shutdown().await;
}

#[tokio::test]
async fn silent_clients_time_out() {
    let options = ForwarderOptions {
        header_timeout: Duration::from_millis(200),
        ..ForwarderOptions::default()
    };
    let fwd = Forwarder::start_with(None, "k".into(), 1, EgressPolicy::default(), options)
        .await
        .unwrap();
    let mut s = TcpStream::connect(fwd.local_addr()).await.unwrap();
    let mut out = String::new();
    timeout(STEP, s.read_to_string(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status_of(&out), 408);
    fwd.shutdown().await;
}

#[tokio::test]
async fn idle_tunnels_are_closed() {
    let origin = OriginServer::start(Origin::Echo).await;
    let options = ForwarderOptions {
        idle_timeout: Duration::from_millis(300),
        ..ForwarderOptions::default()
    };
    let fwd = Forwarder::start_with(None, "k".into(), 1, allow_loopback(), options)
        .await
        .unwrap();
    let (status, mut tunnel) = connect_via(&fwd, &origin.addr.to_string()).await;
    assert_eq!(status, 200);
    echo_roundtrip(&mut tunnel, b"ping").await;
    let mut rest = Vec::new();
    let closed = timeout(STEP, tunnel.read_to_end(&mut rest)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "tunnel should close after the idle limit"
    );
    fwd.shutdown().await;
}

#[tokio::test]
async fn connection_limit_answers_503() {
    let origin = OriginServer::start(Origin::Echo).await;
    let options = ForwarderOptions {
        max_connections: 1,
        ..ForwarderOptions::default()
    };
    let fwd = Forwarder::start_with(None, "k".into(), 1, allow_loopback(), options)
        .await
        .unwrap();
    let (status, mut first) = connect_via(&fwd, &origin.addr.to_string()).await;
    assert_eq!(status, 200);
    echo_roundtrip(&mut first, b"held").await;

    let mut second = TcpStream::connect(fwd.local_addr()).await.unwrap();
    let (status, _) = read_status(&mut second).await;
    assert_eq!(status, 503);
    assert_eq!(fwd.stats().refused, 1);

    drop(first);
    drop(second);
    let mut recovered = false;
    for _ in 0..50 {
        let (status, _) = connect_via(&fwd, &origin.addr.to_string()).await;
        if status == 200 {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(recovered, "capacity must free up after tunnels close");
    fwd.shutdown().await;
}

#[tokio::test]
async fn shutdown_closes_tunnels_and_the_listener() {
    let origin = OriginServer::start(Origin::Echo).await;
    let fwd = start(None, allow_loopback()).await;
    let addr = fwd.local_addr();
    let (status, mut tunnel) = connect_via(&fwd, &origin.addr.to_string()).await;
    assert_eq!(status, 200);
    echo_roundtrip(&mut tunnel, b"alive").await;
    fwd.shutdown().await;

    let mut rest = Vec::new();
    let end = timeout(STEP, tunnel.read_to_end(&mut rest)).await.unwrap();
    assert!(matches!(end, Ok(0) | Err(_)));
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "listener must be gone"
    );
}

#[tokio::test]
async fn dropping_the_forwarder_stops_it() {
    let fwd = start(None, EgressPolicy::default()).await;
    let addr = fwd.local_addr();
    drop(fwd);
    let mut gone = false;
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_err() {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(gone);
}

#[tokio::test]
async fn invalid_configuration_is_rejected_at_start() {
    let bad_cidr = EgressPolicy {
        block_private: true,
        allow_cidrs: vec!["not-a-cidr".into()],
    };
    assert!(matches!(
        Forwarder::start(None, "k".into(), 1, bad_cidr).await,
        Err(Error::InvalidRequest(_))
    ));
    for r in [
        route("ftp://proxy.test:21".into(), None, None),
        route("http://u:p@proxy.test:8080".into(), None, None),
        route(
            "socks5://proxy.test:1080".into(),
            None,
            Some("password-without-user"),
        ),
        route(
            "socks5://proxy.test:1080".into(),
            Some(&"u".repeat(300)),
            None,
        ),
        route("nonsense".into(), None, None),
    ] {
        assert!(matches!(
            Forwarder::start(Some(r), "k".into(), 1, EgressPolicy::default()).await,
            Err(Error::InvalidRequest(_))
        ));
    }
    let zero = ForwarderOptions {
        max_connections: 0,
        ..ForwarderOptions::default()
    };
    assert!(
        Forwarder::start_with(None, "k".into(), 1, EgressPolicy::default(), zero)
            .await
            .is_err()
    );
    let bad_pem = ForwarderOptions {
        extra_root_pem: Some("not pem".into()),
        ..ForwarderOptions::default()
    };
    let r = route("https://proxy.test:8443".into(), None, None);
    assert!(
        Forwarder::start_with(Some(r), "k".into(), 1, EgressPolicy::default(), bad_pem)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn debug_output_never_contains_credentials() {
    let proxy = ConnectProxy::start(ConnectOpts::default()).await;
    let r = route(
        proxy.url("http"),
        Some("synthetic-user"),
        Some("synthetic-pass"),
    );
    assert!(!format!("{r:?}").contains("synthetic-pass"));
    let fwd = start(Some(r), allow_proxy_only()).await;
    let text = format!("{fwd:?}");
    assert!(!text.contains("synthetic"));
    fwd.shutdown().await;
}
