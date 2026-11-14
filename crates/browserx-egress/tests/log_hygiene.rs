//! Upstream proxy credentials never reach logs or the browser's proxy flag, on success and on
//! every failure path. One test per binary: the capturing subscriber is global.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use browserx_core::{ProxyRoute, Secret};
use browserx_egress::{EgressPolicy, Forwarder};
use common::*;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

const USER: &str = "canary-user-{session}";
const PASSWORD: &str = "canary-password-0123";

fn policy() -> EgressPolicy {
    EgressPolicy {
        block_private: true,
        allow_cidrs: vec!["127.0.0.2/32".into()],
    }
}

#[tokio::test]
async fn upstream_credentials_never_reach_logs_or_flags() {
    let logs = Capture::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish(),
    )
    .unwrap();

    let route = |url: String| ProxyRoute {
        url,
        username: Some(USER.into()),
        password: Some(Secret::new(PASSWORD)),
    };
    let rendered = format!("canary-user-sess-key:{PASSWORD}");
    let mut flags = Vec::new();

    // Success, then the upstream refusing the credentials, then no upstream at all.
    let ok = ConnectProxy::start(ConnectOpts {
        expect_auth: Some(format!("Basic {}", STANDARD.encode(&rendered))),
        ..ConnectOpts::default()
    })
    .await;
    let fwd = Forwarder::start(Some(route(ok.url("http"))), "sess-key".into(), 1, policy())
        .await
        .unwrap();
    flags.push(fwd.proxy_server());
    let (status, _) = connect_via(&fwd, "site.test:443").await;
    assert_eq!(status, 200);
    fwd.shutdown().await;

    let strict = ConnectProxy::start(ConnectOpts {
        expect_auth: Some("Basic bm90LXRoZS1zYW1l".into()),
        ..ConnectOpts::default()
    })
    .await;
    let fwd = Forwarder::start(
        Some(route(strict.url("http"))),
        "sess-key".into(),
        1,
        policy(),
    )
    .await
    .unwrap();
    flags.push(fwd.proxy_server());
    let (status, _) = connect_via(&fwd, "site.test:443").await;
    assert_ne!(status, 200);
    let (status, _) = connect_via(&fwd, "10.0.0.5:80").await;
    assert_ne!(status, 200);
    fwd.shutdown().await;

    let fwd = Forwarder::start(
        Some(route("http://127.0.0.2:1".into())),
        "sess-key".into(),
        1,
        policy(),
    )
    .await
    .unwrap();
    flags.push(fwd.proxy_server());
    let (status, _) = connect_via(&fwd, "site.test:443").await;
    assert_ne!(status, 200);
    fwd.shutdown().await;

    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(!logged.is_empty(), "the capture saw the forwarder");
    for secret in [
        PASSWORD,
        "canary-user",
        rendered.as_str(),
        STANDARD.encode(&rendered).as_str(),
    ] {
        assert!(!logged.contains(secret), "credential material in the logs");
        for flag in &flags {
            assert!(
                !flag.contains(secret),
                "credential material in a flag: {flag}"
            );
        }
    }
}
