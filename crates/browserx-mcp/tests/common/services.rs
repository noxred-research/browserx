#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Throwaway service containers for integration tests (podman).
//!
//! Tests that need a real PostgreSQL, MariaDB, object store or other service start it here.
//! They run only when `BROWSERX_TEST_SERVICES=1` is set (the CI lane sets it); otherwise they
//! print a `SKIP:` note and pass, like the real-browser tests. With `BROWSERX_REQUIRE_SERVICES=1`
//! a missing podman or a container that does not start is a failure, never a skip.
//!
//! Every container has a unique name, publishes its ports on loopback only, uses a tmpfs for
//! data where the image allows it and is force-removed when the [`Service`] is dropped, also
//! when the test panics.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A running container.
pub struct Service {
    name: String,
    /// Host port of each requested container port, in request order.
    pub ports: Vec<u16>,
}

/// What to run.
pub struct Spec<'a> {
    /// Image reference.
    pub image: &'a str,
    /// Container ports to publish on `127.0.0.1`.
    pub ports: &'a [u16],
    /// `KEY=value` environment.
    pub env: &'a [&'a str],
    /// Mount a tmpfs at these paths.
    pub tmpfs: &'a [&'a str],
    /// Command and arguments after the image.
    pub command: &'a [&'a str],
    /// How long to wait for the service to answer.
    pub ready_within: Duration,
}

fn podman(args: &[&str]) -> Option<String> {
    let out = Command::new("podman")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Whether service tests should run; prints the skip note when not.
pub fn enabled(what: &str) -> bool {
    if std::env::var("BROWSERX_TEST_SERVICES").as_deref() == Ok("1") {
        return true;
    }
    eprintln!(
        "SKIP: {what} needs a service container (set BROWSERX_TEST_SERVICES=1 and have podman)"
    );
    false
}

fn require() -> bool {
    std::env::var("BROWSERX_REQUIRE_SERVICES").as_deref() == Ok("1")
}

impl Service {
    /// Starts the container and waits until `ready(&host_ports)` returns true. Returns `None`
    /// (after a `SKIP:` note) when podman is missing and services are not required.
    pub async fn start<F, Fut>(spec: &Spec<'_>, ready: F) -> Option<Self>
    where
        F: Fn(Vec<u16>) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        if podman(&["--version"]).is_none() {
            assert!(!require(), "podman is required but not available");
            eprintln!("SKIP: podman is not available");
            return None;
        }
        let name = format!(
            "bx-test-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        );
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--rm".into(),
            "--name".into(),
            name.clone(),
            "--label".into(),
            "bx-test=1".into(),
        ];
        for port in spec.ports {
            args.push("-p".into());
            args.push(format!("127.0.0.1::{port}"));
        }
        for env in spec.env {
            args.push("-e".into());
            args.push((*env).into());
        }
        for path in spec.tmpfs {
            args.push("--tmpfs".into());
            args.push((*path).into());
        }
        args.push(spec.image.into());
        args.extend(spec.command.iter().map(|s| (*s).to_owned()));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let Some(_) = podman(&refs) else {
            assert!(!require(), "container {} did not start", spec.image);
            eprintln!("SKIP: container {} did not start", spec.image);
            return None;
        };
        let mut service = Self {
            name,
            ports: Vec::new(),
        };
        let mut ports = Vec::new();
        for port in spec.ports {
            let mapped = podman(&["port", &service.name, &format!("{port}/tcp")])
                .and_then(|text| text.lines().next().map(str::to_owned))
                .and_then(|line| line.rsplit(':').next().map(str::to_owned))
                .and_then(|p| p.parse::<u16>().ok())
                .expect("a published port");
            ports.push(mapped);
        }
        service.ports = ports;
        let deadline = Instant::now() + spec.ready_within;
        loop {
            if ready(service.ports.clone()).await {
                return Some(service);
            }
            assert!(
                Instant::now() < deadline,
                "{} did not become ready within {:?}; logs:\n{}",
                spec.image,
                spec.ready_within,
                podman(&["logs", "--tail", "30", &service.name]).unwrap_or_default()
            );
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// The container's name (unique).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Runs a command inside the container and returns its stdout.
    pub fn exec(&self, command: &[&str]) -> Option<String> {
        let mut args = vec!["exec", &self.name];
        args.extend_from_slice(command);
        podman(&args)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = Command::new("podman")
            .args(["rm", "-f", "-t", "0", &self.name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// True once something accepts TCP connections on `127.0.0.1:port`.
pub async fn tcp_open(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}
