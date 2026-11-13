//! `browserx doctor`: prove this machine can run browsers for BrowserX.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use browserx_core::{BrowserId, BrowserRuntime, LaunchRequest};
use browserx_runtime::{ChromiumRuntime, RuntimeConfig, discover_chromium};
use browserx_server::Config;

struct Report {
    failures: usize,
}

impl Report {
    fn ok(&self, what: &str, detail: impl std::fmt::Display) {
        println!("[ ok ] {what}: {detail}");
    }
    fn warn(&self, what: &str, detail: impl std::fmt::Display) {
        println!("[warn] {what}: {detail}");
    }
    fn fail(&mut self, what: &str, detail: impl std::fmt::Display) {
        self.failures += 1;
        println!("[FAIL] {what}: {detail}");
    }
}

/// Runs the checks; fails when any of them failed.
pub async fn run(config: Option<&Path>) -> Result<()> {
    let mut report = Report { failures: 0 };
    let (mut runtime_cfg, storage) = match config {
        Some(path) => match Config::load(path) {
            Ok(cfg) => {
                report.ok("configuration", path.display());
                (cfg.runtime.clone(), Some(cfg.storage))
            }
            Err(e) => {
                report.fail("configuration", e);
                bail!("doctor found problems");
            }
        },
        None => (RuntimeConfig::default().validated()?, None),
    };

    if let Some(storage) = &storage {
        match std::fs::create_dir_all(&storage.state_dir)
            .and_then(|()| tempfile_probe(&storage.state_dir))
        {
            Ok(()) => report.ok("state directory writable", storage.state_dir.display()),
            Err(e) => report.fail(
                "state directory",
                format!("{}: {e}", storage.state_dir.display()),
            ),
        }
        if storage.snapshot_key_file.is_file() {
            match browserx_store::Sealer::from_key_file(&storage.snapshot_key_file) {
                Ok(s) => report.ok("snapshot key", format!("key id {}", s.key_id())),
                Err(e) => report.fail("snapshot key", e),
            }
        } else {
            report.warn(
                "snapshot key",
                format!(
                    "{} is missing; create it with `browserx snapshot-key new {}`",
                    storage.snapshot_key_file.display(),
                    storage.snapshot_key_file.display()
                ),
            );
        }
        runtime_cfg.temp_root = storage.temp_dir();
    }
    if let Err(e) = std::fs::create_dir_all(&runtime_cfg.temp_root) {
        report.fail(
            "temporary directory",
            format!("{}: {e}", runtime_cfg.temp_root.display()),
        );
    }

    let default_name = runtime_cfg.default_launch_profile.clone();
    let explicit = runtime_cfg
        .launch_profiles
        .get(&default_name)
        .and_then(|p| p.executable.clone());
    match explicit.clone().or_else(discover_chromium) {
        Some(path) if path.is_file() => report.ok("chromium", path.display()),
        Some(path) => {
            report.fail("chromium", format!("{} does not exist", path.display()));
            bail!("doctor found problems");
        }
        None => {
            report.fail(
                "chromium",
                "not found: install Chromium or set BROWSERX_CHROMIUM_PATH / the launch profile `executable`",
            );
            bail!("doctor found problems");
        }
    }

    let runtime = ChromiumRuntime::new(runtime_cfg)?;
    let started = Instant::now();
    let launched = tokio::time::timeout(
        Duration::from_secs(90),
        runtime.launch(LaunchRequest {
            browser_id: BrowserId::new(),
            launch_profile: None,
            user_data_dir: None,
            proxy_server: None,
            persona_seed: browserx_core::persona_seed(&BrowserId::new().0),
        }),
    )
    .await;
    match launched {
        Ok(Ok(handle)) => {
            report.ok(
                "launch",
                format!(
                    "{} in {} ms",
                    handle.version(),
                    started.elapsed().as_millis()
                ),
            );
            report.ok("devtools endpoint", "answers");
            match handle.health().await {
                browserx_core::RuntimeHealth::Healthy => report.ok("health probe", "healthy"),
                other => report.fail("health probe", format!("{other:?}")),
            }
            match handle.create_context().await {
                Ok(ctx) => match handle.dispose_context(&ctx).await {
                    Ok(()) => report.ok("browser contexts", "create and dispose work"),
                    Err(e) => report.fail("browser contexts", format!("dispose: {e}")),
                },
                Err(e) => report.fail("browser contexts", format!("create: {e}")),
            }
            match handle.shutdown_confirmed().await {
                Ok(()) => report.ok("shutdown", "process exit confirmed"),
                Err(e) => report.fail("shutdown", e),
            }
        }
        Ok(Err(e)) => {
            report.fail("launch", &e);
            if e.to_string().to_ascii_lowercase().contains("sandbox")
                || e.to_string().contains("namespace")
            {
                println!(
                    "       hint: where unprivileged user namespaces are restricted, add \"--no-sandbox\" \
                     (and usually \"--disable-gpu\") to the launch profile `args`, or grant the container \
                     the privileges Chromium's sandbox needs. Only drop the sandbox for trusted content."
                );
            }
        }
        Err(_) => report.fail("launch", "timed out after 90 s"),
    }

    if report.failures > 0 {
        bail!("doctor found {} problem(s)", report.failures);
    }
    println!("all checks passed");
    Ok(())
}

fn tempfile_probe(dir: &Path) -> std::io::Result<()> {
    let probe = dir.join(format!(".doctor-{}", std::process::id()));
    std::fs::write(&probe, b"ok")?;
    std::fs::remove_file(probe)
}
