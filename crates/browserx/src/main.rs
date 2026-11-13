//! The `browserx` command-line program.

mod cli;
mod client;
mod doctor;
mod keys;

use std::io::Write;

use anyhow::{Context, Result};
use browserx_server::Config;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command, ConfigCommand, KeysCommand, LogFormat, SnapshotKeyCommand};

fn init_logging(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    match format {
        LogFormat::Text => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
}

fn check_config(path: &std::path::Path) -> Result<()> {
    let cfg = Config::load(path)?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "configuration is valid: {}", path.display())?;
    writeln!(out, "  api listener:      {}", cfg.server.listen)?;
    writeln!(out, "  ops listener:      {}", cfg.server.ops_listen)?;
    writeln!(out, "  public base url:   {}", cfg.server.public_base_url)?;
    writeln!(out, "  api keys:          {}", cfg.auth.api_keys.len())?;
    writeln!(out, "  max browsers:      {}", cfg.pool.max_browsers)?;
    writeln!(
        out,
        "  launch profiles:   {}",
        cfg.runtime
            .launch_profiles
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    writeln!(
        out,
        "  state directory:   {}",
        cfg.storage.state_dir.display()
    )?;
    for (name, addr) in [
        ("listen", cfg.listen_addr()?),
        ("ops_listen", cfg.ops_addr()?),
    ] {
        if !addr.ip().is_loopback() {
            writeln!(
                out,
                "warning: {name} {addr} is not a loopback address; put TLS and access control in front of it"
            )?;
        }
    }
    if cfg.server.public_base_url.starts_with("http://")
        && !cfg.server.public_base_url.contains("127.0.0.1")
        && !cfg.server.public_base_url.contains("localhost")
    {
        writeln!(
            out,
            "warning: public_base_url is plaintext http/ws; terminate TLS in front of the server for remote clients"
        )?;
    }
    if !cfg.storage.snapshot_key_file.exists() {
        writeln!(
            out,
            "warning: snapshot key file {} does not exist; create it with `browserx snapshot-key new {}`",
            cfg.storage.snapshot_key_file.display(),
            cfg.storage.snapshot_key_file.display()
        )?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { config } => {
            init_logging(cli.log_format);
            let cfg = Config::load(&config)?;
            browserx_server::run(cfg, browserx_server::shutdown_signal())
                .await
                .context("server stopped with an error")
        }
        Command::Config {
            command: ConfigCommand::Check { path },
        } => check_config(&path),
        Command::Keys {
            command: KeysCommand::New { name, max_sessions },
        } => keys::new_api_key(&mut std::io::stdout().lock(), &name, max_sessions),
        Command::SnapshotKey {
            command: SnapshotKeyCommand::New { path },
        } => {
            keys::new_snapshot_key(&path)?;
            println!(
                "created snapshot key {} (mode 0600). Back it up: snapshots cannot be opened without it.",
                path.display()
            );
            Ok(())
        }
        Command::Doctor { config } => {
            init_logging(cli.log_format);
            doctor::run(config.as_deref()).await
        }
        Command::Session { remote, command } => client::run(&remote, command).await,
    }
}
