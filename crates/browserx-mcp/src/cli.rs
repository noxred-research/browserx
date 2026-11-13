//! The `browserx mcp` subcommand: serve, validate a configuration, verify an audit log,
//! generate an HTTP token.

use std::future::Future;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, Subcommand};
use rand::Rng as _;
use sha2::{Digest as _, Sha256};
use tokio::io::BufReader;
use tokio_util::sync::CancellationToken;

use crate::config::{Capability, Config};
use crate::ctx::Ctx;
use crate::error::McpError;
use crate::http::{HttpOptions, parse_digest};
use crate::server::Server;
use crate::tools::catalog;
use crate::{audit, http, stdio};

/// `browserx mcp` arguments.
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct McpArgs {
    /// MCP configuration file (TOML).
    #[arg(long, short, env = "BROWSERX_MCP_CONFIG")]
    pub config: Option<PathBuf>,
    /// Serve streamable HTTP instead of stdio. Without a value, `mcp.http.listen` is used.
    #[arg(long, value_name = "ADDR", num_args = 0..=1, default_missing_value = "")]
    pub http: Option<String>,
    /// With `--http`: also serve stdio.
    #[arg(long, requires = "http")]
    pub stdio: bool,
    /// Utilities.
    #[command(subcommand)]
    pub command: Option<McpCommand>,
}

/// `browserx mcp` utilities.
#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Validate a configuration file and list the tools it enables.
    Check {
        /// MCP configuration file (TOML).
        path: PathBuf,
    },
    /// Audit log commands.
    Audit {
        /// What to do with the log.
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Bearer token for the HTTP transport.
    Token {
        /// What to do.
        #[command(subcommand)]
        command: TokenCommand,
    },
}

/// `browserx mcp audit` commands.
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Recompute the hash chain of an audit log; fails when an entry was edited, removed or moved.
    Verify {
        /// Audit log (JSONL).
        path: PathBuf,
    },
}

/// `browserx mcp token` commands.
#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Generate a bearer token (shown once) and the configuration line that authorizes it.
    New,
}

fn print(text: &str) -> Result<(), McpError> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{text}").map_err(|e| McpError::io("cannot write to stdout", e))
}

fn check(path: &std::path::Path) -> Result<(), McpError> {
    let config = Config::load(path)?;
    let routes = config
        .proxy_routes
        .keys()
        .map(|n| (n.clone(), ()))
        .collect();
    let tools = catalog::enabled(&config, config.ai.is_some(), &routes);
    print(&format!("configuration is valid: {}", path.display()))?;
    print(&format!(
        "  capabilities:  {}",
        if config.mcp.capabilities.is_empty() {
            "none (read-only monitoring)".to_owned()
        } else {
            config
                .mcp
                .capabilities
                .iter()
                .map(|c| c.name())
                .collect::<Vec<_>>()
                .join(", ")
        }
    ))?;
    print(&format!(
        "  tools:         {} ({})",
        tools.len(),
        tools.iter().map(|t| t.name).collect::<Vec<_>>().join(", ")
    ))?;
    if config.has(Capability::Browse) {
        print(&format!(
            "  browse scope:  {}",
            if config.browse.allowed_origins.is_empty() {
                "any http(s) origin (require_scope = false)".to_owned()
            } else {
                config.origins()?.join(", ")
            }
        ))?;
    }
    print(&format!("  audit log:     {}", config.audit.path.display()))?;
    print(&format!(
        "  model:         {}",
        if config.ai.is_some() {
            "configured"
        } else {
            "not configured (advisory tools are not listed)"
        }
    ))?;
    if config.mcp.http.token_sha256.is_none() {
        print(
            "  http:          no token_sha256: `--http` will refuse to start (see `browserx mcp token new`)",
        )?;
    }
    if !config.server.api_key_file.exists() {
        print(&format!(
            "warning: {} does not exist yet",
            config.server.api_key_file.display()
        ))?;
    }
    Ok(())
}

fn verify(path: &std::path::Path) -> Result<(), McpError> {
    let report = audit::verify(path)
        .map_err(|e| McpError::io(format!("cannot read {}", path.display()), e))?;
    match report.broken {
        None => print(&format!(
            "audit log is intact: {} entries, last hash {}\nStore the last hash outside this host: cutting entries off the end leaves a valid chain.",
            report.entries, report.last_hash
        )),
        Some((line, reason)) => Err(McpError::Audit(format!(
            "the chain breaks at line {line} after {} intact entries: {reason}",
            report.entries
        ))),
    }
}

fn new_token() -> Result<(), McpError> {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = format!("bxm_{}", hex::encode(bytes));
    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    print("MCP HTTP bearer token (shown once; give it to the MCP client):")?;
    print(&token)?;
    print("\nAdd this to the MCP configuration (it contains only the token's SHA-256):")?;
    print("[mcp.http]")?;
    print(&format!("token_sha256 = \"{digest}\""))
}

/// Runs `browserx mcp`. `shutdown` resolves on a stop signal.
///
/// # Errors
/// When the configuration is invalid, a transport fails or a utility reports a problem.
pub async fn run(
    args: McpArgs,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), McpError> {
    match args.command {
        Some(McpCommand::Check { path }) => return check(&path),
        Some(McpCommand::Audit {
            command: AuditCommand::Verify { path },
        }) => return verify(&path),
        Some(McpCommand::Token {
            command: TokenCommand::New,
        }) => return new_token(),
        None => {}
    }
    let path = args.config.ok_or_else(|| {
        McpError::Config("pass --config <file> (or set BROWSERX_MCP_CONFIG)".into())
    })?;
    let config = Config::load(&path)?;
    let http_addr = match &args.http {
        None => None,
        Some(addr) if addr.is_empty() => Some(
            config
                .mcp
                .http
                .listen
                .parse::<SocketAddr>()
                .map_err(|e| McpError::Config(format!("mcp.http.listen: {e}")))?,
        ),
        Some(addr) => Some(
            addr.parse::<SocketAddr>()
                .map_err(|e| McpError::Config(format!("--http {addr}: {e}")))?,
        ),
    };
    let options = match http_addr {
        None => None,
        Some(addr) => {
            let digest = config.mcp.http.token_sha256.as_deref().ok_or_else(|| {
                McpError::Config(
                    "mcp.http.token_sha256 is required for the HTTP transport; generate one with `browserx mcp token new`".into(),
                )
            })?;
            if !addr.ip().is_loopback() {
                tracing::warn!(%addr, "the MCP HTTP transport is listening on a non-loopback address: terminate TLS and restrict access in front of it");
            }
            Some((
                addr,
                HttpOptions {
                    path: config.mcp.http.path.clone(),
                    token_sha256: parse_digest(digest)
                        .map_err(|e| McpError::Config(format!("mcp.http.token_sha256: {e}")))?,
                    allowed_origins: config
                        .mcp
                        .http
                        .allowed_origins
                        .iter()
                        .map(|o| crate::config::normalize_origin(o))
                        .collect::<Result<_, _>>()?,
                    loopback_bind: addr.ip().is_loopback(),
                    max_body_bytes: config.mcp.http.max_body_bytes,
                },
            ))
        }
    };
    let serve_stdio = options.is_none() || args.stdio;

    let ctx = Ctx::build(config)?;
    ctx.start();
    let server = Arc::new(Server::new(Arc::clone(&ctx)));
    let stop = CancellationToken::new();

    let mut tasks = tokio::task::JoinSet::new();
    if let Some((addr, options)) = options {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| McpError::Transport(format!("cannot bind {addr}: {e}")))?;
        tracing::info!(%addr, "MCP streamable HTTP is listening");
        let app = http::router(Arc::clone(&server), options);
        let cancel = stop.clone();
        tasks.spawn(async move {
            http::serve(listener, app, cancel)
                .await
                .map_err(|e| McpError::Transport(format!("http: {e}")))
        });
    }
    if serve_stdio {
        let server = Arc::clone(&server);
        tasks.spawn(async move {
            stdio::serve(
                BufReader::new(tokio::io::stdin()),
                tokio::io::stdout(),
                server,
            )
            .await
            .map_err(|e| McpError::Transport(format!("stdio: {e}")))
        });
    }

    // Stdio ending (stdin closed) or a transport failing stops everything, like a signal does.
    let outcome: Result<(), McpError> = tokio::select! {
        () = shutdown => Ok(()),
        finished = tasks.join_next() => match finished {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(McpError::Transport(format!("a transport task failed: {error}"))),
            None => Ok(()),
        },
    };
    stop.cancel();
    ctx.shutdown().await;
    tasks.abort_all();
    outcome
}
