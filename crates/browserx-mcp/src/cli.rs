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
use crate::crypto::{self, OperatorKeys};
use crate::ctx::Ctx;
use crate::error::McpError;
use crate::http::{HttpOptions, parse_digest};
use crate::server::Server;
use crate::tools::catalog;
use crate::{approvals, audit, grants, http, manifest, stdio};

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
    /// The signed engagement manifest.
    Manifest {
        /// What to do.
        #[command(subcommand)]
        command: ManifestCommand,
    },
    /// Signed scope grants.
    Grant {
        /// What to do.
        #[command(subcommand)]
        command: GrantCommand,
    },
    /// Out-of-band approvals of consequential calls.
    Approvals {
        /// What to do.
        #[command(subcommand)]
        command: ApprovalsCommand,
    },
    /// Operator signing keys.
    OperatorKey {
        /// What to do.
        #[command(subcommand)]
        command: OperatorKeyCommand,
    },
}

/// `browserx mcp manifest` commands.
#[derive(Debug, Subcommand)]
pub enum ManifestCommand {
    /// Check a manifest and its detached signature offline.
    Verify {
        /// The manifest (`engagement.toml`).
        path: PathBuf,
        /// Operator key file.
        #[arg(long)]
        keys: PathBuf,
        /// Signature file; default: the manifest path plus `.sig`.
        #[arg(long)]
        signature: Option<PathBuf>,
    },
    /// Sign a manifest: writes the detached signature next to it.
    Sign {
        /// The manifest (`engagement.toml`).
        path: PathBuf,
        /// Operator key file.
        #[arg(long)]
        keys: PathBuf,
        /// Key id to sign with (needed when the file holds several keys).
        #[arg(long)]
        key_id: Option<String>,
    },
}

/// `browserx mcp grant` commands.
#[derive(Debug, Subcommand)]
pub enum GrantCommand {
    /// Check a grant and its detached signature offline.
    Verify {
        /// The grant (`grant.toml`).
        path: PathBuf,
        /// Operator key file.
        #[arg(long)]
        keys: PathBuf,
        /// Signature file; default: the grant path plus `.sig`.
        #[arg(long)]
        signature: Option<PathBuf>,
    },
    /// Sign a grant, or a proposal after review: writes the detached signature next to it.
    Sign {
        /// The grant or proposal file.
        path: PathBuf,
        /// Operator key file.
        #[arg(long)]
        keys: PathBuf,
        /// Key id to sign with (needed when the file holds several keys).
        #[arg(long)]
        key_id: Option<String>,
    },
}

/// `browserx mcp approvals` commands.
#[derive(Debug, Subcommand)]
pub enum ApprovalsCommand {
    /// List pending approval requests.
    List {
        /// MCP configuration file (TOML).
        #[arg(long, short, env = "BROWSERX_MCP_CONFIG")]
        config: PathBuf,
    },
    /// Approve one pending request: signs its record with the operator key.
    Approve {
        /// The approval id (`apr_...`).
        id: String,
        /// MCP configuration file (TOML).
        #[arg(long, short, env = "BROWSERX_MCP_CONFIG")]
        config: PathBuf,
        /// Key id to sign with (needed when the file holds several keys).
        #[arg(long)]
        key_id: Option<String>,
    },
}

/// `browserx mcp operator-key` commands.
#[derive(Debug, Subcommand)]
pub enum OperatorKeyCommand {
    /// Print a new operator key line (shown once; append it to the key file, mode 0600).
    New {
        /// Key id.
        key_id: String,
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
        "  safety:        profile {}, rule of two {}",
        serde_json::to_value(config.safety.profile)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
        config.safety.rule_of_two.mode.name()
    ))?;
    let keys = config
        .operator
        .as_ref()
        .map(|operator| OperatorKeys::load(&operator.keys_file))
        .transpose()
        .map_err(|e| McpError::Config(e.to_string()))?;
    if let (Some(section), Some(keys)) = (&config.manifest, &keys) {
        let signature = section
            .signature_file
            .clone()
            .unwrap_or_else(|| manifest::default_signature_path(&section.path));
        let loaded = manifest::Loaded::load(&section.path, &signature, keys)
            .map_err(|e| McpError::Config(e.to_string()))?;
        print(&format!(
            "  manifest:      {} (engagement {}, {})",
            section.path.display(),
            loaded.manifest.id,
            loaded.status(time::OffsetDateTime::now_utc()).name()
        ))?;
    }
    if let (Some(section), Some(keys)) = (&config.grant, &keys) {
        let mut signature = section.path.as_os_str().to_owned();
        signature.push(".sig");
        let signature = section
            .signature_file
            .clone()
            .unwrap_or_else(|| signature.into());
        let loaded = grants::Loaded::load(&section.path, &signature, keys)
            .map_err(|e| McpError::Config(e.to_string()))?;
        print(&format!(
            "  scope grant:   {} ({})",
            section.path.display(),
            if loaded.trusted() {
                "signed"
            } else {
                "NOT signed: the server will refuse to start"
            }
        ))?;
    }
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

fn pick_key(keys: &OperatorKeys, wanted: Option<&str>) -> Result<String, McpError> {
    let ids: Vec<&str> = keys.ids().collect();
    match (wanted, ids.as_slice()) {
        (Some(id), _) => Ok(id.to_owned()),
        (None, [only]) => Ok((*only).to_owned()),
        _ => Err(McpError::Config(format!(
            "the key file holds several keys ({}): pass --key-id",
            ids.join(", ")
        ))),
    }
}

fn load_keys(path: &std::path::Path) -> Result<OperatorKeys, McpError> {
    OperatorKeys::load(path).map_err(|e| McpError::Config(e.to_string()))
}

fn write_signature(path: &std::path::Path, signature: &str) -> Result<(), McpError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o644);
    let mut file = options
        .open(path)
        .map_err(|e| McpError::io(format!("cannot write {}", path.display()), e))?;
    writeln!(file, "{signature}")
        .map_err(|e| McpError::io(format!("cannot write {}", path.display()), e))
}

fn manifest_command(command: ManifestCommand) -> Result<(), McpError> {
    match command {
        ManifestCommand::Verify {
            path,
            keys,
            signature,
        } => {
            let keys = load_keys(&keys)?;
            let signature = signature.unwrap_or_else(|| manifest::default_signature_path(&path));
            let loaded = manifest::Loaded::load(&path, &signature, &keys)
                .map_err(|e| McpError::Config(e.to_string()))?;
            match &loaded.signature {
                manifest::Signature::Valid(key_id) => {
                    let status = loaded.status(time::OffsetDateTime::now_utc());
                    print(&format!(
                        "manifest is valid: engagement {}, operator {}, signed by key {key_id}",
                        loaded.manifest.id, loaded.manifest.operator
                    ))?;
                    print(&format!("  digest:  {}", loaded.digest))?;
                    print(&format!("  impact:  {}", loaded.manifest.impact.name()))?;
                    for (host, mode) in loaded.manifest.scope_summary() {
                        print(&format!("  scope:   {host} ({})", mode.name()))?;
                    }
                    print(&format!("  now:     {}", status.name()))
                }
                manifest::Signature::Missing => Err(McpError::Config(format!(
                    "the manifest has no signature ({} is missing): its tools that change pages stay unavailable",
                    signature.display()
                ))),
                manifest::Signature::Invalid(why) => Err(McpError::Config(format!(
                    "the manifest signature is invalid: {why}"
                ))),
            }
        }
        ManifestCommand::Sign { path, keys, key_id } => {
            let keys = load_keys(&keys)?;
            let key_id = pick_key(&keys, key_id.as_deref())?;
            let bytes = std::fs::read(&path)
                .map_err(|e| McpError::io(format!("cannot read {}", path.display()), e))?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| McpError::Config("the manifest is not UTF-8".into()))?;
            manifest::Manifest::parse(text).map_err(|e| McpError::Config(e.to_string()))?;
            let signature = manifest::sign(&keys, &key_id, &bytes)
                .map_err(|e| McpError::Config(e.to_string()))?;
            let target = manifest::default_signature_path(&path);
            write_signature(&target, &signature)?;
            print(&format!(
                "signed {} with key {key_id}: {}",
                path.display(),
                target.display()
            ))
        }
    }
}

fn grant_command(command: GrantCommand) -> Result<(), McpError> {
    let default_signature = |path: &std::path::Path| {
        let mut name = path.as_os_str().to_owned();
        name.push(".sig");
        PathBuf::from(name)
    };
    match command {
        GrantCommand::Verify {
            path,
            keys,
            signature,
        } => {
            let keys = load_keys(&keys)?;
            let signature = signature.unwrap_or_else(|| default_signature(&path));
            let loaded = grants::Loaded::load(&path, &signature, &keys)
                .map_err(|e| McpError::Config(e.to_string()))?;
            match &loaded.signature {
                grants::Signature::Valid(key_id) => {
                    print(&format!(
                        "grant is valid: engagement {}, signed by key {key_id}",
                        loaded.grant.engagement
                    ))?;
                    print(&format!("  digest:      {}", loaded.digest))?;
                    print(&format!("  ro origins:  {:?}", loaded.grant.ro_origins))?;
                    print(&format!("  rw origins:  {:?}", loaded.grant.rw_origins))?;
                    print(&format!(
                        "  plan digest: {}",
                        loaded.grant.plan_digest().unwrap_or_else(|| "none".into())
                    ))
                }
                grants::Signature::Missing => Err(McpError::Config(format!(
                    "the grant has no signature ({} is missing)",
                    signature.display()
                ))),
                grants::Signature::Invalid(why) => Err(McpError::Config(format!(
                    "the grant signature is invalid: {why}"
                ))),
            }
        }
        GrantCommand::Sign { path, keys, key_id } => {
            let keys = load_keys(&keys)?;
            let key_id = pick_key(&keys, key_id.as_deref())?;
            let bytes = std::fs::read(&path)
                .map_err(|e| McpError::io(format!("cannot read {}", path.display()), e))?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| McpError::Config("the grant is not UTF-8".into()))?;
            grants::Grant::parse(text).map_err(|e| McpError::Config(e.to_string()))?;
            let signature = grants::sign(&keys, &key_id, &bytes)
                .map_err(|e| McpError::Config(e.to_string()))?;
            let target = default_signature(&path);
            write_signature(&target, &signature)?;
            print(&format!(
                "signed {} with key {key_id}: {}",
                path.display(),
                target.display()
            ))
        }
    }
}

fn approvals_command(command: ApprovalsCommand) -> Result<(), McpError> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    match command {
        ApprovalsCommand::List { config } => {
            let config = Config::load(&config)?;
            let pending = approvals::list_pending(&config.approvals_dir(), now)
                .map_err(|e| McpError::Config(e.to_string()))?;
            if pending.is_empty() {
                return print("no pending approvals");
            }
            for view in pending {
                print(&format!(
                    "{} {} {} on {} [{}] {}{}",
                    view.id,
                    view.tool,
                    view.class,
                    view.origin,
                    view.reasons.join(", "),
                    view.summary,
                    if view.approved { " (approved)" } else { "" }
                ))?;
            }
            Ok(())
        }
        ApprovalsCommand::Approve { id, config, key_id } => {
            let config = Config::load(&config)?;
            let operator = config
                .operator
                .as_ref()
                .ok_or_else(|| McpError::Config("[operator] keys_file is not configured".into()))?;
            let keys = load_keys(&operator.keys_file)?;
            let key_id = pick_key(&keys, key_id.as_deref())?;
            let view = approvals::approve(&config.approvals_dir(), &id, &keys, &key_id, now)
                .map_err(|e| McpError::Config(e.to_string()))?;
            print(&format!(
                "approved {}: {} {} on {} ({})",
                view.id, view.tool, view.class, view.origin, view.summary
            ))
        }
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
        Some(McpCommand::Manifest { command }) => return manifest_command(command),
        Some(McpCommand::Grant { command }) => return grant_command(command),
        Some(McpCommand::Approvals { command }) => return approvals_command(command),
        Some(McpCommand::OperatorKey {
            command: OperatorKeyCommand::New { key_id },
        }) => {
            print(
                "# Operator key (shown once). Append this line to the key file and chmod 600 it:",
            )?;
            return print(&crypto::new_key_line(&key_id));
        }
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
