//! Command-line definition.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// BrowserX: browser pooling, session management, persistence, recovery and handoff.
#[derive(Debug, Parser)]
#[command(name = "browserx", version, about, long_about = None)]
pub struct Cli {
    /// Log output format.
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text, env = "BROWSERX_LOG_FORMAT")]
    pub log_format: LogFormat,
    #[command(subcommand)]
    pub command: Command,
}

/// Log formats.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum LogFormat {
    /// Human-readable lines.
    Text,
    /// One JSON object per line.
    Json,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once at startup
pub enum Command {
    /// Run the BrowserX server.
    Serve {
        /// Configuration file (TOML).
        #[arg(long, short, env = "BROWSERX_CONFIG")]
        config: PathBuf,
    },
    /// Validate configuration files.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Create API keys.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Manage the snapshot encryption key.
    SnapshotKey {
        #[command(subcommand)]
        command: SnapshotKeyCommand,
    },
    /// Check that this machine can run BrowserX: finds Chromium, launches it,
    /// reads its version and shuts it down with confirmation.
    Doctor {
        /// Use the runtime section and storage paths of this configuration.
        #[arg(long, short)]
        config: Option<PathBuf>,
    },
    /// Serve the Model Context Protocol (stdio or streamable HTTP) so AI agents can monitor, drive
    /// and explain BrowserX within limits you set. Also: `mcp check`, `mcp audit verify`,
    /// `mcp token new`.
    Mcp(browserx_mcp::McpArgs),
    /// Talk to a running server.
    Session {
        #[command(flatten)]
        remote: Remote,
        #[command(subcommand)]
        command: SessionCommand,
    },
}

/// `config` subcommands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Parse and validate a configuration file.
    Check {
        /// Configuration file (TOML).
        path: PathBuf,
    },
}

/// `keys` subcommands.
#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Generate an API key. The key is printed once; only its SHA-256 belongs in the configuration.
    New {
        /// Owner name the key belongs to.
        name: String,
        /// Concurrent session cap written into the printed snippet.
        #[arg(long, default_value_t = 16)]
        max_sessions: usize,
    },
}

/// `snapshot-key` subcommands.
#[derive(Debug, Subcommand)]
pub enum SnapshotKeyCommand {
    /// Create a new snapshot encryption key file (mode 0600; refuses to overwrite).
    New {
        /// Where to write the key file.
        path: PathBuf,
    },
}

/// Connection options shared by the client commands.
#[derive(Debug, Args)]
pub struct Remote {
    /// Server base URL.
    #[arg(
        long,
        global = true,
        env = "BROWSERX_SERVER",
        default_value = "http://127.0.0.1:7690"
    )]
    pub server: String,
    /// API key.
    #[arg(long, global = true, env = "BROWSERX_API_KEY", hide_env_values = true)]
    pub api_key: Option<String>,
    /// Session token (for attach, renew, handoff, snapshot and release).
    #[arg(long, global = true, env = "BROWSERX_TOKEN", hide_env_values = true)]
    pub token: Option<String>,
}

/// Persistence modes.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PersistenceArg {
    /// Nothing survives the browser.
    Ephemeral,
    /// Encrypted cookie and storage snapshots.
    Snapshot,
    /// A locked user-data directory.
    Profile,
}

impl PersistenceArg {
    /// API spelling.
    #[must_use]
    pub fn api(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::Snapshot => "snapshot",
            Self::Profile => "profile",
        }
    }
}

/// Isolation levels.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum IsolationArg {
    /// One browser process per session.
    Dedicated,
    /// A context inside a shared browser.
    Shared,
}

impl IsolationArg {
    /// API spelling.
    #[must_use]
    pub fn api(self) -> &'static str {
        match self {
            Self::Dedicated => "dedicated_browser",
            Self::Shared => "shared_browser",
        }
    }
}

/// Recovery policies.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RecoveryArg {
    /// Relaunch and restore.
    Restore,
    /// A lost browser ends the session.
    None,
}

impl RecoveryArg {
    /// API spelling.
    #[must_use]
    pub fn api(self) -> &'static str {
        match self {
            Self::Restore => "restore",
            Self::None => "none",
        }
    }
}

/// `session` subcommands.
#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Create a session. Prints the token and CDP URL once.
    Create(CreateArgs),
    /// List your sessions.
    List {
        /// Only these statuses (comma separated, e.g. `idle,active`).
        #[arg(long)]
        status: Option<String>,
    },
    /// Show one session.
    Get {
        /// Session id.
        id: String,
    },
    /// Attach (recovering the browser if it is gone); prints the recovery outcome and CDP URL.
    Attach {
        /// Session id.
        id: String,
    },
    /// Extend the lease.
    Renew {
        /// Session id.
        id: String,
        /// Generation you hold.
        #[arg(long)]
        generation: u64,
        /// New TTL in seconds.
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
    /// Move control to a new token; the old token and its relays stop working.
    Handoff {
        /// Session id.
        id: String,
        /// Generation you hold.
        #[arg(long)]
        generation: u64,
    },
    /// Take a snapshot now (snapshot persistence only).
    Snapshot {
        /// Session id.
        id: String,
    },
    /// Release the session.
    Release {
        /// Session id.
        id: String,
        /// Fence on this generation.
        #[arg(long)]
        generation: Option<u64>,
    },
}

/// Arguments of `session create`.
#[derive(Debug, Args)]
pub struct CreateArgs {
    /// What survives the browser.
    #[arg(long, value_enum)]
    pub persistence: Option<PersistenceArg>,
    /// Process isolation.
    #[arg(long, value_enum)]
    pub isolation: Option<IsolationArg>,
    /// Reuse this persistent identity (`prf_...`).
    #[arg(long)]
    pub profile_id: Option<String>,
    /// Launch profile name from the server configuration.
    #[arg(long)]
    pub launch_profile: Option<String>,
    /// Upstream proxy URL (`http://`, `https://`, `socks5://`, `socks5h://`).
    #[arg(long)]
    pub proxy_url: Option<String>,
    /// Upstream proxy username (`{session}` and `{generation}` are substituted).
    #[arg(long, requires = "proxy_url")]
    pub proxy_username: Option<String>,
    /// Upstream proxy password.
    #[arg(
        long,
        requires = "proxy_url",
        env = "BROWSERX_PROXY_PASSWORD",
        hide_env_values = true
    )]
    pub proxy_password: Option<String>,
    /// Lease TTL in seconds.
    #[arg(long)]
    pub ttl_secs: Option<u64>,
    /// Absolute lifetime cap in seconds.
    #[arg(long)]
    pub max_lifetime_secs: Option<u64>,
    /// Release after this many idle seconds.
    #[arg(long)]
    pub idle_timeout_secs: Option<u64>,
    /// What to do when the browser is lost.
    #[arg(long, value_enum)]
    pub recovery: Option<RecoveryArg>,
    /// Label `key=value` (repeatable).
    #[arg(long = "label", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,
}
