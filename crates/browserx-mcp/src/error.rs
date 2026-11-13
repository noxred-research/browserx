//! Typed errors: startup and configuration failures ([`McpError`]) and tool failures
//! ([`ToolError`]) that are shown to the model as readable tool results.

use serde_json::{Value, json};

/// A failure that stops the MCP server from starting or running.
#[derive(Debug, thiserror::Error)]
pub enum McpError {
    /// The configuration file is unreadable, malformed or inconsistent.
    #[error("configuration: {0}")]
    Config(String),
    /// A file (key, audit log, secret) could not be read or written.
    #[error("{what}: {source}")]
    Io {
        /// What the server was doing.
        what: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A transport (stdio, HTTP) failed.
    #[error("transport: {0}")]
    Transport(String),
    /// The audit log is broken or could not be written.
    #[error("audit log: {0}")]
    Audit(String),
}

impl McpError {
    /// An [`McpError::Io`] with context.
    pub fn io(what: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            what: what.into(),
            source,
        }
    }
}

/// Why a tool call failed. Tool failures are results with `isError: true`, which models can
/// read and correct; protocol errors are reserved for malformed requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailKind {
    /// The arguments are wrong.
    InvalidArguments,
    /// The safety model refused (scope, engagement window, capability, confirmation).
    Refused,
    /// A rate limit was hit.
    RateLimited,
    /// The BrowserX server answered with an error or could not be reached.
    Backend,
    /// The browser or the page failed (CDP error, timeout, stale reference).
    Browser,
    /// The needed feature or backend is not configured.
    NotConfigured,
    /// The server failed.
    Internal,
}

impl FailKind {
    /// Stable machine-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid_arguments",
            Self::Refused => "refused",
            Self::RateLimited => "rate_limited",
            Self::Backend => "backend_error",
            Self::Browser => "browser_error",
            Self::NotConfigured => "not_configured",
            Self::Internal => "internal_error",
        }
    }
}

/// A failed tool call.
#[derive(Debug, Clone)]
pub struct ToolError {
    /// The class of failure.
    pub kind: FailKind,
    /// What went wrong and, where possible, what to do about it.
    pub message: String,
    /// Optional structured detail (for example the BrowserX error code).
    pub detail: Option<Value>,
}

impl ToolError {
    /// A failure of `kind`.
    pub fn new(kind: FailKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            detail: None,
        }
    }

    /// The arguments are wrong.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(FailKind::InvalidArguments, message)
    }

    /// The safety model refused.
    pub fn refused(message: impl Into<String>) -> Self {
        Self::new(FailKind::Refused, message)
    }

    /// The browser or page failed.
    pub fn browser(message: impl Into<String>) -> Self {
        Self::new(FailKind::Browser, message)
    }

    /// A feature is not configured.
    pub fn not_configured(message: impl Into<String>) -> Self {
        Self::new(FailKind::NotConfigured, message)
    }

    /// An unexpected failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(FailKind::Internal, message)
    }

    /// Attaches structured detail.
    #[must_use]
    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }

    /// The JSON shown to the model.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut error = json!({ "kind": self.kind.name(), "message": self.message });
        if let Some(detail) = &self.detail {
            error["detail"] = detail.clone();
        }
        json!({ "error": error })
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind.name(), self.message)
    }
}

impl std::error::Error for ToolError {}

impl From<browserx_core::Error> for ToolError {
    fn from(error: browserx_core::Error) -> Self {
        let kind = match error {
            browserx_core::Error::InvalidRequest(_) => FailKind::InvalidArguments,
            browserx_core::Error::Forbidden(_) | browserx_core::Error::Unauthorized => {
                FailKind::Refused
            }
            browserx_core::Error::Internal(_) | browserx_core::Error::Storage(_) => {
                FailKind::Internal
            }
            _ => FailKind::Browser,
        };
        Self::new(kind, error.to_string()).with_detail(json!({ "code": error.code() }))
    }
}

impl From<browserx_cdp::CdpError> for ToolError {
    fn from(error: browserx_cdp::CdpError) -> Self {
        Self::browser(error.to_string())
    }
}

/// Result of a tool.
pub type ToolResult<T = crate::tools::Output> = Result<T, ToolError>;
