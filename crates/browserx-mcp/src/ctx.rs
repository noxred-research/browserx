//! The shared state of a running server.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use browserx_core::ProxyRoute;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use crate::audit::{Audit, Context as AuditContext};
use crate::backend::Backend;
use crate::browse::{Hub, Limits};
use crate::config::{Capability, Config, read_secret};
use crate::error::McpError;
use crate::llm::Llm;
use crate::metrics::Sampler;
use crate::redact::Redactor;
use crate::safety::{RateLimiter, Scope};
use crate::sessions::{Managed, Registry};
use crate::tools::catalog::{self, ToolDef};

/// Everything the tools need. Built once from the configuration.
pub struct Ctx {
    /// The configuration.
    pub cfg: Config,
    /// The BrowserX server client.
    pub backend: Backend,
    /// The audit log.
    pub audit: Audit,
    /// Browsing scope and engagement window.
    pub scope: Arc<Scope>,
    /// Secret scrubbing for output and prompts.
    pub redactor: Redactor,
    /// Per-tool rate limits.
    pub limiter: RateLimiter,
    /// Controlled sessions.
    pub registry: Registry,
    /// Browser connections.
    pub hub: Hub,
    /// The optional model endpoint.
    pub llm: Option<Llm>,
    /// Background metrics samples.
    pub sampler: Arc<Sampler>,
    /// Named proxy routes with their secrets loaded.
    pub routes: BTreeMap<String, ProxyRoute>,
    /// The enabled tools.
    pub tools: Vec<ToolDef>,
    /// Fires on shutdown; stops background tasks.
    pub cancel: CancellationToken,
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("capabilities", &self.cfg.mcp.capabilities)
            .finish_non_exhaustive()
    }
}

impl Ctx {
    /// Reads every secret file, opens the audit log and builds the clients.
    ///
    /// # Errors
    /// When a file is unreadable, the audit log cannot be opened or a client cannot be built.
    pub fn build(cfg: Config) -> Result<Arc<Self>, McpError> {
        let api_key = read_secret(&cfg.server.api_key_file)?;
        let mut secrets = vec![api_key.expose().to_owned()];
        let backend = Backend::new(
            &cfg.server.url,
            cfg.server.ops_url.as_deref(),
            api_key,
            Duration::from_secs(cfg.server.request_timeout_secs),
        )
        .map_err(|e| McpError::Config(e.to_string()))?;

        let llm = match &cfg.ai {
            Some(ai) => {
                let key = ai.api_key_file.as_deref().map(read_secret).transpose()?;
                if let Some(key) = &key {
                    secrets.push(key.expose().to_owned());
                }
                Some(Llm::new(ai, key).map_err(|e| McpError::Config(e.to_string()))?)
            }
            None => None,
        };

        let mut routes = BTreeMap::new();
        for (name, route) in &cfg.proxy_routes {
            let password = route
                .password_file
                .as_deref()
                .map(read_secret)
                .transpose()?;
            if let Some(password) = &password {
                secrets.push(password.expose().to_owned());
            }
            routes.insert(
                name.clone(),
                ProxyRoute {
                    url: route.url.clone(),
                    username: route.username.clone(),
                    password,
                },
            );
        }

        let registry = Registry::default();
        for adopt in &cfg.adopt {
            let token = read_secret(&adopt.token_file)?;
            secrets.push(token.expose().to_owned());
            let id = browserx_core::SessionId::parse(&adopt.session_id)
                .map_err(|e| McpError::Config(e.to_string()))?
                .prefixed();
            registry.insert(Managed {
                id,
                token,
                adopted: true,
            });
        }

        let redactor = Redactor::new(secrets);
        let audit = Audit::open(
            &cfg.audit.path,
            AuditContext {
                engagement: cfg.engagement.id.clone(),
                operator: cfg.engagement.operator.clone(),
                authorization_note: cfg.engagement.authorization_note.clone(),
            },
            redactor.clone(),
        )
        .map_err(|e| {
            McpError::io(
                format!("cannot open the audit log {}", cfg.audit.path.display()),
                e,
            )
        })?;

        let scope = Arc::new(Scope::new(
            cfg.origins()?,
            cfg.browse.require_scope,
            cfg.window()?,
        ));
        let hub = Hub::new(Limits::from_config(&cfg.browse), Arc::clone(&scope));
        let sampler = Arc::new(Sampler::new(backend.clone()));
        let route_names: BTreeMap<String, ()> =
            routes.keys().map(|name| (name.clone(), ())).collect();
        let tools = catalog::enabled(&cfg, llm.is_some(), &route_names);
        Ok(Arc::new(Self {
            cfg,
            backend,
            audit,
            scope,
            redactor,
            limiter: RateLimiter::new(),
            registry,
            hub,
            llm,
            sampler,
            routes,
            tools,
            cancel: CancellationToken::new(),
        }))
    }

    /// Starts the background metrics sampler.
    pub fn start(self: &Arc<Self>) {
        if self.backend.has_ops() {
            Arc::clone(&self.sampler).spawn(
                Duration::from_secs(self.cfg.limits.sample_interval_secs),
                self.cancel.clone(),
            );
        }
    }

    /// Whether `capability` is enabled.
    #[must_use]
    pub fn has(&self, capability: Capability) -> bool {
        self.cfg.has(capability)
    }

    /// The current time.
    #[must_use]
    pub fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    /// Stops background tasks, closes browser connections and, when configured, releases the
    /// sessions this server created.
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        self.hub.close_all().await;
        if !self.cfg.mcp.release_on_exit {
            return;
        }
        for managed in self.registry.created() {
            let outcome = self
                .backend
                .release(&managed.id, Some(&managed.token), None)
                .await;
            if let Err(error) = &outcome {
                tracing::warn!(session = %managed.id, %error, "could not release a session at shutdown");
            }
            let caller = crate::audit::Caller {
                transport: "shutdown",
                client_name: None,
                remote: None,
            };
            let _ = self.audit.record(&crate::audit::Entry {
                phase: crate::audit::Phase::Result,
                caller: &caller,
                tool: "release_session",
                arguments: &serde_json::json!({ "session_id": managed.id, "reason": "server shutdown" }),
                outcome: if outcome.is_ok() { "ok" } else { "error" },
                detail: outcome.err().map(|e| e.to_string()).as_deref(),
                duration_ms: None,
            });
        }
    }
}
