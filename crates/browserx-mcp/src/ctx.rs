//! The shared state of a running server.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use browserx_core::ProxyRoute;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use crate::approvals::Approvals;
use crate::audit::{Audit, Context as AuditContext};
use crate::backend::Backend;
use crate::backends::cache::{Admission, Cache};
use crate::backends::export::Exporter;
use crate::browse::{Hub, Limits};
use crate::config::{Capability, Config, read_secret};
use crate::crypto::OperatorKeys;
use crate::error::McpError;
use crate::grants;
use crate::ledger::Ledger;
use crate::llm::Llm;
use crate::manifest;
use crate::metrics::Sampler;
use crate::redact::Redactor;
use crate::safety::{RateLimiter, Scope};
use crate::sessions::{Managed, Registry};
use crate::shots::Shots;
use crate::tools::catalog::{self, ToolDef};

/// How long startup waits for the export sinks to answer once.
const EXPORT_PREFLIGHT: Duration = Duration::from_secs(10);
/// How long shutdown waits for the export queues to flush.
const EXPORT_FLUSH: Duration = Duration::from_secs(5);

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
    /// Per-tool rate limits in memory: the only limiter without a cache, the fallback with one.
    pub limiter: RateLimiter,
    /// Limits and budgets shared with other servers, when `[cache]` is configured.
    pub cache: Option<Arc<Cache>>,
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
    /// The operator keys that verify manifests, grants and approvals.
    pub keys: Option<OperatorKeys>,
    /// The session capability ledger (Rule of Two).
    pub ledger: Ledger,
    /// Approvals: multi round-trip state and out-of-band records.
    pub approvals: Approvals,
    /// Recent screenshots served as resources.
    pub shots: Shots,
    /// Calls of the engagement that touched pages, against `limits.max_calls`.
    pub engagement_calls: AtomicU64,
    /// Start times of recent calls, for `limits.rps`.
    pub engagement_recent: Mutex<VecDeque<Instant>>,
    /// Fires on shutdown; stops background tasks.
    pub cancel: CancellationToken,
}

/// Loads the scope grant and checks it: signed, in force for this engagement and not wider than
/// the manifest and the configured origins. A grant that fails any check stops the server,
/// because running without the restriction an operator asked for would widen access silently.
fn load_grant(
    cfg: &Config,
    section: &crate::config::GrantSection,
    keys: &OperatorKeys,
    trusted_manifest: Option<&Arc<manifest::Loaded>>,
) -> Result<grants::Active, McpError> {
    let signature = section.signature_file.clone().unwrap_or_else(|| {
        let mut name = section.path.as_os_str().to_owned();
        name.push(".sig");
        name.into()
    });
    let loaded = grants::Loaded::load(&section.path, &signature, keys)
        .map_err(|e| McpError::Config(e.to_string()))?;
    if !loaded.trusted() {
        return Err(McpError::Config(format!(
            "the scope grant {} is not signed by an operator key ({:?}): refusing to start",
            section.path.display(),
            loaded.signature
        )));
    }
    let origins = cfg.origins()?;
    let ceiling = grants::Ceiling {
        engagement: trusted_manifest
            .map(|m| m.manifest.id.as_str())
            .or(cfg.engagement.id.as_deref()),
        manifest: trusted_manifest.map(|m| &m.manifest),
        origins: &origins,
        grant: None,
        max_calls: trusted_manifest.and_then(|m| m.manifest.limits.max_calls),
        not_after: trusted_manifest.and_then(|m| m.manifest.not_after),
    };
    let violations = loaded.grant.violations_against(&ceiling);
    if !violations.is_empty() {
        return Err(McpError::Config(format!(
            "the scope grant widens its ceiling: {}",
            violations.join("; ")
        )));
    }
    Ok(grants::Active::new(loaded.grant, loaded.digest))
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
                sensitive: None,
            });
        }

        let cache = cfg
            .cache
            .as_ref()
            .map(|section| Cache::new(section).map(Arc::new))
            .transpose()?;
        let redactor = Redactor::new(secrets);
        let keys = cfg
            .operator
            .as_ref()
            .map(|operator| {
                OperatorKeys::load(&operator.keys_file).map_err(|e| McpError::Config(e.to_string()))
            })
            .transpose()?;
        let loaded_manifest = match (&cfg.manifest, &keys) {
            (Some(section), Some(keys)) => {
                let signature = section
                    .signature_file
                    .clone()
                    .unwrap_or_else(|| manifest::default_signature_path(&section.path));
                Some(Arc::new(
                    manifest::Loaded::load(&section.path, &signature, keys)
                        .map_err(|e| McpError::Config(e.to_string()))?,
                ))
            }
            _ => None,
        };
        let trusted_manifest = loaded_manifest.as_ref().filter(|m| m.trusted());
        let active_grant = match (&cfg.grant, &keys) {
            (Some(section), Some(keys)) => {
                Some(Arc::new(load_grant(&cfg, section, keys, trusted_manifest)?))
            }
            _ => None,
        };
        let exporter = Exporter::from_config(&cfg)?;
        let audit = Audit::open(
            &cfg.audit.path,
            AuditContext {
                engagement: trusted_manifest
                    .map(|m| m.manifest.id.clone())
                    .or_else(|| cfg.engagement.id.clone()),
                operator: trusted_manifest
                    .map(|m| m.manifest.operator.clone())
                    .or_else(|| cfg.engagement.operator.clone()),
                authorization_note: trusted_manifest
                    .map(|m| m.manifest.authorization_note.clone())
                    .or_else(|| cfg.engagement.authorization_note.clone()),
                manifest_digest: loaded_manifest.as_ref().map(|m| m.digest.clone()),
                grant_digest: active_grant.as_ref().map(|g| g.digest.clone()),
            },
            redactor.clone(),
        )
        .map_err(|e| {
            McpError::io(
                format!("cannot open the audit log {}", cfg.audit.path.display()),
                e,
            )
        })?;
        let audit = match exporter {
            Some(exporter) => audit.with_exporter(exporter),
            None => audit,
        };

        let mut scope = Scope::new(cfg.origins()?, cfg.browse.require_scope, cfg.window()?);
        if let Some(loaded) = &loaded_manifest {
            scope = scope.with_manifest(Arc::clone(loaded));
        }
        if let Some(active) = &active_grant {
            scope = scope.with_grant(Arc::clone(active));
        }
        let scope = Arc::new(scope);
        let hub = Hub::new(Limits::from_config(&cfg.browse), Arc::clone(&scope));
        let sampler = Arc::new(Sampler::new(backend.clone()));
        let route_names: BTreeMap<String, ()> =
            routes.keys().map(|name| (name.clone(), ())).collect();
        let tools = catalog::enabled(&cfg, llm.is_some(), &route_names);
        let c_enabled = cfg.has(Capability::Interact) || cfg.has(Capability::Evaluate);
        let ledger = Ledger::new(cfg.safety.rule_of_two.mode, c_enabled);
        let approvals = Approvals::new(keys.clone(), cfg.approvals_dir(), cfg.approvals.ttl_secs);
        Ok(Arc::new(Self {
            cfg,
            backend,
            audit,
            scope,
            redactor,
            limiter: RateLimiter::new(),
            cache,
            registry,
            hub,
            llm,
            sampler,
            routes,
            tools,
            keys,
            ledger,
            approvals,
            shots: Shots::default(),
            engagement_calls: AtomicU64::new(0),
            engagement_recent: Mutex::new(VecDeque::new()),
            cancel: CancellationToken::new(),
        }))
    }

    /// Checks the shared cache once at startup. A cache that does not answer leaves the server
    /// running on its in-memory limits (`degraded`), unless `cache.required` is set.
    ///
    /// # Errors
    /// [`McpError::Cache`] when the cache is required and does not answer.
    pub async fn check_cache(&self) -> Result<(), McpError> {
        let (Some(cache), Some(section)) = (&self.cache, &self.cfg.cache) else {
            return Ok(());
        };
        match cache.probe().await {
            Ok(()) => Ok(()),
            Err(error) if section.required => Err(McpError::Cache(format!(
                "cache.required is set and the cache cannot be used: {error}"
            ))),
            Err(error) => {
                tracing::warn!(%error, "the shared cache is not available at startup: the in-memory limits apply");
                Ok(())
            }
        }
    }

    /// Admits a call of `tool` against `per_minute`: in the shared cache when one answers, else
    /// in memory. A call the cache admitted is also recorded in memory, so the fallback
    /// continues from what this server has seen. The result is the wait in seconds on refusal.
    ///
    /// # Errors
    /// The seconds after which the call would be admitted.
    pub async fn admit(&self, tool: &str, per_minute: u32) -> Result<(), u64> {
        if let Some(cache) = &self.cache {
            match cache.rate_limit(tool, per_minute).await {
                Ok(Admission::Admitted) => {
                    self.limiter.note(tool);
                    return Ok(());
                }
                Ok(Admission::Wait(seconds)) => return Err(seconds),
                Err(_) => {}
            }
        }
        self.limiter.admit(tool, per_minute)
    }

    /// Starts the background metrics sampler and the audit export tasks.
    pub fn start(self: &Arc<Self>) {
        if let Some(exporter) = self.audit.exporter() {
            exporter.start();
        }
        if self.backend.has_ops() {
            Arc::clone(&self.sampler).spawn(
                Duration::from_secs(self.cfg.limits.sample_interval_secs),
                self.cancel.clone(),
            );
        }
    }

    /// The tools a client may see now: sorted by name, and without the tools that change pages
    /// while a configured engagement manifest is unsigned, invalid or outside its window.
    #[must_use]
    pub fn listed_tools(&self) -> Vec<&ToolDef> {
        let now = Self::now();
        let mutation_ok = self.scope.check_mutation(now).is_ok();
        let mut listed: Vec<&ToolDef> = self
            .tools
            .iter()
            .filter(|t| {
                mutation_ok
                    || !matches!(t.class, catalog::Class::Interact | catalog::Class::Evaluate)
            })
            .collect();
        listed.sort_by_key(|t| t.name);
        listed
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

    /// Waits until every audit export sink has tried to reach its service once.
    ///
    /// # Errors
    /// When a sink refuses to run (wrong engine or version, a schema newer than this build).
    /// A sink that is merely unreachable is logged and keeps retrying.
    pub async fn preflight_export(&self) -> Result<(), McpError> {
        match self.audit.exporter() {
            Some(exporter) => exporter.preflight(EXPORT_PREFLIGHT).await,
            None => Ok(()),
        }
    }

    /// Stops background tasks, closes browser connections, when configured releases the
    /// sessions this server created, and flushes the audit export.
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        self.hub.close_all().await;
        if self.cfg.mcp.release_on_exit {
            self.release_created().await;
        }
        if let Some(exporter) = self.audit.exporter() {
            exporter.shutdown(EXPORT_FLUSH).await;
        }
    }

    async fn release_created(&self) {
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
                principal: None,
            };
            let _ = self.audit.record(&crate::audit::Entry {
                phase: crate::audit::Phase::Result,
                caller: &caller,
                tool: "release_session",
                arguments: &serde_json::json!({ "session_id": managed.id, "reason": "server shutdown" }),
                outcome: if outcome.is_ok() { "ok" } else { "error" },
                detail: outcome.err().map(|e| e.to_string()).as_deref(),
                duration_ms: None,
                extra: None,
            });
        }
    }
}
