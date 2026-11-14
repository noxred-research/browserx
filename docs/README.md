# BrowserX documentation

BrowserX is next-generation AI/LLM-native browser pooling, session management, persistence, recovery and handoff for authorized security research. AI agents can watch, drive and explain a worker within limits an operator sets; models advise and never authorize, and leases, recovery and egress policy stay deterministic code. These pages describe `0.1.0-dev`. They are written for operators who run a worker and for developers who integrate a client; none of them depends on another repository.

## Design

How BrowserX works and why. Read these to understand the guarantees before you rely on them.

| Page | What it explains |
| --- | --- |
| [Architecture](design/architecture.md) | Components, the request path, what runs where, bounds and failure domains |
| [Sessions and leases](design/sessions-and-leases.md) | The lease record, lifecycle states, generations, tokens, time limits, admission |
| [Persistence](design/persistence.md) | `ephemeral`, `snapshot` and `profile`: what each keeps, what it cannot keep, how snapshots are sealed |
| [Recovery](design/recovery.md) | The four attach outcomes, health monitoring, relaunch, startup reconciliation |
| [Handoff](design/handoff.md) | Moving control of a live session to another client without losing the browser |
| [Isolation and security](design/isolation-and-security.md) | Dedicated and shared isolation, the scoped relay, credentials, threat model and limits |
| [Backends](design/backends.md) | Which databases, object stores, caches and streams BrowserX can use, why each family is in or out, how services are shared, what happens when one fails |
| [Egress](design/egress.md) | The loopback forwarder, destination policy, upstream proxies, sticky exits |
| [AI/LLM-native](design/ai-llm-native.md) | What agents can do, the safety model, and why the data path stays deterministic |

## Guides

How to do things.

| Page | What it covers |
| --- | --- |
| [Getting started](guides/getting-started.md) | Build, configure, start, create a session, kill the browser, see the outcome |
| [Configuration reference](guides/configuration.md) | Every key of the TOML file, with defaults and bounds |
| [API reference](guides/api.md) | HTTP routes, bodies, errors, the CDP relay |
| [CLI reference](guides/cli.md) | Every `browserx` command and flag |
| [MCP server](guides/mcp.md) | `browserx mcp`: stdio and HTTP setup, configuration, the tool catalog, resources, prompts, the audit log, typical sessions |
| [Backends](guides/backends.md) | PostgreSQL, MariaDB, S3-compatible stores, Valkey, Redis, ClickHouse, Kafka, RabbitMQ, OpenSearch and Elasticsearch: configuration, shared instances, tests |
| [Integrating CDP clients](guides/cdp-clients.md) | Attaching a client, reconnecting, handing off, reading the outcome |
| [Using an upstream proxy](guides/upstream-proxy.md) | `proxy` in the session spec, username templates, sticky exits, CONNECT-only gateways |
| [Custom launch profiles and browser builds](guides/launch-profiles.md) | Choosing an executable, flags and environment per profile |
| [Operations](guides/operations.md) | Metrics, health, readiness, logs, backups of `state_dir`, key rotation, upgrades |

## Project

- [Contributing](../CONTRIBUTING.md), [Code of Conduct](../CODE_OF_CONDUCT.md), [Security policy](../SECURITY.md)
- [Changelog](../CHANGELOG.md), [Third-party notices](../THIRD_PARTY_NOTICES.md)

## Conventions used in these pages

- A *worker* is one `browserx serve` process. A *controller* is the client that holds a session's lease token and drives its browser.
- `bxk_...` is an API key, `bxt_...` is a lease token, `ses_...`, `prf_...`, `brw_...`, `wrk_...` are session, profile, browser and worker identifiers.
- Example hosts end in `.test` or use loopback addresses; example keys and tokens are synthetic.
