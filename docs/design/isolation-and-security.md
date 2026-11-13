# Isolation and security

This page states what BrowserX separates, what it does not, which secrets it handles and how, and the threat model the design assumes. Read it before exposing a worker to anyone other than yourself.

## Isolation modes

| | `dedicated_browser` (default) | `shared_browser` |
| --- | --- | --- |
| Browser | One Chromium process per session | A warm Chromium process, one *browser context* per session |
| Client access | A byte relay to the browser-level DevTools endpoint | A relay that parses CDP and scopes every command to the session's context |
| Profile directory | Own `--user-data-dir` (temporary, or a locked persistent one) | Shared process; no per-session directory |
| Per-session upstream proxy | Yes | No (the forwarder is per browser process) |
| `profile` persistence | Yes | No |
| Crash blast radius | That session | Every context in the browser |
| Cost | One process per session | Cheap and fast after warm-up |

### Dedicated browser

The client has the browser-level endpoint through the relay, so it controls the whole browser, which is its own. Use it for anything where the client is not fully trusted with a neighbor's data, for `profile` persistence, and when you need a per-session proxy or a launch profile of its own.

### Shared browser

A shared browser serves several sessions through isolated browser contexts: separate cookies, storage and cache per context. The worker never gives a shared-session client the browser-level endpoint. The relay parses every CDP message and applies **default-deny** rules: only an allow-list of browser-level methods passes (a subset of `Target.*`, `Browser.getVersion` and context-scoped helpers), everything else is refused. A refused command is answered with a CDP error (`code -32000`, message `refused by the scoped relay: ...`) and the connection stays open. In particular:

- `Target.createTarget` has `browserContextId` injected (or forced);
- `Target.getTargets`, `Target.getBrowserContexts` and target events are filtered to the session's own context;
- `Target.setDiscoverTargets` is filtered the same way;
- `Target.createBrowserContext`, `Target.disposeBrowserContext`, `Browser.close`, `Browser.crash*` and `SystemInfo.*` are refused;
- attaching to a target outside the context is refused, and page-session traffic (flat `sessionId` messaging) is allowed only for targets created or attached inside the context; non-flat messaging is refused;
- responses and events that mention targets or contexts are filtered to the session's own, and unknown browser-level events are dropped.

**Context isolation is not a hostile multi-tenant boundary.** It protects cooperative clients from each other's cookies and mistakes. It does not defend against a browser exploit, a renderer escape, a side channel through shared CPU or memory, or a client that finds a CDP method the filter did not anticipate. If clients are mutually untrusted, use dedicated isolation, ideally with one worker per trust domain.

## Credentials and where they live

| Secret | Shape | Stored as | Appears in | Never appears in |
| --- | --- | --- | --- | --- |
| API key | `bxk_...` (created by `browserx keys new`) | SHA-256 digest in the config file | The `Authorization` header | Logs, config, the lease store |
| Lease token | `bxt_<64 hex>` | SHA-256 digest in the lease record | The `X-BrowserX-Token` header; the `cdp_url` path | Logs, metrics, error bodies, the store |
| Snapshot key | 32 bytes in `snapshot_key_file` (`0600`) | The key file | Memory (zeroized on drop) | Config, logs, backups of snapshots |
| Proxy password | In the session spec | The lease's spec, in the lease store | The forwarder's upstream authentication | Browser command line, logs, API responses |

- API keys and lease tokens are compared by digest in constant time.
- The CDP relay path contains the lease token because many CDP clients accept only a URL. BrowserX never logs the path of that route, and neither should your reverse proxy: configure it to drop or redact request paths for `/cdp/`.
- The lease store holds the proxy password of a session's spec in the clear (it is needed to recover the session). Protect `state_dir` accordingly: owner-only permissions, encrypted disk where appropriate.
- Tracing never prints credentials. `Secret` values print as `<redacted>` in debug output.

## Transport

The relay and the API speak plaintext HTTP and `ws://`. BrowserX does not terminate TLS.

- On a single machine, keep `server.listen` on loopback.
- On a trusted network, restrict by firewall.
- Across untrusted networks, put a TLS-terminating reverse proxy in front, forward WebSocket upgrades for `/cdp/`, set `server.public_base_url` to the external address so that returned `cdp_url` values use the external host (and `wss://` when you terminate TLS), and keep paths out of its access logs.

## Browser hardening

The worker launches Chromium with a fixed set of managed flags: `--remote-debugging-port=0` (a random loopback port), `--user-data-dir=<dir>`, `--no-first-run`, `--no-default-browser-check`, `--disable-background-networking`, `--disable-sync`, `--disable-default-apps`, `--password-store=basic`, `--use-mock-keychain`, headless mode when requested, and `--proxy-server` / `--proxy-bypass-list=<-loopback>` when a forwarder is in use (so loopback addresses are proxied too, not bypassed).

Launch profiles cannot override the managed flags: a profile whose `args` set `--remote-debugging-*`, `--user-data-dir`, `--proxy-server`, `--proxy-bypass-list`, `--proxy-pac-url`, `--proxy-auto-detect`, `--no-proxy-server` or `--headless` (use the `headless` key instead) is rejected when the worker starts. The browser-level DevTools endpoint is bound to loopback and is never handed to clients directly.

Chromium's own sandbox stays on unless a launch profile disables it. Running browsers as root in a container usually requires `--no-sandbox`; prefer a non-root user and a container runtime that permits user namespaces, and treat a no-sandbox browser as having the privileges of its process.

## Egress policy

By default the forwarder refuses to connect to private, loopback, link-local, carrier-grade NAT, multicast and cloud-metadata addresses, so a page, a redirect or a DNS answer cannot turn the browser into a pivot into your network. See [egress](egress.md) for the rules, the allow-list and the SOCKS5-with-remote-DNS caveat.

## Ownership

Sessions belong to the API key name that created them. List, get, attach, renew, handoff, snapshot and release are scoped to that owner, plus the token requirement for controller operations. An API key sees only its own sessions. Per-key `max_sessions` bounds one owner's footprint.

## Threat model

BrowserX is designed to be run by an operator who trusts the machine and the operator's own clients, and to limit the damage when a client or a page misbehaves.

**Defended**

- A client that guesses or replays another session's identifier: the token is required, 256 random bits, compared by digest.
- A stale or superseded controller: generation fencing and token rotation.
- A page or redirect that targets internal addresses: egress policy.
- A snapshot file read from disk or a swapped snapshot blob: AES-256-GCM with bound metadata.
- A browser that hangs or leaks: health probes, confirmed shutdown, process-group kill, bounded queues and limits.
- Resource exhaustion by one owner: per-key quotas, admission queue with deadline, message-size limits.

**Not defended**

- A compromised worker host or a user who can read `state_dir` and the key file.
- Other local processes on the worker host. Each browser's DevTools endpoint and each session's forwarder listen on loopback without authentication, so any local process can reach them. Run workers on hosts, or in network namespaces, where local processes are trusted.
- A malicious client with dedicated isolation: it controls a real browser on your machine and can run arbitrary page content. Run workers with the least privilege you can.
- A malicious tenant under shared isolation, as described above.
- Network observers when you expose plaintext listeners.
- What a target site does with the traffic your browsers send.

## Reporting a problem

See [SECURITY.md](../../SECURITY.md) for private reporting and for what is in scope.
