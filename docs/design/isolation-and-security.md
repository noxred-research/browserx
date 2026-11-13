# Isolation and security

This page states what BrowserX separates, what it does not, which secrets it handles and how, and the threat model the design assumes. Read it before exposing a worker to anyone other than yourself. AI agents that drive a worker through the MCP server have their own safety model, described in [AI/LLM-native](ai-llm-native.md).

## Isolation modes

| | `dedicated_browser` (default) | `shared_browser` |
| --- | --- | --- |
| Browser | One Chromium process per session | A warm Chromium process, one *browser context* per session |
| Client access | A relay to the browser-level DevTools endpoint that applies the host-protection rules | A relay that parses CDP, applies the host-protection rules and scopes every command to the session's context |
| Profile directory | Own `--user-data-dir` (temporary, or a locked persistent one) | Shared process; no per-session directory |
| Per-session upstream proxy | Yes | No (the forwarder is per browser process) |
| `profile` persistence | Yes | No |
| Crash blast radius | That session | Every context in the browser |
| Cost | One process per session | Cheap and fast after warm-up |

### Dedicated browser

The client has the browser-level endpoint through the relay, so it controls the whole browser, which is its own. Use it for anything where the client is not fully trusted with a neighbor's data, for `profile` persistence, and when you need a per-session proxy or a launch profile of its own.

The dedicated relay parses every client command (bounded by the 64 MiB message limit) and applies the [host-protection rules](#host-protection-rules) below; everything else passes through unchanged. Binary client frames are not forwarded, because the browser would read them as an encoding the relay does not inspect.

### Shared browser

A shared browser serves several sessions through isolated browser contexts: separate cookies, storage and cache per context. The worker never gives a shared-session client the browser-level endpoint. The relay parses every CDP message and applies **default-deny** rules: only an allow-list of browser-level methods passes (a subset of `Target.*`, `Browser.getVersion` and context-scoped helpers), everything else is refused. A refused command is answered with a CDP error (`code -32000`, message `refused by the scoped relay: ...`) and the connection stays open. In particular:

- `Target.createTarget` has `browserContextId` injected (or forced);
- `Target.getTargets`, `Target.getBrowserContexts` and target events are filtered to the session's own context;
- `Target.setDiscoverTargets` is filtered the same way, and so are `Target.targetCreated`, `targetInfoChanged`, `targetDestroyed` and `targetCrashed` events on page sessions;
- `Target.createBrowserContext`, `Target.disposeBrowserContext`, `Browser.close`, `Browser.crash*` and `SystemInfo.*` are refused;
- attaching to a target outside the context is refused, and page-session traffic (flat `sessionId` messaging) is allowed only for targets created or attached inside the context; non-flat messaging is refused;
- page sessions may use an allow-list of protocol domains (`Page`, `Runtime`, `Network`, `DOM`, `Input`, `Emulation` and the other per-target domains). `Tracing`, `Memory`, `SystemInfo`, `Extensions` and unknown domains are refused, and `Storage` commands that name another context are refused;
- requests are tracked by `(sessionId, id)`; a request that reuses an id still in flight is refused, and requests waiting on a CDP session that detached or whose target was destroyed are dropped, so unanswered commands cannot fill the table;
- when a browser-wide `Target.setAutoAttach` reaches a target of another context, the relay does not deliver the attachment; it resumes the target (`Runtime.runIfWaitingForDebugger`) and detaches the attachment (`Target.detachFromTarget`) so a sibling's popup is never left waiting for a debugger;
- responses and events that mention targets or contexts are filtered to the session's own, and unknown browser-level events are dropped.

The shared relay also limits messages to `scoped_relay_max_message_bytes` (16 MiB by default).

### Host-protection rules

Browsers run as the worker's uid, so a relay client must not be able to turn the browser into a tool against the worker's host. Both relay kinds therefore apply these rules, whichever target or CDP session a command addresses. A refused command is answered with a CDP error (`code -32000`, message `refused by the host-protection policy: ...` on a dedicated relay) and the connection stays open.

- **Navigation and target creation** (`Page.navigate`, `Target.createTarget`, `Network.loadNetworkResource`, `Fetch.continueRequest`) accept only `http`, `https`, `data`, `blob`, `javascript` and `about:blank`/`about:srcdoc` URLs. `file:`, `filesystem:`, `view-source:`, `chrome:`, `chrome-untrusted:`, `devtools:`, `about:` aliases of internal pages and URLs without a scheme are refused. Leading control characters, tabs, newlines and letter case do not change the result.
- **Egress.** `Target.createBrowserContext` with `proxyServer` or `proxyBypassList` is refused on a dedicated relay (a context that connects directly would bypass the session's forwarder and its destination policy); shared relays refuse `Target.createBrowserContext` altogether.
- **Host files.** `DOM.setFileInputFiles`, `Page.handleFileChooser`, `Input.dispatchDragEvent` carrying files and `Extensions.*` are refused.
- **Downloads.** `Browser.setDownloadBehavior` and `Page.setDownloadBehavior` always get `downloadPath` replaced with `<state_dir>/downloads/<session_id>` (behavior `default` becomes `allow`; `deny` is kept). The directory is removed when the session's last relay connection closes, and `<state_dir>/downloads` is emptied at startup. Downloaded bytes count against the disk of `state_dir`; put a quota on that filesystem if sessions are not trusted with disk space.
- **Browser-wide data and process control.** `Tracing.*`, `Memory.*`, `SystemInfo.*`, `Browser.close`, `Browser.crash*` and `Target.sendMessageToTarget` are refused. Release a session through the API.

These rules close the CDP paths known to reach the worker's files, network position and sibling data. They are not a sandbox: a browser exploit, or a CDP method not covered above, still runs with the worker's privileges. Run the worker under a dedicated uid with only the state directory it needs, keep the snapshot key outside `state_dir` (below), and treat dedicated isolation as the boundary for untrusted clients only together with that host hardening.

**Context isolation is not a hostile multi-tenant boundary.** It protects cooperative clients from each other's cookies and mistakes. It does not defend against a browser exploit, a renderer escape, a side channel through shared CPU or memory, or a client that finds a CDP method the filter did not anticipate. If clients are mutually untrusted, use dedicated isolation, ideally with one worker per trust domain.

## Credentials and where they live

| Secret | Shape | Stored as | Appears in | Never appears in |
| --- | --- | --- | --- | --- |
| API key | `bxk_...` (created by `browserx keys new`) | SHA-256 digest in the config file | The `Authorization` header | Logs, config, the lease store |
| Lease token | `bxt_<64 hex>` | SHA-256 digest in the lease record | The `X-BrowserX-Token` header; the `cdp_url` path | Logs, metrics, error bodies, the store |
| Snapshot key | 32 bytes in `snapshot_key_file` (`0600`), outside `state_dir` | The key file | Memory (zeroized on drop; passed by reference as a `Zeroizing` buffer) | Config, logs, backups of snapshots |
| Proxy password | In the session spec | The lease's spec, in the lease store | The forwarder's upstream authentication (memory zeroized on drop) | Browser command line, logs, API responses |

- API keys and lease tokens are compared by digest in constant time.
- The CDP relay path contains the lease token because many CDP clients accept only a URL. BrowserX never logs the path of that route, and neither should your reverse proxy: configure it to drop or redact request paths for `/cdp/`.
- The lease store holds the proxy password of a session's spec in the clear while the session can still be recovered. When the lease becomes terminal (`closed` or `lost`) the password is removed from the stored record, and the SQLite database runs with `secure_delete` so freed content is overwritten; the database file (and its `-wal`/`-shm` files) is set to mode `0600` on every start. Protect `state_dir` accordingly: owner-only permissions, encrypted disk where appropriate.
- Tracing never prints credentials. `Secret` values print as `<redacted>` in debug output.

The key file must live **outside `state_dir`**: browsers run as the worker's uid and `state_dir` holds the lease database and browser profiles. The default is `./.browserx-keys/snapshot.key`, and a configuration whose key files sit inside `state_dir` is rejected at startup. A key file is loaded only if it is owned by the user running the worker and grants nothing to group or others (mode `0600` or stricter); anything else is a startup error, not a warning. Missing parent directories of a new key file are created with mode `0700`.

## Transport

The relay and the API speak plaintext HTTP and `ws://`. BrowserX does not terminate TLS.

Both listeners close a connection that does not deliver a complete request head within `header_read_timeout_secs` (10 by default; the timeout also ends idle keep-alive connections) and stop accepting new connections once `max_connections` (API, default 1024) or `ops_max_connections` (default 64) are open. A session accepts at most `max_relay_connections_per_session` (default 4) relay connections; more are refused with `429`. These limits blunt slow-header and connection-flood clients, but an exposed listener still belongs behind a reverse proxy that applies its own limits.

- On a single machine, keep `server.listen` on loopback.
- On a trusted network, restrict by firewall.
- Across untrusted networks, put a TLS-terminating reverse proxy in front, forward WebSocket upgrades for `/cdp/`, set `server.public_base_url` to the external address so that returned `cdp_url` values use the external host (and `wss://` when you terminate TLS), and keep paths out of its access logs.

## Browser hardening

The worker launches Chromium with a fixed set of managed flags: `--remote-debugging-port=0` (a random loopback port), `--user-data-dir=<dir>`, `--no-first-run`, `--no-default-browser-check`, `--disable-background-networking`, `--disable-sync`, `--disable-default-apps`, `--password-store=basic`, `--use-mock-keychain`, headless mode when requested, and `--proxy-server` / `--proxy-bypass-list=<-loopback>` when a forwarder is in use (so loopback addresses are proxied too, not bypassed), together with `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` (WebRTC may only use UDP that is itself proxied).

Launch profiles cannot override the managed flags: a profile whose `args` set `--remote-debugging-*`, `--user-data-dir`, `--proxy-server`, `--proxy-bypass-list`, `--proxy-pac-url`, `--proxy-auto-detect`, `--no-proxy-server`, `--force-webrtc-ip-handling-policy`, `--webrtc-ip-handling-policy` or `--headless` (use the `headless` key instead) is rejected when the worker starts. The browser-level DevTools endpoint is bound to loopback and is never handed to clients directly.

Chromium's own sandbox stays on unless a launch profile disables it. Running browsers as root in a container usually requires `--no-sandbox`; prefer a non-root user and a container runtime that permits user namespaces, and treat a no-sandbox browser as having the privileges of its process.

## Egress policy

By default the forwarder refuses to connect to private, loopback, link-local, carrier-grade NAT, multicast and cloud-metadata addresses, so a page, a redirect or a DNS answer cannot turn the browser into a pivot into your network. See [egress](egress.md) for the rules, the allow-list and the SOCKS5-with-remote-DNS caveat.

## Agent actions

The relay policy above applies to every CDP client, an AI agent included. The MCP server adds a separate, deterministic layer **above** it for agents: scope checks on every top-level request, an action gate (action classes and a profile, a signed engagement manifest, signed scope grants, a per-session Rule of Two ledger and human approvals) and a hash-chained audit log. That layer narrows what an agent may do; it does not replace the relay policy and it does not make a hostile page trustworthy. A model advises and never authorizes. See [AI/LLM-native operation](ai-llm-native.md) and the [MCP server guide](../guides/mcp.md#the-action-gate).

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
