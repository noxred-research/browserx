# MCP server

`browserx mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server for BrowserX. It lets an AI agent (any MCP client) **watch** a worker, **explain** what its sessions did and, if you allow it, **drive** browsers through scoped tools, with a hash-chained audit log of every call. Read [AI/LLM-native operation](../design/ai-llm-native.md) first for the principle and the limits; this page is the how-to and the reference.

The server implements MCP itself (JSON-RPC 2.0, protocol revisions `2026-07-28`, `2025-06-18` and `2025-03-26` on one engine; see [Protocol revisions](#protocol-revisions)) and talks to a worker through its public HTTP API and its operations listener. For browsing it connects to a session's `cdp_url` over the same authenticated relay any CDP client uses. It does not need a model: the optional [`[ai]` endpoint](#the-optional-model-endpoint) only adds advisory tools. Actions that change a page pass a deterministic [action gate](#the-action-gate): action classes and profiles, a signed engagement manifest, signed scope grants, a session ledger and human approvals.

## Quick start

1. **Create an API key** for the MCP server on the worker, with its own quota, and put it in a file with mode `0600`:

   ```sh
   browserx keys new mcp --max-sessions 4       # add the printed snippet to the worker's configuration
   umask 077 && printf '%s\n' "bxk_..." > mcp-api-key
   ```

2. **Write the configuration** from [`examples/mcp.toml`](../../examples/mcp.toml) and check it:

   ```sh
   cp examples/mcp.toml mcp.toml            # set server.url, server.api_key_file, browse scope
   browserx mcp check mcp.toml              # validates, lists the tools it enables
   ```

3. **Point your MCP client at the command.** Clients that launch servers over stdio take the command and arguments:

   ```json
   { "mcpServers": { "browserx": { "command": "browserx", "args": ["mcp", "--config", "/etc/browserx/mcp.toml"] } } }
   ```

   `browserx mcp --config mcp.toml` serves JSON-RPC on stdin and stdout (newline-delimited, one message per line; logs go to stderr) and stops when stdin closes. `BROWSERX_MCP_CONFIG` can replace `--config`.

With no `capabilities` set, the server is read-only: the agent can monitor and explain but cannot create or change anything. Add capabilities one at a time.

## Streamable HTTP

For a client that connects over HTTP, serve it instead of (or next to) stdio:

```sh
browserx mcp token new                     # prints a bearer token once, and the configuration line
# put token_sha256 = "..." under [mcp.http], then:
browserx mcp --config mcp.toml --http 127.0.0.1:7692
```

`--http` without an address uses `mcp.http.listen`. `--stdio` serves stdio as well. The endpoint is `POST /mcp` (path configurable) with one JSON-RPC message per request, answered as `application/json`:

```sh
curl -s http://127.0.0.1:7692/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

- A bearer token is always required. Only its SHA-256 is configured (`mcp.http.token_sha256`), and the presented token is compared by digest in constant time.
- The `Origin` header, when present, must be a loopback origin or one of `mcp.http.allowed_origins` (DNS-rebinding protection). A listener bound to a non-loopback address accepts only the configured origins and logs a warning.
- Requests are bounded: bodies up to `mcp.http.max_body_bytes` (at most 4 MiB), at most `mcp.max_in_flight` requests at once (`429` beyond).
- There are no sessions and no server-initiated stream: `GET` and `DELETE` answer `405`, notifications answer `202`, an `Mcp-Session-Id` header is ignored. `GET /healthz` is an unauthenticated liveness check.
- **No TLS.** Keep the listener on loopback, or put TLS and access control in front of it.

## Protocol revisions

One engine serves three revisions of the protocol: `2026-07-28`, `2025-06-18` and `2025-03-26`. The revision is a property of each **request**, never of the connection, so the same stdio stream or HTTP endpoint answers all three.

| | `2026-07-28` (stateless) | `2025-06-18`, `2025-03-26` (handshake) |
| --- | --- | --- |
| Start | No handshake. Every request carries `params._meta` with `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities` (and, optionally, `io.modelcontextprotocol/clientInfo`) | `initialize` negotiates a version: the requested one when it is served, otherwise `2025-06-18`. The server keeps no per-connection state |
| Discovery | `server/discover` returns the supported versions, capabilities, server info and instructions | The `initialize` result |
| Results | Carry `resultType` (`complete`, or `input_required` when a human must answer) and the server identity in `_meta` | Unchanged |
| Lists | `ttlMs` and `cacheScope` say how long a client may cache them | Unchanged |
| Approvals | `input_required` with an elicitation form, when the client declared `elicitation` | A structured `approval_required` error and an out-of-band approval, see [Approvals](#approvals) |
| Screenshots | A `resource_link` | An inline image |

A request without `io.modelcontextprotocol/protocolVersion` is served with the legacy semantics. A modern request without `clientCapabilities` is refused with `-32602` (HTTP 400). A version the server does not serve is refused with `-32022` (`Unsupported protocol version`, HTTP 400); `error.data.supported` lists the versions it does serve and `error.data.requested` echoes the request.

**Caching.** `server/discover`, `resources/list`, `resources/templates/list` and `prompts/list` answer `ttlMs: 3600000` and `cacheScope: "public"`. `tools/list` does the same, except that with an [engagement manifest](#engagement-manifest) configured the list depends on the manifest's state, so it answers `ttlMs: 5000` and `cacheScope: "private"`, like `resources/read`.

**HTTP headers.** A `2026-07-28` request over HTTP must carry `MCP-Protocol-Version` (equal to the version in `_meta`), `Mcp-Method` (equal to the JSON-RPC method) and, for `tools/call` and `prompts/get`, `Mcp-Name` (equal to `params.name`) or, for `resources/read`, `Mcp-Name` (equal to `params.uri`). A header that is missing or disagrees with the body is answered with HTTP 400 and JSON-RPC code `-32020`. The `=?base64?...?=` form of a header value is decoded before the comparison. No tool argument is mirrored into a header. A legacy request may omit `MCP-Protocol-Version`; when it sends one, it must be a served version (`-32022` otherwise). A header that names `2026-07-28` binds the request to it: a body whose `_meta` does not declare that version (none, or another one) is answered with `-32020`, so a gateway that routes on `Mcp-Method` and `Mcp-Name` never sees a different call than the one that runs.

**Tracing.** A valid W3C `traceparent` in `params._meta` is accepted and its trace id is recorded as `trace_id` in the [audit entries](#audit-log) of that call. A malformed one is ignored.

A failed `resources/read` answers `-32602` to a modern request and `-32002` to a legacy one.

## Configuration reference

One TOML file with `deny_unknown_fields`. Relative paths resolve against the file's directory. Secrets are always files, never inline. [`examples/mcp.toml`](../../examples/mcp.toml) has every key with comments.

| Section and key | Default | Meaning |
| --- | --- | --- |
| `[server] url` | required | The worker's API listener (`http://` or `https://`) |
| `[server] ops_url` | none | The operations listener; needed for `pool_status`, `assess`, `diagnose` rates and readiness |
| `[server] api_key_file` | required | File with the API key (`bxk_...`); a file readable by group or others logs a warning |
| `[server] request_timeout_secs` | `30` | Timeout of calls to the worker (1 to 600) |
| `[mcp] capabilities` | `[]` | Any of `sessions`, `handoff` (needs `sessions`), `browse`, `interact` (needs `browse`), `evaluate` (needs `browse`) |
| `[mcp] reveal_endpoints` | `false` | Show the lease token and CDP URL to the model when a session is created or handed off. Leave off |
| `[mcp] max_in_flight` | `8` | Requests served at once (1 to 64) |
| `[mcp] max_result_bytes` | `262144` | Largest text block of a tool result (4096 to 4 MiB) |
| `[mcp] release_on_exit` | `true` | Release the sessions this server created when it stops |
| `[mcp.http] listen`, `token_sha256`, `allowed_origins`, `path`, `max_body_bytes` | `127.0.0.1:7692`, none, `[]`, `/mcp`, `4194304` | The HTTP transport |
| `[browse] allowed_origins` | `[]` | Exact origins the browser may visit: `https://host[:port]`, no path, query or credentials |
| `[browse] require_scope` | `true` | Refuse to start with `browse` unless `allowed_origins`, `engagement.operator` and `engagement.authorization_note` are set. With `false`, an empty `allowed_origins` allows any http(s) origin |
| `[browse] max_tabs` | `8` | Tabs per session; extra tabs a page opens are closed |
| `[browse] default_max_chars`, `max_chars_cap` | `12000`, `60000` | Character budget of snapshots, page text and script results, and the most a call may ask for |
| `[browse] command_timeout_secs`, `navigation_timeout_secs` | `20`, `30` | Per CDP command, and how long a navigation or action waits for the page to settle |
| `[browse] network_log_entries`, `console_log_entries` | `500`, `200` | Ring sizes per tab |
| `[engagement] id`, `operator`, `authorization_note` | none | Recorded in every audit entry |
| `[engagement] not_before`, `not_after` | none | RFC 3339; browsing tools are refused outside the window |
| `[sessions] max_tracked` | `4` | Sessions this server controls at once (1 to 64) |
| `[sessions] default_ttl_secs`, `max_ttl_secs` | `900`, `3600` | Lease TTL when the model names none, and the most it may ask for |
| `[audit] path` | required | The audit log |
| `[limits] sample_interval_secs` | `15` | Background metrics sampling, for rates |
| `[limits.per_minute] <tool>` | by class | Calls per minute for one tool |
| `[ai] base_url`, `model`, `api_key_file`, `timeout_secs`, `max_tokens`, `max_input_chars` | none; `60`; `1024`; `24000` | The optional chat-completions endpoint |
| `[proxy_routes.<name>] url`, `username`, `password_file` | none | A named upstream proxy a model may choose; credentials stay here |
| `[[adopt]] session_id`, `token_file` | none | An existing session this server may browse; the file holds its controller token |
| `[operator] keys_file` | none | File of operator signing keys, one `key_id = <hex>` line each (at least 16 bytes). Needed by `[manifest]`, `[grant]` and out-of-band approvals |
| `[manifest] path`, `signature_file` | none; the path plus `.sig` | The signed [engagement manifest](#engagement-manifest). Needs `[operator]`. When present it replaces the `browse.require_scope` requirement for origins, operator and authorization note |
| `[grant] path`, `signature_file` | none; the path plus `.sig` | The signed [scope grant](#scope-grants). Needs `[operator]` and `browse`. The server refuses to start when it is unsigned or wider than its ceiling |
| `[approvals] dir`, `ttl_secs` | `approvals` beside the audit log; `300` | Where out-of-band [approvals](#approvals) wait, and how long a request stays valid (30 to 3600) |
| `[safety] profile` | `test_environment` | The [action profile](#action-classes-and-profiles): `read_only`, `test_environment` or `authorized_security_test` |
| `[safety.rule_of_two] mode`, `private_network_is_sensitive` | `warn`, `true` | `off`, `warn`, `enforce` or `strict`; see [the ledger](#the-session-ledger). An absent section means `warn`, so existing configurations keep working; `examples/mcp.toml` sets `enforce` for new installs |

Default rate limits per minute: monitoring, browsing and interaction `120`, sessions and model-assisted tools `20`, `evaluate_js` `30`, engagement tools `60`.

## Tools

A tool whose capability is not enabled is **not listed**, and calling it is a protocol error (`Unknown tool`). Failures inside a tool (a refusal, a stale reference, an unreachable worker) are normal results with `isError: true` and a readable `error.kind` (`invalid_arguments`, `refused`, `rate_limited`, `approval_required`, `backend_error`, `browser_error`, `not_configured`, `internal_error`) and, for a refusal, a stable `error.detail.reason` (see [reason codes](#reason-codes)), so the model can correct itself. Arguments are validated against the schema the tool advertises; unknown arguments are rejected, not ignored.

### Monitoring (always on, read-only)

| Tool | What it returns |
| --- | --- |
| `capabilities` | What the operator enabled: capabilities, the tool names, browsing scope and engagement window, proxy route names, whether a model is configured, the sessions this server controls. Agents should call it first |
| `health` | The API (reachable, key accepted, latency) and the operations listener (`/healthz`, `/readyz` with the reasons it gives) |
| `pool_status` | Sessions by status, browsers by isolation, queue depth, relay connections, admissions, recoveries, snapshots and egress refusals over `window_secs` (default 300), and a verdict `ok`, `saturated` or `degraded` with reasons |
| `assess` | Graded checks `pass`, `warn`, `fail` with evidence and remediation: `readiness`, `queue_saturation`, `recovery_rate`, `lost_sessions`, `snapshot_failures`, `egress_refusals`. Missing metrics are reported as `warn`, never as healthy |
| `list_sessions` | Lease views of the API key's sessions (`status`, `controlled_only` filters). `controlled` marks sessions this server can drive, `mcp` marks ones created by an MCP server. Never a token |
| `get_session`, `explain_session` | One lease view; or a deterministic narrative: what the status means, what the last recovery outcome means (which state survived and which did not), the recorded reason, next steps |
| `explain_error` | What a BrowserX error code (`stale_generation`, `capacity`, `profile_locked`, ...), a relay refusal message or an MCP failure kind means and what to do |
| `list_launch_profiles`, `list_snapshots` | Launch profile names; snapshot metadata of a profile (version, size, time, writer; no contents) |

The rates behind `pool_status` and `assess` come from background samples of `/metrics` (every `limits.sample_interval_secs`) differenced over the window. A call right after start has one sample, so counts show the current state and rates appear from the second sample on.

### Sessions (capability `sessions`; `handoff` for `handoff_session`)

| Tool | Arguments | Notes |
| --- | --- | --- |
| `create_session` | `persistence`, `isolation`, `launch_profile`, `profile_id`, `proxy_route`, `ttl_secs`, `idle_timeout_secs`, `recovery`, `labels` | A subset of the session spec. The proxy is a **name** from `[proxy_routes]` (listed in the schema when any exist), never credentials. The session is labelled `mcp=true` and this server keeps its token. Refused beyond `sessions.max_tracked` |
| `renew_session` | `session_id`, `ttl_secs` | Controlled sessions only |
| `snapshot_session` | `session_id` | Snapshot persistence only |
| `release_session` | `session_id`, `confirm` | Needs `confirm: true`. Works for controlled sessions and, after a restart of this server, for sessions labelled `mcp=true` (as the key's owner) |
| `handoff_session` | `session_id`, `confirm` | Needs `confirm: true`. Rotates the controller token: any token and CDP URL issued before stop working and their relay connections close. The new token stays inside this server |

Sessions this server created are released when it stops (`mcp.release_on_exit`). Tokens live only in memory: a created session that outlives the process can no longer be browsed, but can still be released by its label.

### Browsing (capability `browse`)

All browsing tools take `session_id` of a controlled session and an optional `tab_id` (`t1`, `t2`, ... from `list_tabs`; default the current tab). Calls on one session run one at a time. If the browser behind the session was recovered since the last call, the first call reconnects through `attach` and returns a `notice` that says what the recovery outcome means (for example, that cookies came back but JavaScript state did not) and that earlier element refs are invalid.

| Tool | What it does |
| --- | --- |
| `open_page` | Navigates (`url`, `new_tab`). Only `http` and `https`; the origin must be in scope; the final origin after redirects must be too |
| `page_snapshot` | The accessibility tree as compact text with stable refs (see below). `max_chars`, `interactive_only`, `since`, `include_hidden` |
| `find_in_snapshot` | Refs of elements in the latest (or a given) stored snapshot whose accessible name or value contains `text` and/or whose `role` matches; `limit` (default 20, at most 100), `snapshot_id`. Takes a snapshot when the tab has none |
| `page_text` | Readable Markdown of the main content: headings, paragraphs, lists, tables, links (targets kept, image sources dropped). `max_chars` |
| `screenshot` | PNG of the viewport or, with `full_page`, the page (at most 16000 px tall), returned as a `resource_link` to `browserx://screenshots/{id}` for `2026-07-28` requests and as inline MCP image content for older ones. At most 2 MiB |
| `list_tabs`, `switch_tab`, `close_tab` | Tabs with URL, title, current marker and whether each is in scope |
| `go_back`, `go_forward` | History navigation; the landing page must be in scope |
| `wait_for` | Waits for `text` in the page or an element `ref` (or, with `gone: true`, for it to disappear); `timeout_ms` at most 30000 |
| `network_log` | Recent requests of the tab: method, URL, status, resource type, MIME type, size. No bodies, no headers. `limit`, `url_contains`, `resource_type`, `failed_only` |
| `console_log` | Recent console messages and uncaught exceptions. `limit`, `level` |

#### Snapshots and element references

`page_snapshot` renders the accessibility tree (`Accessibility.getFullAXTree`), with the trees of same-process frames merged in:

```text
page "Test Site"
  heading "Test Site" (level=1)
  text "Welcome to the lab."
  [e1] link "Go to page two"
  [e2] textbox "Search" value="lab rats" (required)
  [e3] button "Find"
  [e4] combobox "Color" value="Red"
  frame "https://app.example.test"
    [e5] button "Pay"
  frame "https://ads.example.test" (content not captured: cross-process frame)
```

Interactive elements carry a ref (`e1`). A ref is keyed by the element's DOM node, so the same element keeps its number across snapshots until the page navigates; navigation clears every ref. Every interaction **re-resolves** its ref against the live tree and refuses it when the element is gone or its role or accessible name changed since the snapshot (`ref e1 is stale ...`, with `stale_ref: true` in the error detail): take a new `page_snapshot`. Names are cut at 160 characters and values at 120.

- **Snapshot ids and deltas.** Every snapshot has a `snapshot_id` (`s3`, increasing per tab) in the metadata and the text header. The tab remembers its last eight snapshots (at most 20 000 nodes each; a larger page is cut and marked `truncated`) and forgets them when it loads a new document. `since: "s3"` returns only what changed against that snapshot, rendered with the same options: `+` added and `~` changed lines (indented by depth so they can be placed), a `- [removed] N nodes (refs: e4, e9)` summary and `N unchanged nodes omitted`. An unknown, evicted or incomparable id returns the full snapshot with `since_unknown: true`.
- **Frames and shadow roots.** Each frame boundary is a line `frame "<origin>"`, and the content under it belongs to that origin; in `interactive_only` lists each ref line says `(in frame "<origin>")`. Refs inside same-process frames work with the interaction tools. A frame the browser keeps in another process (a cross-site frame) is listed as `(content not captured: cross-process frame)`; a frame whose origin the read scope refuses is listed as `(content withheld: outside the read scope)` and none of its text is returned. Open shadow roots are part of the tree.
- **Hidden text.** Text a user cannot see is left out unless `include_hidden` is true: zero-size clipped boxes, opacity 0, font size 0, text of the same colour as its effective background, boxes far outside the document (the `text-indent: -9999px` family) and everything under `aria-hidden`. The metadata reports `hidden_omitted` and `hidden_detection` (`ok`, `skipped_too_large` above 100 000 DOM nodes, or `unavailable`). Detection is best effort: it reads computed styles and layout boxes, not pixels.
- **Truncation.** When `max_chars` is reached the text ends with `[truncated at N characters: M more nodes not shown; narrow with interactive_only/find_in_snapshot or raise max_chars]`.

### Interaction (capability `interact`)

| Tool | What it does |
| --- | --- |
| `click` | Scrolls the element into view, finds the center of its box and sends mouse move, press and release events |
| `type_text` | Focuses the element and inserts `text` (at most 4000 characters), optionally replacing its content (`clear`) and pressing Enter (`submit`) |
| `press_key` | A key press with optional `modifiers`: a single character, or `Enter`, `Tab`, `Escape`, `Backspace`, `Delete`, `ArrowUp`, `ArrowDown`, `ArrowLeft`, `ArrowRight`, `Home`, `End`, `PageUp`, `PageDown`, `Space` |
| `select_option` | Chooses an option of a `<select>` by `value` or visible `label` |
| `scroll` | Mouse-wheel scroll by `direction` and `amount` (at most 5000 px), or `to` the top or bottom; returns the scroll position |
| `hover` | Moves the pointer over the element |

Each interaction reports the URL and title afterwards, whether a new document loaded (`navigated`) and whether the page settled, and enforces the scope again.

### Script (capability `evaluate`, off by default)

`evaluate_js` runs a JavaScript expression in the page (promises are awaited, five seconds at most) and returns the bounded JSON value. Script can read everything the page can and can call other origins; the scope guard covers top-level navigation, not requests a script makes. Enable it only when you need it.

### Tool descriptors and results

- **Deterministic list.** `tools/list` is sorted by tool name, so the same configuration always lists the same tools in the same order.
- **Descriptors.** Each tool has a `title`, an `inputSchema`, an `outputSchema` and `annotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`). The annotations are set truthfully but they are **hints for clients**: the server never uses them for enforcement, and neither should you.
- **Structured results.** A successful call returns `structuredContent` that validates against the tool's `outputSchema` (the schema lists the stable members; others may be present) and a text block with the same JSON, for clients that do not read structured content. A result whose JSON exceeds `mcp.max_result_bytes` keeps only the truncated text. Page-derived text is never part of `structuredContent`; it is a separate, wrapped text block.
- **Failures.** A refusal, a validation error against the argument schema, a rate limit or an approval request is a result with `isError: true` and `structuredContent.error` (`kind`, `message`, and `detail` with a stable `reason` code such as `out_of_scope` or `unsigned_manifest`; see [reason codes](#reason-codes)). Only an unknown or unlisted tool is a protocol error.
- **Screenshots.** For a `2026-07-28` request `screenshot` returns a `resource_link` to `browserx://screenshots/{id}` (MIME type `image/png`, also `resource_uri` in the structured result); `resources/read` on it returns the PNG as a base64 `blob`. The server keeps the last 16 screenshots (and at most 24 MiB of encoded data); an older link answers resource-not-found. A legacy request gets the image inline, as before.
- **Approvals.** The tools that can ask for an approval (`open_page`, `click`, `type_text`, `press_key`, `select_option`, `evaluate_js`) accept an extra `approval_id` argument; see [Approvals](#approvals).

### Engagement tools

Always listed (except `propose_scope_grant`): they let a model see its own situation and ask for less. Nothing here widens anything.

| Tool | Arguments | What it does |
| --- | --- | --- |
| `engagement_status` | `handle` | Shows the session ledger: the Rule of Two flags `A`, `B`, `C` with the events that set each, the policy (`rule_of_two` mode and profile), the number of calls, the state of the [engagement manifest](#engagement-manifest) (status, digest and, when it is signed, id, impact, `not_after` and hosts with their modes) and of the [scope grant](#scope-grants) (digest, origins, tools, actions, plan digest and steps). Call it before consequential work |
| `reset_context` | `approval_id` | Retires the caller's handle, mints a fresh one with clean flags and invalidates every element ref. While the handle holds untrusted input or sensitive context it needs a human [approval](#approvals) under `enforce` and is refused under `strict`; see [the ledger](#the-session-ledger) |
| `propose_scope_grant` | `ro_origins`, `rw_origins`, `allowed_tools`, `allowed_actions`, `plan`, `not_after`, `calls`, `time_secs`, `reason` | Proposes a **narrower** grant for the operator to review. Listed only when `[operator]` and `browse` are configured; see [Scope grants](#scope-grants) |

### The optional model endpoint

Add `[ai]` to enable three advisory tools. Without it they are not listed and everything else is unchanged.

| Tool | What it does | Fallback when the model is unreachable or answers badly |
| --- | --- | --- |
| `summarize_page` | Summary and key points of the page's main content (needs `browse`) | The title, headings and lead paragraphs, `source: extractive_fallback` |
| `extract_data` | Structured data for a JSON Schema you give (`type: object`, `properties`), validated against it (needs `browse`) | `label: value` lines and table rows matched to property names and coerced to their types, `method: heuristic_fallback`, with a `missing` list |
| `diagnose` | `assess` plus an explanation of a session (`session_id`), with a narrative | The deterministic findings are always included; the narrative is assembled from them, `narrative_source: deterministic` |

The endpoint is any chat-completions compatible service: `base_url` gets `/chat/completions` appended unless present. Requests use temperature 0 and ask for JSON that matches a schema; answers are validated and rejected when they do not match. The key goes only in the `Authorization` header, redirects are not followed, responses are size-capped and neither prompts nor answers are logged. The result always says whether the model was used (`llm.used`, and `llm.reason` when it was not). **The model sees what the tool sends it**: redacted, untrusted-wrapped page content for the first two, and the deterministic findings for `diagnose`.

## Resources and prompts

**Resources.** `resources/list` returns the documentation bundled into the binary at build time, `browserx://docs/sessions`, `persistence`, `recovery`, `handoff`, `security`, `egress` and `mcp` (Markdown), and `browserx://sessions/<id>` for each session this server controls. `resources/templates/list` advertises `browserx://sessions/{id}`, which reads any of the key's sessions as a lease view (JSON, no token).

**Prompts.** `triage_session` (what state is this session in and what should I do), `capacity_review` (is the pool saturated, what holds capacity, what to change) and `explore_authorized_site` (the snapshot, act, observe loop with the scope and untrusted-content reminders).

## The action gate

Every tool that touches a page passes one deterministic gate before it runs. No model takes part: the gate reads configuration, signed documents and what the page says about the element, and it answers *allow*, *needs an approval* or *refuse*. The order is fixed:

1. the **profile** in force: `[safety] profile`, narrowed by the engagement manifest (`observe` impact and `visit` hosts make it read-only);
2. the scope grant's allowed action classes;
3. the manifest's **protected requests**, which are never allowed, whatever the class;
4. the profile's decision for the action's class: allow, approval or deny;
5. the grant's **plan**;
6. the **Rule of Two**, for consequential calls;
7. an **approval**, when one is needed, bound to the exact action.

Models advise and act through these tools; they never authorize. The gate is what authorizes, and every refusal carries a stable [reason code](#reason-codes).

### Action classes and profiles

Before acting on an element the server collects fixed facts about it from the page (its role, accessible name, the form it submits, the URL it opens, whether it is inside a frame) and derives one **action class**:

| Class | Meaning |
| --- | --- |
| `read` | Looking or expanding; nothing changes in the application |
| `navigate_in_scope` | Opening a page inside the scope |
| `navigate_out_of_scope` | Opening a page outside the scope |
| `form_edit` | Editing a field or choosing an option, without submitting |
| `submit_state_change` | Submitting a form that changes server state |
| `credential_entry` | Entering or submitting credentials |
| `external_communication` | Sending something to a person or publishing it (`mailto:`, `tel:`, a form that posts out of scope, a "send" button) |
| `destructive` | Deleting, deactivating, revoking, ending a session (a logout counts) |
| `payment` | Spending money |
| `file_transfer` | Uploading or downloading a file |
| `unknown` | The effect cannot be determined; read the strict way |

`[safety] profile` (default `test_environment`) maps each class to a decision:

| Class | `read_only` | `test_environment` | `authorized_security_test` |
| --- | --- | --- | --- |
| `read`, `navigate_in_scope` | allow | allow | allow |
| `navigate_out_of_scope` | deny | deny | deny |
| `form_edit`, `submit_state_change` | deny | allow | allow |
| `credential_entry` | deny | approval | approval |
| `external_communication` | deny | approval | approval |
| `destructive` | deny | approval | approval |
| `payment` | deny | deny | deny |
| `file_transfer` | deny | approval | approval |
| `unknown` | deny | approval | allow |

*approval* means the call does not run until a human approves it ([Approvals](#approvals)); *deny* is a refusal with `profile_denied`. `evaluate_js` has no element to classify: it is allowed unless the profile is `read_only`, and it always counts as consequential for the [Rule of Two](#the-session-ledger).

**How the class is derived.**

- **Structure first.** What the control does decides: a submit control of a POST, PUT, PATCH or DELETE form is a state change (raised to `credential_entry` when the form has a password field, to `file_transfer` when it has a file input, to `external_communication` when its action leaves the scope); a submit in a GET form is a navigation; `mailto:`, `tel:` and `sms:` links are external communication; a `javascript:` link is `unknown`; a `download` attribute or an archive or binary file extension is a file transfer; password, `current-password`, `new-password` and `one-time-code` fields are credential entry and `cc-*` fields are payment; a plain button or menu item with no form and no `href` has no visible effect and is `unknown` unless its label says more; controls inside embedded frames are `unknown`; Enter in a form field submits the form, and Enter in a field with no form is `unknown`.
- **Language can only raise the class.** A small static table of verbs (currently English, French, German, Spanish, Italian, Portuguese, Dutch, Turkish, Chinese, Japanese, Korean and Russian) is matched on the label and on the URL path. A hit raises the class only together with structural evidence that the control acts: a submit control of a non-GET form, or a plain actuator. A destructive word on an ordinary link to an in-scope page stays a navigation, unless the URL path itself says `/logout` or `/delete`.
- **Contradictory evidence gives the stricter class.** A button labelled "Cancel" that posts a form to `/account/delete` is `destructive`; no label ever lowers a class. A disabled control is classified as if it were enabled.

The decision table and the classifier cases are pinned by test vectors in `crates/browserx-mcp/tests/vectors/classifier`.

**Which tools are gated.** `click`, `type_text`, `select_option` and `press_key` with `Enter` or `Space` (classified from the focused element) are classified per element. Other `press_key` keys count as `form_edit`. `evaluate_js` is gated as above. `open_page` carries the [exfiltration guard](#scope-grants), and `go_back` and `go_forward` are `navigate_in_scope`. The remaining browsing tools (`page_snapshot`, `find_in_snapshot`, `page_text`, `screenshot`, `wait_for`, `network_log`, `console_log`, `scroll`, `hover`, and the tab tools) are `read` class: they still pass the grant, plan and manifest checks but need no approval. A call is **consequential**, and therefore subject to the Rule of Two, when its class is `submit_state_change` or stricter (that is, `unknown`, `credential_entry`, `file_transfer`, `external_communication`, `destructive`, `navigate_out_of_scope`, `payment`), and for `evaluate_js`.

### Approvals

A call that needs a human does not run. How it answers depends on the request.

**1. Multi round-trip (a `2026-07-28` request from a client that declared `elicitation`).** The result is `resultType: "input_required"` with an `inputRequests.approval` elicitation form (one boolean, `approve`; the message names the action class, the tool, the page, the origin and the reasons; it carries page-derived text, so it is redacted and bounded like a result, and quotes and invisible or direction-changing characters in an element's name are escaped or dropped) and an opaque `requestState`. The state is sealed with AES-256-GCM under a key generated randomly when the server process starts, and it is bound to the caller (principal), the tool, a digest of the request (tool and arguments, without `approval_id`), a digest of the exact action to approve, an expiry (`approvals.ttl_secs`, default 300) and a random nonce. The client shows the form to the user and retries the **same request** with `requestState` and the answer:

```json
{"name": "type_text", "arguments": {"...": "..."}, "requestState": "<state>",
 "inputResponses": {"approval": {"action": "accept", "content": {"approve": true}}}}
```

The server verifies the state, consumes its nonce (a state works once), recomputes the action digest (a page that changed in between is a different action and gets a new request) and runs the call once. A declined answer ends in `approval_declined`; state that was altered, issued to another caller, for another request or sealed by an earlier process ends in `approval_invalid`; expired or already used state gets a fresh request.

**2. Out-of-band (legacy requests, or a client without `elicitation`).** The result is an error with `kind: "approval_required"` and `detail` carrying `approval_id` (`apr_` and 24 hex digits), `action_class`, `origin`, `reasons`, `expires_in_secs` and instructions. The request waits as `<id>.pending.json` in the approvals directory (`[approvals] dir`, default `approvals` beside the audit log; mode `0700`, files `0600`; at most 256 pending, at most 16 per caller). The same caller asking again for the same call gets the same `approval_id`, so a loop does not multiply requests or use up the room of other callers. The operator reviews and approves it with the operator key:

```sh
browserx mcp approvals list --config mcp.toml
browserx mcp approvals approve apr_0123456789abcdef01234567 --config mcp.toml
```

`approve` signs the record (HMAC-SHA256, domain `browserx/approval/v1`) and writes `<id>.approved`. The client then calls the **same tool with the same arguments** and `approval_id`; until the operator has approved, the answer is `approval_required` with `status: "pending"`. A signed record is single use across processes (the approval is renamed before the call runs, and the pending record is retired with it: a used id is no longer listed, cannot be approved again and does not run the action a second time), is bound to the caller and the request, and expires after `approvals.ttl_secs`. Verifying an approval needs `[operator]`: without it the server answers that no approval can be verified.

`confirm: true` is an intent flag the model sets about its own call. It is never an approval. What needs a human is decided by the action class, the profile, the Rule of Two and the exfiltration guard; `error.detail.reasons` lists why (`profile.<class>`, `rule_of_two`, `exfiltration_guard`). The summary a human sees quotes the element's accessible name as bounded, control-free text: it is page content, so read it as such.

### Engagement manifest

The manifest is the operator's rules of engagement as one signed file: who is testing under which authorization and when, which hosts may be attacked, only visited or never touched, which requests are protected, how much impact is allowed and how fast. The server reads it at startup and judges its signature offline.

```toml
[operator]
keys_file = "./operator.keys"          # one `key_id = <hex>` line per key, each at least 16 bytes

[manifest]
path = "./engagement.toml"
# signature_file = "./engagement.toml.sig"    # default: the path plus .sig
```

```sh
browserx mcp operator-key new ops-2026 >> operator.keys && chmod 600 operator.keys
browserx mcp manifest sign engagement.toml --keys operator.keys [--key-id ops-2026]
browserx mcp manifest verify engagement.toml --keys operator.keys [--signature engagement.toml.sig]
```

`operator-key new` prints a key line (32 random bytes) once; key ids are 1 to 64 characters without whitespace, `:` or `=`, and `#` starts a comment in the key file. `sign` checks that the manifest parses and writes `engagement.toml.sig` next to it (one line, `key_id:<hex>`); `sign` always writes `<path>.sig`: when `[manifest] signature_file` names another file, move it there. `verify` prints the engagement, the operator, the key that signed, the digest, the impact, the hosts and whether the manifest is active now. The signature is the HMAC-SHA256 of the **exact bytes** of the file under the operator key, domain separated by `browserx/engagement-manifest/v1\0`: changing one byte, for example `not_after`, invalidates it. It is a symmetric MAC: the key that verifies can also sign, so keep the key file readable only by the operator account and the MCP process.

```toml
[engagement]
id = "ENG-2026-014"
operator = "alice"
authorization_note = "Written authorization, ticket SEC-1234, scope document v3"
not_before = "2026-01-05T00:00:00Z"        # optional, RFC 3339
not_after = "2026-03-31T23:59:59Z"

[[scope]]
host = "app.example.test"                  # host, host:port or *.suffix
mode = "attack"                            # attack | visit | blocked

[[scope]]
host = "docs.example.test"
mode = "visit"

[[scope]]
host = "admin.example.test"
mode = "blocked"

[[protected]]
pattern = "POST /admin/*"                  # METHOD glob; * matches any text
mode = "blocked"

[impact]
level = "probe"                            # observe (default) | probe | demonstrate

[limits]
rps = 5                                    # page-touching calls per second
max_calls = 2000                           # page-touching calls in total

[windows]
allow = ["Mon-Fri 09:00-17:00 UTC"]        # recurring windows, UTC only
```

`id`, `operator` and `authorization_note` are required and non-empty; unknown keys are rejected. Host patterns are case-insensitive; `*.example.test` matches subdomains but not `example.test` itself; without a port a pattern matches any port. When several entries match a host, `blocked` wins over `visit` and `visit` over `attack`; a host that no entry names is out of scope. Host patterns may be IDN names (matched by their punycode form) and bracketed IPv6 literals (`[::1]`, `[::1]:8080`). A protected pattern is `METHOD glob` (`*` as the method means any); the glob is matched against the request the way a server routes it: letter case is ignored, percent-escapes are decoded (also when escaped twice), `.` and `..` segments, `;parameters`, repeated slashes and a trailing slash do not matter, and the query is kept apart from the path, so `POST /account/delete` also protects `/Account//Delete/?x=1` and `/account/%64elete`. A glob is matched against the full URL and, when it starts with `/`, against the path (a glob that names a query, such as `/search?q=*`, matches it). At most 256 `[[scope]]` and 256 `[[protected]]` entries. A manifest without `[impact]` is `observe`.

**What the manifest does.**

| Situation | Effect |
| --- | --- |
| Signed and in its window | Its hosts are the browsing scope when `browse.allowed_origins` is empty, and the **intersection** with it otherwise. It replaces the `browse.require_scope` requirement for `allowed_origins`, `engagement.operator` and `engagement.authorization_note`: the manifest carries them. A host the manifest does not list is `out_of_scope`; a `blocked` host is `blocked_host` |
| `visit` host | Read-only: the profile is narrowed to `read_only` on its pages, and changes are refused with `visit_only` |
| `impact = "observe"` | The profile is narrowed to `read_only` everywhere (`impact_ceiling`) |
| `impact = "probe"` | Destructive, credential, external-communication and file-transfer actions are refused (`profile_denied`); other classes follow the profile |
| `impact = "demonstrate"` | Whatever the profile and approvals allow |
| A `[[protected]]` request | Refused with `blocked_protected`, whatever the class: page loads (as `GET`), the requests that an action would send (a link, a form submit, or the request of a form's default button when Enter is pressed in a field), and, at the network, any document request the page makes with its real method (a script that submits a protected `POST` is held back) |
| `limits.rps`, `limits.max_calls` | Page-touching calls over the rate are refused with `rate_limited`; calls beyond the total with `budget_exhausted` |
| Unsigned, or the signature does not verify | The manifest is inert: it widens nothing and its hosts are not used as scope. The tools that change pages (`click`, `type_text`, `press_key`, `select_option`, `scroll`, `hover`, `evaluate_js`) are **unlisted** and refused with `unsigned_manifest` |
| Before `not_before`, after `not_after` or outside `windows` | The same tools are unlisted and refused with `window_closed`, and so is every other tool that touches a page |

The manifest's id, operator and authorization note replace the `[engagement]` values in the audit log when it is signed, and the manifest's SHA-256 (`manifest_digest`) and state (`engagement_status`: `active`, `not_started`, `expired`, `outside_windows`, `unsigned` or `invalid_signature`) are part of every audit entry. `limits.max_cost_usd`, `[stop]` and `budgets.cost_usd` in a grant are not supported yet: a manifest or grant that contains them is refused (at `manifest sign`, `grant sign` and at startup) with a "not supported yet" error instead of being ignored.

### Scope grants

A grant narrows a session further than the manifest: which origins it may read, where it may act, which tools and action classes it may use, how much it may do and, optionally, in which order. It is signed like the manifest.

```toml
[operator]
keys_file = "./operator.keys"

[grant]
path = "./grant.toml"
# signature_file = "./grant.toml.sig"
```

```sh
browserx mcp grant sign grant.toml --keys operator.keys
browserx mcp grant verify grant.toml --keys operator.keys
```

The commands work like their manifest counterparts: `sign` writes `grant.toml.sig` next to the file and the signature is domain separated by `browserx/scope-grant/v1\0`.

```toml
[grant]
engagement = "ENG-2026-014"                # must name the manifest's (or [engagement]'s) id
principal = "*"                            # default *; or the caller, e.g. stdio
ro_origins = ["https://docs.example.test"] # content may be read here
rw_origins = ["https://app.example.test"]  # actions allowed here; content may be read too
allowed_tools = ["open_page", "page_snapshot", "click", "type_text"]   # empty: every enabled tool
allowed_actions = ["read", "navigate_in_scope", "form_edit"]           # empty: every class the profile allows
not_before = "2026-01-05T00:00:00Z"
not_after = "2026-02-01T00:00:00Z"

[budgets]
calls = 200                                # page-touching calls per handle
time_secs = 3600                           # seconds from the handle's first call

[[plan]]                                   # optional ordered steps
tool = "open_page"
origin = "https://app.example.test"        # default *
action_class = "navigate_in_scope"         # default *
max_count = 2                              # default 1
```

The server **refuses to start** when the grant is unsigned, malformed, or wider than its ceiling: a different engagement id, an origin the manifest does not allow (or a read-write origin on a `visit` host) or that is not in `browse.allowed_origins`, more calls than the manifest's `limits.max_calls` (the grant must set `budgets.calls` when the manifest does) or a `not_after` later than the manifest's. Running without a restriction the operator asked for would widen access silently, so it is an error, not a warning.

**What a grant does.**

- **Read and write origins.** Content from an origin outside `ro_origins` and `rw_origins` is never returned: navigation there is refused (`origin_not_in_rw`) and a frame from such an origin appears in a snapshot only as a placeholder, `(content withheld: outside the read scope)`. A `screenshot` of a page that embeds a frame from such an origin is refused with `frame_not_in_ro`, because pixels cannot be filtered by origin. Read-only origins can be read but are not places to act: `type_text`, `select_option`, `press_key`, `click` (whatever its class) and `evaluate_js` on a page of an origin outside `rw_origins` are refused with `origin_not_in_rw`. A `screenshot` also looks for frames in other processes (cross-site iframes are not in the page's frame tree): their owner elements and the browser's frame targets are listed, and a frame whose URL the browser does not report is refused too. Every top-level request, redirect hops included, is checked against the same rule.
- **URLs built by the model.** The URL argument of `open_page` must be a read-write origin, or an origin the grant lets the session read **and** whose URL was literally seen as a link or form action on a readable page. A URL that carries a secret-looking value (a known credential prefix, a JWT, a long hex string or a long high-entropy token in a query key or value, a path segment or a fragment, as written or percent-decoded) is refused with `origin_not_in_rw` unless it goes to a read-write origin; to a read-write origin it needs an [approval](#approvals) (`exfiltration_guard`) unless the same URL was seen on a page. Independently of any grant, a URL that contains a value the redactor recognizes as a secret is refused with `secret_in_url`.
- **Tools, actions and principal.** `tool_not_granted`, `action_not_granted` and `principal_not_granted` refuse what the grant does not list.
- **Budgets.** `budget_exhausted` refuses a call beyond `calls` or `time_secs` of the caller. Budgets belong to the principal, not to a handle: `reset_context` does not refill them.
- **Plan.** Steps run in order for each principal: a call must match a step (tool, origin, class) at or after the current position with uses left, and using a later step closes the earlier ones; `reset_context` does not rewind it. A step's `origin` is stored in the normalized form of a page's origin (`https://App.test:443/` is `https://app.test`). A call outside the plan is refused with `outside_plan`, so page content can change data but not which tools run. The plan's digest is part of every approval and audit entry.
- **Window.** Outside `not_before` and `not_after` page-touching tools are refused with `window_closed`.

**Proposals.** A model may ask for less with `propose_scope_grant` (listed only when `[operator]` and `browse` are configured). The proposal is checked against the ceiling: the manifest's hosts, `browse.allowed_origins`, the active grant (tools and actions cannot be added), `limits.max_calls` and the earliest `not_after`. A proposal that widens anything is refused with `proposal_widens_ceiling` and the list of violations in `error.detail.violations`. A narrowing one is written to `<approvals dir>/proposals/<digest prefix>.toml` (mode `0600`) and answered with `active: false`, the digest and the file; it does nothing until the operator reviews it, runs `browserx mcp grant sign` on it and points `[grant] path` at it for the next start.

### The session ledger

The Rule of Two says that within one session an agent should have at most two of three properties. The server tracks them per **handle** and makes the third a decision:

| Flag | Meaning | Set by |
| --- | --- | --- |
| `A` | Untrusted input was ingested | Any tool result that returned untrusted-wrapped page content |
| `B` | Sensitive context is in play | `create_session` with `persistence` `snapshot` or `profile`, with a `profile_id` or with a `proxy_route`; use of an adopted session; a target on a private network (loopback, private, link-local and carrier-grade NAT addresses, `localhost`, `.local`, `.internal`, `.lan`) while `private_network_is_sensitive` is `true` |
| `C` | A tool that changes pages can run | The `interact` or `evaluate` capability is enabled: every handle starts with `C` set |

Flags only turn on within a handle; nothing, no model and no tool, turns one off. `reset_context` retires the handle and mints a fresh one (`hnd_` and 24 hex digits), which is the only way to start again; it does not make the model forget what it already read, so start a fresh context window as well. Because a fresh handle clears the flags, a model that could reset on its own could step out of the Rule of Two, so once the handle holds untrusted input (A) or sensitive context (B) the reset needs a human [approval](#approvals) under `enforce` (reason `reset_context`, class `context_reset`) and is refused with `reset_refused` under `strict`; `off` and `warn` leave it free. A reset also invalidates every element ref (the new context reads the page again before it acts), and it does not touch what the principal spent: the call count, the time budget and the plan progress of a [scope grant](#scope-grants) belong to the principal, not to the handle. A session created with persistent state, a `profile_id` or a proxy route keeps its sensitivity: every use of it sets B again, whichever handle or principal makes it. The text and the pixels of a page both count as untrusted input (A): a `screenshot` sets it too. A handle belongs to the principal that created it (`stdio`, or `http:` and a digest prefix of the bearer token): another principal's handle and a forged one are both answered with `unknown_handle`. The ledger lives in memory, keeps at most 256 handles, and a restart of the server forgets every handle.

When all three flags are set and a call is consequential, `[safety.rule_of_two] mode` decides:

| Mode | Effect |
| --- | --- |
| `off` | Not applied |
| `warn` | The call proceeds; the audit entry records `rule_of_two: "warn"` |
| `enforce` | The call needs an [approval](#approvals) (reason `rule_of_two`) |
| `strict` | The call is refused with `rule_of_two`; only the operator can start a fresh context (restart the server) |

An absent `[safety.rule_of_two]` section means `warn`, so existing configurations keep working; `examples/mcp.toml` sets `enforce` for new installs.

Every audit entry carries `handle`, `abc` (the three flags), `action_class` (and `action_rules`, the rule ids that produced it), `reason` for a refusal, `trace_id` when the client sent one, `engagement_status` when a manifest is configured, and the digests of the manifest, the grant and the plan.

### Reason codes

A refusal carries its code in `error.detail.reason` and in the audit entry's `reason`. An approval request lists its causes in `error.detail.reasons`.

| Code | Meaning |
| --- | --- |
| `out_of_scope`, `blocked_host`, `invalid_url` | The origin is outside the scope or the manifest; the host is `blocked` in the manifest; the URL is not an absolute http(s) URL, is too long or carries credentials |
| `blocked_protected` | The request matches a `[[protected]]` pattern of the manifest |
| `unsigned_manifest`, `window_closed` | The manifest is unsigned or invalid; the engagement, manifest, grant or a recurring window is closed |
| `visit_only`, `impact_ceiling`, `profile_denied` | A change on a `visit` host; the manifest's impact is `observe`; the profile denies the class |
| `origin_not_in_rw`, `frame_not_in_ro`, `exfiltration_guard`, `secret_in_url` | The grant's origin and URL rules, and the secret checks |
| `tool_not_granted`, `action_not_granted`, `principal_not_granted`, `outside_plan`, `budget_exhausted` | The grant's tool, class, principal, plan and budget limits (and the manifest's `max_calls`) |
| `rule_of_two` | All three flags are set: refused in `strict`, an approval reason in `enforce` |
| `approval_declined`, `approval_invalid` | The human said no; the approval evidence was altered, issued to another caller or for another request |
| `unknown_handle`, `proposal_widens_ceiling` | The ledger handle does not exist or is not the caller's; a grant proposal widens its ceiling |

## Safety model

The [design page](../design/ai-llm-native.md#how-the-limits-are-enforced) explains why. In practice:

- **Scope.** `open_page` refuses a URL outside `browse.allowed_origins` before touching the browser. While a tab is attached, the server also asks the browser to hold each top-level document request until its URL has been compared with the scope, so an out-of-scope redirect hop or link target is blocked **before it is sent** and the tab stays on its previous page. After a page settles, its final URL is checked again; a landing outside the scope resets the tab to `about:blank`. A tab that a page opened itself (a popup) and that sits outside the scope is refused and reset the first time it is used. Sub-frames and sub-resources are not held.
- **Engagement window.** Outside `not_before` and `not_after`, every browsing, interaction and model-assisted page tool is refused.
- **Untrusted content.** Page-derived text (page text, snapshots, network and console logs, tab titles, script results, summaries) is wrapped as `<untrusted_page_content origin="..." nonce="...">`. Every call draws a fresh 64-bit nonce that closes the block (`</untrusted_page_content nonce="...">`) and whose first eight hex digits start every line of the block (`1a2b3c4d| `), so a page can predict neither the closing tag nor the line marker. The wrapper's tags, the marker and the nonce are also neutralized inside the text. Trusted metadata (counts, ids, flags) is returned separately as structured content and never contains page text.
- **No secrets to the model.** Tool results, prompts and the audit log are scrubbed of the API key, the model key, proxy passwords, lease tokens (`bxt_...`), `bxk_...` keys, `Bearer` values and URL credentials. Members named like secrets are replaced. With `mcp.reveal_endpoints = true` the token and CDP URL of a created or handed-off session are appended as a separate text block, never in structured content.
- **Confirmation.** `release_session` and `handoff_session` need `confirm: true`. The flag states the model's intent; it is never an approval.
- **Action gate.** Element interactions are classified and decided by the profile; riskier ones, and consequential ones once all three Rule of Two flags are set, need a human approval ([The action gate](#the-action-gate)).
- **Signed rules of engagement.** An operator-signed manifest and an optional signed grant narrow hosts, impact, origins, tools, budgets and steps. Unsigned or altered documents widen nothing.
- **Rate limits and budgets.** Per-tool calls per minute (a refusal says how long to wait), `mcp.max_result_bytes` per text block with a truncation notice, bounded tabs, logs and in-flight requests.
- **Calls that change something run to completion.** The server records an `intent` entry first (the call is refused if the audit log cannot be written), then runs the call even if the client cancels the request, then records the result.

### Security notes

- **Models advise; they never authorize.** Nothing a model writes (tool arguments, a `confirm` flag, a grant proposal, text it read on a page) changes the scope, the profile, the manifest, a grant or an approval. Those come from files the operator controls and signs, and from a human's answer.
- **Page content is untrusted.** The wrapper and the instructions make a hostile page less likely to steer the model; they do not make it impossible. What holds when a model is steered is the gate: out-of-scope requests, protected requests and refused classes are refused in code, secrets are not present, and consequential calls wait for a human.
- **The client shows the approval.** The server can ask for an approval but cannot make a client display the prompt to a person. A client that answers elicitation requests by itself defeats the multi round-trip route; use a client that shows the form to the user, or the out-of-band route, which needs the operator's signature.
- **Annotations are hints.** `readOnlyHint`, `destructiveHint` and the others describe a tool to a client. The server enforces nothing from them.
- **The classifier reads what the page says.** A page can mislabel a control, but evidence only ever raises the class, so a label can make an action look riskier, never safer. A control whose effect is invisible in the page (a plain button whose script spends money) is classed `unknown`, which `authorized_security_test` allows. `evaluate_js` can do anything the page can; leave it off unless you need it.
- **Signatures are MACs.** The operator key signs and verifies. Keep its file readable only by the operator account and the MCP process.
- **A local server, not a service.** It is one process: the ledger, the budgets and plan progress and the sealing key of approval state live in memory, so a restart forgets handles and pending multi round-trip approvals (signed out-of-band records stay on disk until they expire), and several processes do not share them. There is no high-availability mode. The HTTP transport has no TLS: keep it on loopback or put TLS and access control in front of it.
- **No evasion.** The gate only narrows what an agent may do. Nothing in the server hides the browser from a site or works around a site's protections.

## Audit log

`audit.path` is a JSONL file created with mode `0600`. Every tool call adds a `result` entry; calls that change something (sessions, navigation, interaction, script, tab changes) add an `intent` entry before they run. Refused and invalid calls are recorded too.

```json
{"seq":7,"ts":"2026-03-02T09:14:03Z","prev":"3f1c...","hash":"9a60...","phase":"result",
 "caller":{"transport":"stdio","client_name":"my-client","remote":null,"principal":"stdio"},
 "context":{"engagement":"ENG-2026-014","operator":"alice","authorization_note":"ticket SEC-1234","manifest_digest":"c41d...",
             "handle":"hnd_8d1f0a52c3b7e9140a6d2f31","abc":{"A":true,"B":false,"C":true},"reason":"out_of_scope","engagement_status":"active"},
 "tool":"open_page","arguments":{"session_id":"ses_...","url":"https://evil.example.test/"},
 "outcome":"refused","detail":"https://evil.example.test is outside the authorized scope ...","duration_ms":1}
```

The `context` holds the accountability fields and, for each call, the gate's facts: `handle` and `abc` (the Rule of Two flags of the caller's handle), `action_class` and `action_rules` for classified actions, `reason` for a refusal, `approved` when an approval was used, `trace_id` when the client sent a `traceparent`, `engagement_status` and `manifest_digest` when a manifest is configured, `grant_digest` and `plan_digest` when a grant is. The hash chain covers all of it.

`hash` is the SHA-256 of the entry's fields in a fixed order, including the hash of the entry before it (`prev`; the first entry links to 64 zeros). Arguments are redacted before they are written, and the text of `type_text` is recorded by length and digest, not content.

```sh
browserx mcp audit verify mcp-audit.jsonl
# audit log is intact: 142 entries, last hash 9a60...
```

`verify` recomputes every hash and exits non-zero at the first entry that was edited, removed or reordered, naming its line. Cutting entries off the end keeps a valid chain, so **store the printed last hash outside the host** (or set `chattr +a` on the file). To rotate, stop the server, move the file away and start again: the new file begins a new chain.

## Evaluating the gate

`browserx agent eval --suite <path> --report <path> --seed <n>` runs a versioned adversarial suite against the enforcement layers (scope, grant, ledger, classifier, stale references, redaction) with a real Chromium and an offline fixture server on the loopback interface, and writes a JSON report with a matrix of attempted, blocked and escaped attempts per layer. It exits `0` only when no deterministic layer let an attempt escape and every case passed, and `2` when Chromium is missing, so a CI lane cannot pass without a browser. `--seed` fixes the order of the cases. See the [CLI reference](cli.md#browserx-agent-eval); a build with the `fault-injection` feature adds `--mutate <layer>` to prove that the suite notices a layer that was switched off.

## Typical sessions

**Monitoring triage** (read-only; no capabilities needed). The agent calls `capabilities`, `health` and `pool_status`. If the verdict is not `ok`, it calls `assess`, reads the failing checks with their evidence and remediation, and lists the sessions that hold capacity with `list_sessions`. For a session in an odd state it calls `explain_session`; for an error it saw in a client it calls `explain_error` with the code. The `capacity_review` prompt starts exactly this.

**Authorized site exploration** (`sessions`, `browse`, `interact`).

```text
capabilities                                  -> scope: https://app.example.test; engagement window open
create_session {}                             -> ses_...  (this server holds the token)
open_page {session_id, url: "https://app.example.test/"}
page_snapshot {session_id}                    -> [e1] link "Reports" ...  [e2] textbox "Search" ...
click {session_id, ref: "e1"}                 -> navigated: true
page_text {session_id}                        -> # Reports ... (untrusted block)
network_log {session_id, url_contains: "/api/"}
open_page {session_id, url: "https://other.example.test/"}   -> refused: outside the authorized scope
release_session {session_id, confirm: true}
```

A refusal is final: the agent is told not to look for a way around it, and none exists from inside the tool surface. The `explore_authorized_site` prompt carries these rules.

**A consequential action** (`sessions`, `browse`, `interact`; profile `test_environment`). The agent snapshots a settings page and clicks "Delete account". The class is `destructive`, which the profile answers with *approval*, so the click does not run. A `2026-07-28` client that declared `elicitation` gets `input_required` with a form and a `requestState`; the user accepts, the client retries the same request with `requestState` and `inputResponses`, and the click runs once. An older client gets `approval_required` with an `apr_...` id; the operator runs `browserx mcp approvals approve <id> --config mcp.toml` and the client retries with `approval_id`. Either way the audit log shows the `approval_required` result and then the `ok` one, both with `action_class: "destructive"`.

**Recovery debugging** (`sessions`, `browse`). A browser dies under an agent that was working in a `snapshot` session. The next browsing call reconnects by itself and returns a `notice`: `restored_from_snapshot`, cookies and `localStorage` came back, the JavaScript state did not, refs are invalid. The agent calls `explain_session` for the narrative, reopens the pages it needs with `open_page`, and takes a new `page_snapshot`. If the outcome were `fresh_process` the notice would say nothing was restored. `assess` shows whether crashes are a pattern (`recovery_rate`).

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `browserx mcp check` fails with "browse.require_scope is true" | Browsing needs `browse.allowed_origins`, `engagement.operator` and `engagement.authorization_note`, or `require_scope = false` |
| `unauthorized` / `key_accepted: false` in `health` | The key in `server.api_key_file` is not in the worker's `auth.api_keys` |
| `pool_status` says rates are unavailable | `server.ops_url` is not set, or only one metrics sample exists yet |
| A tool is missing from the list | Its capability is not in `mcp.capabilities` (or `[ai]` is not configured for the advisory tools) |
| "is not controlled by this server" | The session was created elsewhere or before this process started; create a new one, or adopt it with `[[adopt]]` |
| "the connection to the browser closed" | The browser was recovered or released; call the tool again, it reconnects |
| A navigation fails with `net::ERR_...` | The destination may be refused by the worker's egress policy (private addresses are blocked unless `egress.allow_cidrs` lists them); call `assess` |
| A page loads from a sub-frame of another origin | Sub-frames are page content and are not scope-checked; only top-level documents are |
| Snapshots miss content | They cover the main frame only; use `page_text` or open the frame's URL in scope |
| A tool is unlisted, or refused with `unsigned_manifest` | The engagement manifest has no signature or the signature does not match its bytes. Run `browserx mcp manifest verify` and sign again after every edit |
| `window_closed` | The engagement window, the manifest's window or the grant's window is closed. `engagement_status` shows the manifest's state |
| `approval_required` with an `approval_id` | The action needs the operator: `browserx mcp approvals list`, then `approve <id>`, then call the same tool again with `approval_id`. `confirm: true` does not approve anything |
| `rule_of_two` | Untrusted input, sensitive context and a page-changing tool are all present in this handle. Check `engagement_status`; `reset_context` starts clean when a human approves it under `enforce` (and start a fresh model context too); under `strict` the operator restarts the server |
| The server refuses to start: the scope grant is unsigned or widens its ceiling | Sign it with `browserx mcp grant sign`; narrow it to the manifest's hosts, `browse.allowed_origins`, call budget and `not_after` |
| HTTP 400 with code `-32020` or `-32022` | A `2026-07-28` request whose `MCP-Protocol-Version`, `Mcp-Method` or `Mcp-Name` header disagrees with the body, or a protocol version the server does not serve (`error.data.supported` lists them) |
| The audit log refuses writes | Calls that change something are refused when the log cannot be written; check the path's permissions and space |

## Limits

- The snapshot, interaction and text extraction cover the main frame. Coordinates for clicks are those of the main frame's viewport.
- `page_text` and the wait and select helpers run fixed scripts in the page's own JavaScript world; a hostile page can tamper with what they return, which is why the result is untrusted.
- Tokens are held in memory only. A restart of the server forgets them, and so it forgets ledger handles, plan progress and pending multi round-trip approvals.
- Request interception is a feature of the relay's protocol surface; if it is unavailable the server logs a warning and enforces scope after navigation only.
- Per-tool limits and budgets bound a single server process; running several processes against one worker multiplies them.
