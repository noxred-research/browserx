# MCP server

`browserx mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server for BrowserX. It lets an AI agent (any MCP client) **watch** a worker, **explain** what its sessions did and, if you allow it, **drive** browsers through scoped tools, with a hash-chained audit log of every call. Read [AI/LLM-native operation](../design/ai-llm-native.md) first for the principle and the limits; this page is the how-to and the reference.

The server implements MCP itself (JSON-RPC 2.0, protocol revisions `2025-06-18` and `2025-03-26`) and talks to a worker through its public HTTP API and its operations listener. For browsing it connects to a session's `cdp_url` over the same authenticated relay any CDP client uses. It does not need a model: the optional [`[ai]` endpoint](#the-optional-model-endpoint) only adds advisory tools.

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

Default rate limits per minute: monitoring, browsing and interaction `120`, sessions and model-assisted tools `20`, `evaluate_js` `30`.

## Tools

A tool whose capability is not enabled is **not listed**, and calling it is a protocol error (`Unknown tool`). Failures inside a tool (a refusal, a stale reference, an unreachable worker) are normal results with `isError: true` and a readable `error.kind` (`invalid_arguments`, `refused`, `rate_limited`, `backend_error`, `browser_error`, `not_configured`), so the model can correct itself. Arguments are validated against the schema the tool advertises; unknown arguments are rejected, not ignored.

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
| `page_snapshot` | The accessibility tree as compact text with stable refs (see below). `max_chars`, `interactive_only` |
| `page_text` | Readable Markdown of the main content: headings, paragraphs, lists, tables, links (targets kept, image sources dropped). `max_chars` |
| `screenshot` | PNG of the viewport or, with `full_page`, the page (at most 16000 px tall), returned as MCP image content. At most 2 MiB |
| `list_tabs`, `switch_tab`, `close_tab` | Tabs with URL, title, current marker and whether each is in scope |
| `go_back`, `go_forward` | History navigation; the landing page must be in scope |
| `wait_for` | Waits for `text` in the page or an element `ref` (or, with `gone: true`, for it to disappear); `timeout_ms` at most 30000 |
| `network_log` | Recent requests of the tab: method, URL, status, resource type, MIME type, size. No bodies, no headers. `limit`, `url_contains`, `resource_type`, `failed_only` |
| `console_log` | Recent console messages and uncaught exceptions. `limit`, `level` |

#### Snapshots and element references

`page_snapshot` renders the accessibility tree (`Accessibility.getFullAXTree` on the main frame):

```text
page "Test Site"
  heading "Test Site" (level=1)
  text "Welcome to the lab."
  [e1] link "Go to page two"
  [e2] textbox "Search" value="lab rats" (required)
  [e3] button "Find"
  [e4] combobox "Color" value="Red"
```

Interactive elements carry a ref (`e1`). A ref is keyed by the element's DOM node, so the same element keeps its number across snapshots until the page navigates; navigation clears every ref. Every interaction **re-resolves** its ref against the live tree and refuses it when the element is gone or its role or accessible name changed since the snapshot (`ref e1 is stale ...`): take a new `page_snapshot`. Limits: main frame only (the content of sub-frames is not in the tree), names are cut at 160 characters and values at 120, and the output stops at `max_chars` with a note.

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

## Safety model

The [design page](../design/ai-llm-native.md#how-the-limits-are-enforced) explains why. In practice:

- **Scope.** `open_page` refuses a URL outside `browse.allowed_origins` before touching the browser. While a tab is attached, the server also asks the browser to hold each top-level document request until its URL has been compared with the scope, so an out-of-scope redirect hop or link target is blocked **before it is sent** and the tab stays on its previous page. After a page settles, its final URL is checked again; a landing outside the scope resets the tab to `about:blank`. A tab that a page opened itself (a popup) and that sits outside the scope is refused and reset the first time it is used. Sub-frames and sub-resources are not held.
- **Engagement window.** Outside `not_before` and `not_after`, every browsing, interaction and model-assisted page tool is refused.
- **Untrusted content.** Page-derived text (page text, snapshots, network and console logs, tab titles, script results, summaries) is wrapped as `<untrusted_page_content origin="...">`. The wrapper's tags are neutralized inside the text. Trusted metadata (counts, ids, flags) is returned separately as structured content and never contains page text.
- **No secrets to the model.** Tool results, prompts and the audit log are scrubbed of the API key, the model key, proxy passwords, lease tokens (`bxt_...`), `bxk_...` keys, `Bearer` values and URL credentials. Members named like secrets are replaced. With `mcp.reveal_endpoints = true` the token and CDP URL of a created or handed-off session are appended as a separate text block, never in structured content.
- **Confirmation.** `release_session` and `handoff_session` need `confirm: true`.
- **Rate limits and budgets.** Per-tool calls per minute (a refusal says how long to wait), `mcp.max_result_bytes` per text block with a truncation notice, bounded tabs, logs and in-flight requests.
- **Calls that change something run to completion.** The server records an `intent` entry first (the call is refused if the audit log cannot be written), then runs the call even if the client cancels the request, then records the result.

## Audit log

`audit.path` is a JSONL file created with mode `0600`. Every tool call adds a `result` entry; calls that change something (sessions, navigation, interaction, script, tab changes) add an `intent` entry before they run. Refused and invalid calls are recorded too.

```json
{"seq":7,"ts":"2026-03-02T09:14:03Z","prev":"3f1c...","hash":"9a60...","phase":"result",
 "caller":{"transport":"stdio","client_name":"my-client","remote":null},
 "context":{"engagement":"ENG-2026-014","operator":"alice","authorization_note":"ticket SEC-1234"},
 "tool":"open_page","arguments":{"session_id":"ses_...","url":"https://evil.example.test/"},
 "outcome":"refused","detail":"https://evil.example.test is outside the authorized scope ...","duration_ms":1}
```

`hash` is the SHA-256 of the entry's fields in a fixed order, including the hash of the entry before it (`prev`; the first entry links to 64 zeros). Arguments are redacted before they are written, and the text of `type_text` is recorded by length and digest, not content.

```sh
browserx mcp audit verify mcp-audit.jsonl
# audit log is intact: 142 entries, last hash 9a60...
```

`verify` recomputes every hash and exits non-zero at the first entry that was edited, removed or reordered, naming its line. Cutting entries off the end keeps a valid chain, so **store the printed last hash outside the host** (or set `chattr +a` on the file). To rotate, stop the server, move the file away and start again: the new file begins a new chain.

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
| The audit log refuses writes | Calls that change something are refused when the log cannot be written; check the path's permissions and space |

## Limits

- The snapshot, interaction and text extraction cover the main frame. Coordinates for clicks are those of the main frame's viewport.
- `page_text` and the wait and select helpers run fixed scripts in the page's own JavaScript world; a hostile page can tamper with what they return, which is why the result is untrusted.
- Tokens are held in memory only. A restart of the server forgets them.
- Request interception is a feature of the relay's protocol surface; if it is unavailable the server logs a warning and enforces scope after navigation only.
- Per-tool limits and budgets bound a single server process; running several processes against one worker multiplies them.
