# AI/LLM-native operation

BrowserX is *next-generation AI/LLM-native browser pooling, session management, persistence, recovery and handoff for authorized security research*. This page explains what that means, what an AI agent can do with it, how the limits are enforced and why the parts that matter stay ordinary code. The operator's how-to is the [MCP server guide](../guides/mcp.md).

## The principle

**AI agents can watch, drive and explain BrowserX within limits an operator sets. Models advise and act through scoped tools; they never authorize. Leases, recovery, egress policy and the host-protection relay policy stay deterministic code; no model sits in the data path.**

Three consequences follow from that sentence.

1. **Authority lives in configuration, not in prompts.** Which tools exist, which origins a browser may visit, when an engagement starts and ends, which proxy routes are selectable and how fast tools may run are all set in a file the operator controls. A model cannot widen them by asking, by being persuasive or by being tricked by a web page.
2. **The browser pool does not depend on a model.** Admission, fencing, expiry, health checks, recovery, snapshots, handoff and the relay's refusal rules are the same code with or without an agent. If the model endpoint is down, nothing in the pool changes; the advisory tools fall back to deterministic answers.
3. **Everything an agent does is accountable.** Every tool call is written to a hash-chained audit log together with the operator and the authorization the engagement runs under.

## What an agent can do

An agent reaches BrowserX through `browserx mcp`, a [Model Context Protocol](https://modelcontextprotocol.io) server that talks to a worker through its public HTTP API. It is useful on three levels, and each level is a separate switch.

| Level | What the agent can do | Switch |
| --- | --- | --- |
| **Watch** | Read health, readiness, pool saturation, recovery and snapshot rates over a window, graded checks with remediation, session lease views; ask for a narrative of a session's state or of an error code | always on (read-only) |
| **Explain** | Turn a status, a recovery outcome or an error into plain statements of what happened, which state survived and what to do next | always on |
| **Drive** | Create, renew, snapshot, release and hand off sessions; open pages, read an accessibility snapshot with stable element references, read page text, take screenshots, read network and console logs; click, type, select and scroll; run script | `capabilities` in the configuration |

Explanation is deterministic. The statement "this session came back as `restored_from_snapshot`, so cookies and `localStorage` survived and the JavaScript heap did not" comes from a table in the server, not from a model. A configured model can rephrase and prioritize (`diagnose`), summarize a page (`summarize_page`) or extract structured data (`extract_data`), always as advice with the deterministic findings alongside.

## How the limits are enforced

| Limit | Enforced by | Where it matters |
| --- | --- | --- |
| Tools that are not enabled do not exist | The tool list is built from `mcp.capabilities`; a call to an unlisted tool is a protocol error | A model cannot call what it was never offered |
| Browsing scope | Exact `scheme://host[:port]` origins in `browse.allowed_origins`, checked before navigation, on every top-level request (redirect hops included) while the browser is held at the request, and again on the final page | A page cannot lead the browser out of scope by redirect or by a link the agent clicks |
| Engagement window | `engagement.not_before` and `engagement.not_after` | Browsing tools are refused outside the window |
| Accountability | `engagement.operator` and `engagement.authorization_note` are required when scope is required, and are part of every audit entry | The log says who was testing under what authorization |
| Controlled sessions only | The server keeps lease tokens in memory; only sessions it created or was configured to adopt can be browsed, renewed or snapshotted | An agent cannot reach sessions of other clients |
| Secrets | Lease tokens, CDP URLs, API keys, model keys and proxy credentials never enter tool output, prompts or the audit log; proxies are chosen by name from configuration | A prompt injection has nothing to exfiltrate |
| Destructive calls | `release_session` and `handoff_session` need `confirm: true` | One mistaken call does not end a session |
| Rate and size | Per-tool calls per minute, a result byte budget per call, 4 MiB messages, bounded in-flight requests, bounded tabs and logs | A looping agent cannot flood the pool or its own context |
| Page content is data | All page-derived text is redacted, then wrapped in `<untrusted_page_content origin="...">` with the wrapper's own tags neutralized inside the text | A page cannot close the wrapper and continue "outside" it |

The scope check is the one most worth understanding. A policy that only inspected the page after it loaded would already have sent a request to the out-of-scope origin. The MCP server therefore asks the browser to hold every top-level document request (`Fetch.requestPaused`) until it has compared the URL with the scope, and fails the request when it is outside. Sub-frames and sub-resources are page content and are not held: a page in scope may embed a widget from elsewhere, as it could for any visitor. The check after the page settles is a second line for the rare case that interception is unavailable.

## Why the data path stays deterministic

A model in the data path would turn every lease operation into a judgment call. The properties BrowserX sells are the opposite of that: a write is fenced by a generation or it is refused; a token matches a digest or it does not; a browser is healthy or it is replaced after N strikes; an egress destination is private or it is not. Those answers have to be the same on Tuesday as on Monday, reproducible from the code, and testable without a network.

So the model sits *beside* the pool, not inside it:

- it reads the same HTTP API and metrics any operator can read;
- it acts through the same session API as any client, with an API key whose quota the operator chose;
- it controls a browser through the same authenticated relay as any CDP client, and the relay applies the same host-protection policy to it;
- it is optional: the MCP server starts, monitors, explains, browses and audits with no model endpoint configured.

The consequence for safety reviews is simple: the question "what can the agent do?" is answered by reading one configuration file and the relay's published refusal rules, not by evaluating a prompt.

## What this does not protect against

Be precise about the residual risks before you enable the powerful capabilities.

- **Prompt injection is mitigated, not solved.** Wrapping page content and instructing the model to treat it as data reduces the chance that a hostile page steers the agent; it does not remove it. The hard limits above are what holds when a model is steered: out-of-scope requests are refused, secrets are not present, destructive calls need confirmation.
- **In-scope sites can still mislead an agent.** An agent with `interact` can click, type and submit forms on in-scope origins, including actions with side effects. Give it scopes and accounts you would hand to a careful junior colleague, not production systems you cannot afford to have changed.
- **`evaluate_js` is a sharp tool.** Script in the page can read everything the page can and can call other origins with `fetch`; the scope guard covers top-level navigation, not requests a script makes. It is off unless the operator adds `evaluate` to `mcp.capabilities`.
- **Third-party content inside a page is not scope-checked.** Sub-frames and sub-resources load as the page asks.
- **The audit log detects tampering, not truncation.** The hash chain proves that entries were not edited, removed or reordered, but cutting entries off the end leaves a valid chain. Store the last hash that `browserx mcp audit verify` prints somewhere the host cannot rewrite, or set the append-only attribute on the file.
- **Plaintext transport.** The HTTP transport does not terminate TLS. Keep it on loopback or put TLS and access control in front of it.
- **A model endpoint sees what you send it.** If `[ai]` is configured, summaries and extraction send redacted page content, and `diagnose` sends the deterministic findings, to that endpoint. Use an endpoint you are permitted to send that data to.

Responsible use is the same for an agent as for a person: authorized security research, within a scope you can show. See [isolation and security](isolation-and-security.md) for the relay's own limits.

## See also

- [MCP server guide](../guides/mcp.md): setup, configuration, the full tool catalog, audit log, typical sessions
- [Sessions and leases](sessions-and-leases.md), [recovery](recovery.md), [handoff](handoff.md): the contracts the explanations are based on
- [Isolation and security](isolation-and-security.md): the host-protection policy every relay applies, MCP-driven or not
