# API reference

The public listener (`server.listen`) serves a JSON API under `/v1` and a WebSocket relay under `/cdp`. The ops listener (`server.ops_listen`) serves health and metrics.

## Conventions

- **Authentication.** Every `/v1` request carries `Authorization: Bearer <api key>`. Keys are matched by SHA-256 digest in constant time. A missing or wrong key is `401 unauthorized`.
- **Lease token.** Controller operations also carry the session's token in the `X-BrowserX-Token` header (or, for the relay, in the URL path). A wrong or stale token is `403 forbidden` on the `/v1` operations; on the relay it is `401 unauthorized`, the same answer as an unknown session. The token is checked before any session state is read, so a caller without it learns nothing about a session.
- **Ownership.** An API key sees and operates only on the sessions and profiles it created. Another owner's session or profile id answers `404 not_found`, exactly as a missing one does.
- **Bodies.** Request and response bodies are JSON. Request bodies reject unknown fields. `POST /v1/sessions` accepts an empty body (same as `{}`); `renew` and `handoff` need a body with `generation`.
- **Identifiers.** `ses_...` (session), `prf_...` (profile). Both the prefixed form and the bare UUID are accepted in paths and, for `profile_id`, in the create body.
- **Timestamps.** RFC 3339, UTC.

## Objects

### `SessionSpec` (request body of create)

See [sessions and leases](../design/sessions-and-leases.md#the-session-spec) for the semantics and the refused combinations.

```json
{
  "launch_profile": "default",
  "persistence": "snapshot",
  "isolation": "dedicated_browser",
  "profile_id": "prf_0f3c...",
  "proxy": {
    "url": "http://gateway.test:8080",
    "username": "pool-sid-{session}-g{generation}",
    "password": "synthetic-password"
  },
  "ttl_secs": 600,
  "max_lifetime_secs": 7200,
  "idle_timeout_secs": 300,
  "recovery": "restore",
  "labels": { "job": "nightly-check" }
}
```

Every field is optional. `{}` creates an ephemeral, dedicated session with the default launch profile, direct egress and the server's default time limits.

### `LeaseView` (the `session` field of responses)

A client-visible projection of the lease. Worker, browser and context identifiers and the token digest are not exposed, and neither is the proxy configuration.

| Field | Meaning |
| --- | --- |
| `session_id` | `ses_...` |
| `owner` | The API key name that created the session |
| `status` | `queued`, `allocating`, `active`, `idle`, `recovering`, `draining`, `lost`, `closed` |
| `generation` | Fencing counter. Pass it back on `renew`, `handoff` and `release` |
| `isolation`, `persistence`, `recovery` | The admitted values from the spec |
| `launch_profile` | The requested launch profile, or `null` for the server default |
| `profile_id` | Persistent identity, when persistence is not `ephemeral` |
| `snapshot_version` | Newest snapshot version of the profile, when there is one |
| `last_recovery` | `resumed_same_process`, `restored_from_profile`, `restored_from_snapshot` or `fresh_process` |
| `recoveries` | How many times the browser was replaced |
| `created_at`, `expires_at`, `max_expires_at` | Creation, current expiry, absolute cap (RFC 3339) |
| `last_attach_at` | Last attach or detach |
| `reason` | Why the latest recovery or terminal transition happened |
| `labels` | The caller's labels |

### `outcome`

One of `resumed_same_process`, `restored_from_profile`, `restored_from_snapshot`, `fresh_process`. See [recovery](../design/recovery.md#attach-outcomes).

### Snapshot metadata

| Field | Meaning |
| --- | --- |
| `profile_id` | The persistent identity |
| `version` | Monotonic version within the profile |
| `session_id`, `generation` | The session and generation that wrote it |
| `created_at` | Capture time |
| `size` | Ciphertext length in bytes |
| `key_id` | Identifier of the key that sealed it |

## Sessions

### `POST /v1/sessions`

Creates a session. Body: a `SessionSpec`.

`201 Created`:

```json
{
  "session": { "session_id": "ses_9a41...", "status": "idle", "generation": 1 },
  "token": "bxt_0000000000000000000000000000000000000000000000000000000000000000",
  "cdp_url": "ws://127.0.0.1:7690/cdp/ses_9a41.../bxt_0000...",
  "outcome": "fresh_process"
}
```

The `token` is returned **once**; only its digest is stored. Errors: `400 invalid_request` (bad spec, or a `ttl_secs`, `max_lifetime_secs` or `idle_timeout_secs` above the server maximum lifetime), `401`, `404 not_found` (unknown `profile_id`), `409 conflict` or `profile_locked` (the profile is in use), `429 capacity` (quota, full queue or wait deadline), `502 browser` / `egress` (launch or upstream failure), `503 shutting_down`.

### `GET /v1/sessions`

Lists the caller's sessions. Optional `?status=` filters by state; several states are comma-separated (`?status=active,idle`). An unknown state answers `400`.

```json
{ "sessions": [ { "session_id": "ses_9a41...", "status": "active", "generation": 1 } ] }
```

### `GET /v1/sessions/{id}`

Returns `{ "session": LeaseView }`. No token needed; the API key's ownership is enough. Terminal sessions stay readable until `session.terminal_retention_secs` passes.

### `POST /v1/sessions/{id}/attach`

Header `X-BrowserX-Token`. Marks the session in use and reports how it got its browser.

```json
{
  "session": { "session_id": "ses_9a41...", "status": "active", "generation": 2 },
  "cdp_url": "ws://127.0.0.1:7690/cdp/ses_9a41.../bxt_0000...",
  "outcome": "restored_from_snapshot",
  "generation": 2
}
```

If the browser is alive the outcome is `resumed_same_process`, except that a recovery since the last attach is reported once, to the first `POST .../attach` (a relay connection does not count). If the browser is dead and recovery is allowed, the worker recovers (bounded) and reports that outcome. Errors: `403` (wrong token), `404`, `409 conflict` (the session is closed, lost or draining), `502 browser`, `504 timeout`.

### `POST /v1/sessions/{id}/renew`

Header `X-BrowserX-Token`. Body (required):

```json
{ "generation": 2, "ttl_secs": 600 }
```

`ttl_secs` is optional (default: the session's own `ttl_secs`, else the server default); it must be between 1 and `session.max_ttl_secs` (`400 invalid_request` otherwise). Returns `{ "session": ... }` with `expires_at` set to now plus the time-to-live, never beyond `max_expires_at`. A `generation` that no longer matches answers `409 stale_generation`; a closed, lost or draining session answers `409 conflict`.

### `POST /v1/sessions/{id}/handoff`

Header `X-BrowserX-Token`. Body `{ "generation": 2 }`. Returns a new token and `cdp_url`; the old token and the relay connections bound to it stop working. See [handoff](../design/handoff.md).

```json
{ "session": { "generation": 3 }, "token": "bxt_...", "cdp_url": "ws://.../cdp/ses_.../bxt_..." }
```

### `POST /v1/sessions/{id}/snapshot`

Header `X-BrowserX-Token`. Captures and stores a snapshot now. Only sessions with `persistence = "snapshot"` can be snapshotted; others answer `409 conflict`, as does a session that is not `active` or `idle`.

```json
{ "snapshot": { "profile_id": "prf_0f3c...", "version": 7, "session_id": "ses_9a41...", "generation": 2, "created_at": "2026-01-01T00:00:00Z", "size": 4812, "key_id": "a1b2c3d4" } }
```

### `DELETE /v1/sessions/{id}?generation=N`

Releases the session: final snapshot (snapshot mode), disposal of the context or confirmed shutdown of the browser, release of the profile lock. Header `X-BrowserX-Token`, or no token when the caller owns the session (administrative release). `generation` is optional; when present it must match.

`200 OK` with `{ "session": ... }` once the session is released (`status` `closed`; an already terminal session is returned as it is). The call returns after the final snapshot and the confirmed browser shutdown, so it can take a few seconds. A release can also fail with `403` (wrong token) or `409 stale_generation`.

## Profiles

### `GET /v1/profiles/{id}/snapshots`

Lists retained snapshots of a profile as `{ "snapshots": [...] }` (metadata only, newest first).

### `DELETE /v1/profiles/{id}`

Erases a profile: its snapshots, its profile directory and its ownership record. Returns `{ "deleted_snapshots": <count> }`. A profile that a session uses answers `409 conflict` (or `409 profile_locked` when another process holds the directory lock); release the session first. Unknown profiles, and profiles of other owners, answer `404`.

## Launch profiles

### `GET /v1/launch-profiles`

Returns the names this worker offers and the default: `{ "default": "default", "profiles": ["default", "wide"] }`. Needs an API key like every `/v1` route.

## CDP relay

### `GET /cdp/{session_id}/{token}`

WebSocket upgrade. The token is in the path because many CDP clients accept only a URL. The server does not log paths of this route; do not log them in front of it either.

- The server verifies the token digest first and answers `401` for a wrong or stale token and for an unknown session, without telling them apart. Only a caller holding a valid token learns more: `409` for a closed or releasing session. Opening a relay does not consume the recovery outcome; only `POST .../attach` reports it.
- **Dedicated isolation:** a relay to the browser-level DevTools endpoint that applies the [host-protection rules](../design/isolation-and-security.md#host-protection-rules) (no `file:` or internal-page navigation, no per-context proxy, no `Target.exposeDevToolsProtocol`, downloads confined to a per-session directory); other commands of the page-level protocol domains pass through. Messages are bounded at 64 MiB.
- **Shared isolation:** a scoped relay that allows only the session's browser context; see [isolation and security](../design/isolation-and-security.md#shared-browser). A refused command answers with a CDP error response (`code -32000`) on that command; the connection stays open. Messages are bounded at `scoped_relay_max_message_bytes` (16 MiB by default).
- A session accepts at most `max_relay_connections_per_session` (default 4) relay connections at once; another upgrade is refused with `429 capacity` until one closes.
- The connection closes when the session is handed off (the old token's connections), when recovery starts or finishes (the browser behind it is gone), when the session is released, closed or lost, and when the worker shuts down. A clean `attach` after that gives you a new connection.
- The server pings every 30 seconds and closes a connection on which the client has sent no frame (a pong counts) for 120 seconds; standard WebSocket clients answer pings automatically.
- When the last relay connection of a session closes, the session becomes `idle`.

## Errors

Every error has the same body:

```json
{ "error": { "code": "stale_generation", "message": "stale generation: expected 2, found 3" } }
```

| `code` | HTTP | Meaning |
| --- | --- | --- |
| `invalid_request` | 400 | Malformed request or unsupported combination |
| `unauthorized` | 401 | Missing or wrong API key; on the relay, also a wrong token or an unknown session |
| `forbidden` | 403 | Missing, wrong or stale lease token on a `/v1` call, or an operation the credential does not allow |
| `not_found` | 404 | No such session, profile or snapshot (or not yours) |
| `stale_generation` | 409 | The lease moved on; read it and decide |
| `conflict` | 409 | The session's state forbids the operation |
| `profile_locked` | 409 | A running browser holds the profile directory |
| `capacity` | 429 | Quota reached, queue full or wait deadline passed |
| `browser` | 502 | Launch, crash or protocol failure of the browser |
| `egress` | 502 | Upstream proxy or forwarder failure |
| `timeout` | 504 | A bounded operation ran out of time |
| `shutting_down` | 503 | The worker is draining |
| `storage`, `crypto`, `internal` | 500 | Storage, snapshot encryption or an unexpected internal error. The response message is the generic `internal error`; the cause is in the worker log |

Branch on `code`, not on `message`. A `401` carries `WWW-Authenticate: Bearer`; a `429` carries `Retry-After: 1`. Unknown routes answer `404 not_found` with the same body shape. Request bodies are limited to 256 KiB.

## Ops listener

| Route | Meaning |
| --- | --- |
| `GET /healthz` | `200` with body `ok` when the process is alive |
| `GET /readyz` | `200 {"ready": true}` when the lease store is reachable, the default launch profile exists with a findable executable and the worker is not draining; otherwise `503 {"ready": false, "problems": [...]}` |
| `GET /metrics` | Prometheus text exposition; see [operations](operations.md#metrics) |

## Example: a full cycle with curl

```sh
BASE=http://127.0.0.1:7690
KEY=<api key>

# create
curl -s -X POST "$BASE/v1/sessions" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d '{"persistence":"snapshot"}'

# attach and read the outcome
curl -s -X POST "$BASE/v1/sessions/$SES/attach" \
  -H "Authorization: Bearer $KEY" -H "X-BrowserX-Token: $TOKEN"

# release
curl -s -X DELETE "$BASE/v1/sessions/$SES?generation=1" \
  -H "Authorization: Bearer $KEY" -H "X-BrowserX-Token: $TOKEN"
```
