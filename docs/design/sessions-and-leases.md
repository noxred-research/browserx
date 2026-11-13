# Sessions and leases

A session is a lease on a browser. The lease is a durable record; the browser behind it can change. This page defines the record, its states, the fencing generation, the controller token, the time limits and admission.

## The session spec

A client creates a session by sending a `SessionSpec` (JSON, unknown fields are rejected):

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `launch_profile` | string | the configured default | Named [launch profile](../guides/launch-profiles.md) |
| `persistence` | `ephemeral` \| `snapshot` \| `profile` | `ephemeral` | What outlives the browser process; see [persistence](persistence.md) |
| `isolation` | `dedicated_browser` \| `shared_browser` | `dedicated_browser` | Process isolation; see [isolation and security](isolation-and-security.md) |
| `profile_id` | `prf_...` | none | Reuse a persistent identity (profile directory and/or snapshots). A new one is minted when absent and persistence is not `ephemeral`. Only identities created by the same API key (owner) can be reused; any other id answers `not_found`. Not allowed with `ephemeral` |
| `proxy` | object | none (direct egress) | Upstream route; see [egress](egress.md) |
| `ttl_secs` | integer > 0 | server default | Lease time-to-live; renewals extend it |
| `max_lifetime_secs` | integer > 0 | server default | Hard cap on total lifetime regardless of renewals |
| `idle_timeout_secs` | integer > 0 | server default | Release after this long without an attached controller |
| `recovery` | `restore` \| `none` | `restore` | What the scheduler may do when the browser is lost; see [recovery](recovery.md) |
| `labels` | map of string to string | empty | Free-form bookkeeping, not interpreted. At most 32 labels, keys and values at most 256 bytes |

Requested durations above the server's maximums (`session.max_ttl_secs`, `session.max_lifetime_secs`) are refused with `invalid_request`; an `idle_timeout_secs` longer than the maximum lifetime is refused too, since the lifetime would end the session first. Omitted values take the server defaults.

Combinations that contradict each other are refused at admission with `invalid_request`:

- `persistence = "profile"` with `isolation = "shared_browser"`: a profile directory belongs to exactly one browser process.
- `proxy` with `isolation = "shared_browser"`: the egress forwarder is per browser process, so a per-session upstream needs a dedicated browser.
- Proxy URLs that contain credentials (`http://user:pw@host`): credentials go in `proxy.username` and `proxy.password`.
- `profile_id` together with `persistence = "ephemeral"`: an ephemeral session has no persistent identity.
- An unknown `launch_profile`.
- A duration of zero, too many labels, or labels that are too long.

## The lease record

The lease is stored as a whole and replaced with compare-and-swap. It carries:

| Field | Meaning |
| --- | --- |
| `session_id` (`ses_...`) | Public, stable identity. Survives browser replacement |
| `owner` | The API key name that created the session |
| `spec` | The request as admitted |
| `status` | Lifecycle state, below |
| `generation` | Fencing counter |
| `worker_id`, `browser_id`, `context_id` | Which worker, browser process and (for shared isolation) browser context currently back the session |
| `profile_id` | Persistent identity, when persistence is not `ephemeral` |
| `snapshot_version` | Newest snapshot written for the profile |
| `token_digest` | SHA-256 of the current controller token. The token itself is never stored |
| `last_recovery` | How the session reached its current browser: one of the four [outcomes](recovery.md#attach-outcomes) |
| `recoveries` | How many times the backing browser was replaced |
| `created_at`, `expires_at`, `max_expires_at` | Creation time, current expiry, absolute cap |
| `last_heartbeat_at`, `last_attach_at` | Last health probe success, last attach or detach |
| `reason` | Human-readable reason for the latest terminal or recovery transition |

The API returns a view of the lease without `token_digest`.

## Lifecycle

```text
queued -> allocating -> active <-> idle
                          |  \      |
                          |   +-> recovering -> active
                          v         |
                       draining     v
                          |        lost
                          v
                        closed
```

| State | Meaning |
| --- | --- |
| `queued` | Admitted, waiting for capacity |
| `allocating` | A browser is being launched or a context created |
| `active` | A controller is attached |
| `idle` | Running with no controller attached |
| `recovering` | The browser was lost; a replacement is being launched and restored |
| `draining` | Release requested: final snapshot, cleanup |
| `lost` | The browser was lost and recovery is disabled or failed. Terminal |
| `closed` | Released and cleaned up. Terminal |

Terminal states never change again. A controller can attach in `active` and `idle`. Any other transition that the diagram does not show is refused with `conflict`.

## Generations: fencing

Every ownership change increments the lease's `generation`:

- allocation creates generation 1;
- recovery onto a new browser increments it;
- [handoff](handoff.md) to a new controller increments it.

Every lease mutation is *load, modify, compare-and-swap on the expected generation*. The store refuses the write if another writer advanced the lease in between, and the caller sees `stale_generation` (HTTP `409`) with the generation now stored. Two consequences:

1. A client that passes `generation` on `renew`, `handoff` and `release` cannot act on a lease that changed under it. If the browser was replaced or the session was handed to someone else, its call fails instead of silently applying to a different situation.
2. A background writer that lost a race (a snapshot taken by a superseded generation, a recovery that started before a release) is discarded.

## The controller token

`POST /v1/sessions` returns a token of the form `bxt_<64 hex characters>`: 32 random bytes with a recognizable prefix so secret scanners can find it. It is returned once. The server stores only its SHA-256 digest and compares in constant time.

The token authorizes the controller operations (`attach`, `renew`, `handoff`, `snapshot`, `release`) together with the owner's API key (a wrong token answers `forbidden`; on the relay, `unauthorized`), and it appears in the `cdp_url`. Treat it as a credential. Handoff replaces it; the old token stops working immediately.

## Time limits

| Limit | Set by | Effect |
| --- | --- | --- |
| Time-to-live | `ttl_secs`, at most `session.max_ttl_secs` | The lease expires at `expires_at` unless renewed. `renew` sets it to now plus the time-to-live, never past the absolute cap |
| Absolute lifetime | `max_lifetime_secs`, bounded by `session.max_lifetime_secs` | `max_expires_at`; renewals and heartbeats cannot move it |
| Idle timeout | `idle_timeout_secs` | A session with no attached controller is released after this long |
| Terminal retention | `session.terminal_retention_secs` | Closed and lost leases stay readable for this long, then are purged |

The reaper releases expired sessions through the normal `draining` path, so a snapshot session gets its final snapshot. Time arithmetic saturates at the far future rather than wrapping, and the pool refuses configured durations above ten years, so an oversized value can never make a session look instantly expired.

The reaper also finishes leases that an operation left in `draining` or `recovering`. Every operation holds the session's control mutex from its first lease change to its last, so a transient lease nobody holds the mutex for is stranded: the reaper retries the release (`draining`), releases it when expired, or retries the recovery (`recovering`). Otherwise such a lease would hold the owner's quota, the profile claim and possibly a browser until the worker restarted.

## Operations run to completion

`create`, `attach`, `renew`, `handoff`, `snapshot`, `release` and profile deletion run in a tracked task that the client connection does not own. If the client disconnects or times out mid-call, the operation still finishes (or rolls back by itself), so it cannot leak a browser, a context slot, a quota slot or a profile claim, and a handoff cannot half-commit. The caller that disconnected simply does not see the response: a created session whose token was never delivered ends at its idle timeout, and an owner who lost the token of a handoff can release the session with the API key alone. Graceful shutdown waits for these tasks (bounded) before stopping browsers.

## Admission

Creating a session passes four checks in order:

1. **Validation** of the spec (above).
2. **Owner quota.** The API key's `max_sessions` bounds how many non-terminal sessions it owns. Over the quota: `429 capacity`.
3. **Queue.** A bounded FIFO queue of `pool.queue_capacity` entries. A full queue answers `429 capacity` immediately.
4. **Capacity.** A waiting request is served when `pool.max_browsers` allows a new browser (dedicated) or a shared browser has a free context slot (`pool.max_contexts_per_browser`). If `pool.queue_timeout_secs` passes first: `429 capacity`.

The queue is first-in-first-out; there are no priorities.

## Operations on a lease

| Operation | Needs | Effect |
| --- | --- | --- |
| create | API key | New lease, generation 1, token returned once |
| attach | key + token | Marks the session `active`, reports the [outcome](recovery.md#attach-outcomes) |
| detach | (implicit) | When the last relay connection closes, the session becomes `idle` |
| renew | key + token + generation | Extends `expires_at` |
| handoff | key + token + generation | New generation, new token, old connections closed; see [handoff](handoff.md) |
| snapshot | key + token | Writes a snapshot now (`snapshot` persistence only) |
| release | key + token + generation, or the owner's key alone | `draining`, then `closed`. The owner may release without the token (an administrative release) |
