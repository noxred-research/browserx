# Operations

Running a BrowserX worker: what to watch, how to back it up, how to rotate keys, how to restart and upgrade without surprises.

## Deployment shape

- One worker is one process on one machine. It owns the browsers it launched; they die with it.
- Run it as an unprivileged user with a dedicated `state_dir`, under a supervisor that restarts it (systemd, a container runtime).
- Size the host for `pool.max_browsers` browsers. A headless Chromium typically needs several hundred MiB; leave headroom for page memory and for browsers being launched or torn down.
- Put a TLS-terminating reverse proxy in front for any remote client; keep paths for `/cdp/` out of its logs. See [isolation and security](../design/isolation-and-security.md#transport).
- Expose the ops listener only to your orchestrator and monitoring.

## Health and readiness

| Endpoint | Use it for | Healthy when |
| --- | --- | --- |
| `GET /healthz` | Liveness probe: restart the worker if it fails | The process is alive and serving (`200`, body `ok`) |
| `GET /readyz` | Readiness probe: send traffic only when it passes | The lease store is reachable, the default launch profile exists and its executable can be found, and the worker is not draining |

`/readyz` answers `200 {"ready": true}` or `503 {"ready": false, "problems": [...]}` with human-readable reasons. It turns to failure at the start of a graceful shutdown, so a load balancer stops sending new sessions while existing ones drain.

## Metrics

`GET /metrics` on the ops listener returns Prometheus text.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `browserx_sessions` | gauge | `status` | Sessions by lifecycle state (terminal ones until they are purged) |
| `browserx_browsers` | gauge | `isolation` | Running browser processes by isolation mode |
| `browserx_admissions_total` | counter | `result` | Admission decisions: `accepted`, `queue_full`, `timeout`, `quota`, `failed` |
| `browserx_queue_depth` | gauge | | Admissions waiting for capacity |
| `browserx_recoveries_total` | counter | `outcome` | Recoveries by outcome: `restored_from_profile`, `restored_from_snapshot`, `fresh_process`, `lost` |
| `browserx_launch_seconds` | histogram | | Browser launch time |
| `browserx_relay_connections` | gauge | | Open CDP relay connections |
| `browserx_snapshots_total` | counter | `result` | Snapshot attempts: `ok`, `failed`, `stale` (a superseded generation, discarded) |
| `browserx_egress_refused_total` | counter | | Connections refused by the egress policy |

Useful alerts:

| Condition | Why it matters |
| --- | --- |
| `browserx_queue_depth` stays near `pool.queue_capacity` | Clients are about to see `429 capacity`; raise `max_browsers` or add a worker |
| `rate(browserx_recoveries_total[10m])` rises | Browsers are crashing: memory pressure, bad pages, a bad build |
| `increase(browserx_recoveries_total{outcome="lost"}[1h])` above 0 | Recovery failed after its attempts, so sessions were lost |
| `browserx_snapshots_total{result="failed"}` increases | Snapshots are failing: key file, disk space, a stuck browser |
| `browserx_launch_seconds` p95 climbs | Host saturation or a slow executable |
| `/readyz` fails while `/healthz` passes | The worker is alive but cannot serve: store, launch profile or draining |

## Logs

Structured logs go to standard error through `tracing`. Choose the format with `--log-format json|text` on `browserx serve` and the filter with `RUST_LOG` (default `info`). Examples: `RUST_LOG=info,browserx_pool=debug`, `RUST_LOG=browserx_egress=debug`.

Lease tokens, API keys, proxy credentials and the CDP relay path are never logged. If you see one in your own aggregation, it came from something in front of the worker (a reverse proxy access log).

## Backups

Everything persistent lives under `state_dir` (and the key file named by `storage.snapshot_key_file`).

| Path | What it is | How to back it up |
| --- | --- | --- |
| `browserx.db` (+ `-wal`, `-shm`) | SQLite lease registry in WAL mode | Use the SQLite online backup (`sqlite3 browserx.db ".backup 'copy.db'"`), or stop the worker and copy all three files together. Copying only `browserx.db` while the worker runs can produce an inconsistent copy |
| `snapshots/<profile_id>/` | Sealed snapshots. Files are written atomically and never modified | Copy at any time; for a consistent set copy the whole directory with a tool that tolerates files appearing |
| `profiles/<profile_id>/`, `profiles/.owners/` | Live Chromium profile directories, and the ownership records of every persistent identity (snapshot profiles included) | Copy only a profile whose session is `closed` (no browser holds `.browserx.lock`). A copy of a running profile is not reliable |
| `tmp/` | Temporary directories of running ephemeral browsers | Do not back up |
| the snapshot key files (active and retired) | The keys that seal and open snapshots | Back it up **separately** from the snapshots, with strict access. Without it the snapshots cannot be read; with it next to them, they are not encrypted in any useful sense |

Restoring a backup to a fresh `state_dir`:

1. Put the key file, `snapshots/`, `browserx.db`, `profiles/.owners/` and the profile directories in place with owner-only permissions (`0700` for directories, `0600` for files).
2. Start the worker. Every lease in a non-terminal state is treated as orphaned and recovered per its recovery policy: `restored_from_snapshot`, `restored_from_profile` or `fresh_process`, or `lost` with `recovery = "none"`. See [startup reconciliation](../design/recovery.md#startup-reconciliation).
3. Profile sessions restored onto another machine come back as `restored_from_profile` only if the profile directories came with them and are usable with the local Chromium; otherwise treat them as snapshot-less.

A backup of the state directory contains session cookies (in sealed snapshots, and in plain form inside profile directories). Protect backups like the credentials they hold.

## Key rotation

### API keys

API keys live in the configuration as SHA-256 digests. To rotate one without downtime for the new key:

1. `browserx keys new <name>-2` and add the printed `[[auth.api_keys]]` block next to the old one.
2. Restart the worker (below). Clients start using the new key.
3. Remove the old block and restart again once nothing uses it.

The owner of a session is the key's `name`. A key with a **new name** cannot see sessions of the old name, so for a rotation that must keep access to running sessions, create the new key under the same `name` and replace the old digest in one edit and restart. Keys are read at startup; there is no hot reload.

### Lease tokens

A token is per session. Rotate one by [handoff](../design/handoff.md), which replaces it and cuts off the old holder. Do this when a token may have leaked.

### Snapshot key

One key is **active** and seals every new snapshot. Earlier keys can be kept as **retired**: they can only open old snapshots, never seal new ones. Each snapshot records the `key_id` of the key that sealed it, and the worker picks the matching key when it reads one.

Rotation without losing restorable state:

1. Generate the new key: `browserx snapshot-key new <new path>`.
2. In the configuration, point `storage.snapshot_key_file` at the new file and list the old file under `storage.retired_snapshot_key_files`:

   ```toml
   [storage]
   snapshot_key_file = "/var/lib/browserx/keys/snapshot-2.key"
   retired_snapshot_key_files = ["/var/lib/browserx/keys/snapshot-1.key"]
   ```

3. Restart the worker (see below). Sessions restore from old snapshots through the retired key; every snapshot taken from now on is sealed with the new key.
4. Old versions disappear as `session.snapshot_keep` prunes them. `GET /v1/profiles/{id}/snapshots` shows the `key_id` of each retained snapshot. Once no snapshot you need still carries the old `key_id`, remove the retired entry and restart.

A snapshot sealed with a key that is neither active nor retired cannot be opened; the restore fails with a `crypto` error (`unknown key_id <id>` in the worker log, a generic `500` for the client). A retired key needs a `key_id` distinct from the active one.

When a key may have leaked, rotation is not enough: every snapshot sealed with it holds session cookies that are credentials. Delete those snapshots (`DELETE /v1/profiles/{id}`), drop the key from the configuration and invalidate the sessions at the sites involved.

## Restarts and upgrades

A worker restart restarts every browser it supervised. Plan it:

1. Stop admission and drain: send `SIGTERM` (or `SIGINT`). The worker stops accepting sessions (`/readyz` fails), closes relays, gives open requests up to 15 seconds to finish, writes final snapshots for snapshot sessions and confirms each browser is gone before it exits.
2. Start the new binary against the same `state_dir` and key file.
3. On start, leases from the previous run are reconciled: each one is recovered (and reported to its controller on the next attach as `restored_from_*` or `fresh_process`) or marked `lost`.

Clients see a restart as a recovery with an outcome other than `resumed_same_process`. That is by design: the browser really was replaced. A controller that reconnects and branches on the outcome handles it correctly.

Pre-1.0, the lease database schema carries a migration table and the snapshot plaintext carries a format version; a worker refuses snapshots whose format is newer than it understands. Read the [changelog](../../CHANGELOG.md) before upgrading, and take a [backup](#backups) first.

## Capacity planning

| Setting | Effect | Guidance |
| --- | --- | --- |
| `pool.max_browsers` | Hard cap on processes | The main memory knob. Start low, watch memory and `browserx_launch_seconds` |
| `pool.max_contexts_per_browser` | Sessions per shared browser | Higher is cheaper and less isolated from a crash |
| `pool.warm_shared_browsers` | Idle shared browsers kept ready | Raises idle memory, cuts shared-session start time |
| `pool.queue_capacity`, `queue_timeout_secs` | How long overload is absorbed | Short queues fail fast; long queues hide overload |
| `auth.api_keys.max_sessions` | One owner's footprint | Set per client, so a runaway client cannot take the pool |
| `session.snapshot_interval_secs` | Snapshot IO and the recovery point | 60 s default; lower it for important state, or snapshot on demand after changes |

## Disk

- Snapshot files are small (cookies and storage of a few origins), but `snapshot_keep` versions of every profile accumulate. Delete profiles you no longer need with `DELETE /v1/profiles/{id}`.
- Profile directories are real Chromium profiles and grow with cache and storage; they are not pruned for you.
- Closed and lost leases are purged after `terminal_retention_secs`.

## Running the real-browser tests in CI

The default CI job runs the test suite without a browser: tests that need Chromium detect it (`BROWSERX_CHROMIUM_PATH`, then `PATH`) and skip with a printed note. The `browser` job in the CI workflow runs them for real. It is opt-in: run the workflow manually (workflow dispatch) with `run_browser_tests` enabled and `chromium_path` set to the absolute path of a Chromium executable that exists on the runner host. The job fails if the path is not an executable and if any browser test would still skip.

## Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `browserx doctor` cannot find Chromium | Not installed or not on `PATH` | Install it or set `BROWSERX_CHROMIUM_PATH` |
| Browser exits at once in a container | Sandbox cannot start | Allow user namespaces, or use a launch profile with `--no-sandbox` knowingly |
| `429 capacity` | Queue full, quota reached or `max_browsers` exhausted | Check `browserx_queue_depth`, raise limits or add workers |
| `409 profile_locked` | A running browser holds the profile | Release the other session, or choose another `profile_id` |
| `409 stale_generation` | The lease moved on (recovery or handoff) | Read the session, then re-attach |
| `502 browser` on create | Launch failed or timed out | Check logs, `runtime.startup_timeout_secs`, the executable path and flags |
| `500` on create or attach of a snapshot session; the log says `unknown key_id` | No loaded key matches the snapshot's `key_id` | Add the old key file to `retired_snapshot_key_files`; see [key rotation](#snapshot-key) |
| Sessions `lost` after a restart | Their recovery was `none`, or recovery failed three times | Check the lease's `reason` field and the logs |
| Clients behind TLS get `ws://` URLs | `server.public_base_url` is not the external address | Set it to the `https://` URL clients use |
