# Configuration reference

`browserx serve --config <path>` reads one TOML file. Every table rejects unknown keys (`deny_unknown_fields`): a misspelled key is a startup error, not a silently ignored setting. Validate a file without starting anything:

```sh
browserx config check browserx.toml
```

A commented example is in [`examples/browserx.toml`](../../examples/browserx.toml). Durations are whole seconds (`*_secs`) unless the key says `_ms`. Relative paths are relative to the working directory of the process; use absolute paths in production.

## `[server]`

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | `"127.0.0.1:7690"` | Address of the public listener: `/v1/...` and `/cdp/...` |
| `ops_listen` | `"127.0.0.1:7691"` | Address of the ops listener: `/healthz`, `/readyz`, `/metrics` |
| `public_base_url` | `"http://127.0.0.1:7690"` | The externally reachable base URL. `cdp_url` values are built from it with the scheme switched to `ws`/`wss`. Set it to the address clients really use (for example behind a TLS reverse proxy) |
| `max_relay_connections_per_session` | `4` | Relay (WebSocket) connections one session may have open. More are refused with `429 capacity`. `1`..`256` |
| `scoped_relay_max_message_bytes` | `16777216` | Largest WebSocket message, in bytes, on a shared-session relay (dedicated relays allow 64 MiB). `65536`..`67108864` |
| `header_read_timeout_secs` | `10` | Time a client has to send a complete request head on either listener; also closes idle keep-alive connections. `1`..`300` |
| `max_connections` | `1024` | Open connections the public listener keeps (relay connections count); further ones are closed at once |
| `ops_max_connections` | `64` | The same for the ops listener |

Both listeners speak plaintext. Keep them on loopback or a trusted network, or terminate TLS in front. See [isolation and security](../design/isolation-and-security.md#transport).

## `[[auth.api_keys]]`

One table per API key. Create keys with `browserx keys new <name>`, which prints the key once and the snippet to paste here.

| Key | Default | Meaning |
| --- | --- | --- |
| `name` | required | Owner name. Sessions belong to the key's name; names must be unique |
| `sha256` | required | Lowercase hex SHA-256 of the key. The key itself is never stored |
| `max_sessions` | `16` | Most non-terminal sessions this owner may hold (at least 1). Over it: `429 capacity` |

```toml
[[auth.api_keys]]
name = "dev"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
max_sessions = 16
```

At least one key is required to start. Names are 1 to 64 characters without control characters and must be unique. Keys are compared by digest in constant time.

## `[pool]`

| Key | Default | Meaning |
| --- | --- | --- |
| `max_browsers` | `8` | Most browser processes at once (dedicated and shared, including ones being launched or torn down) |
| `max_contexts_per_browser` | `8` | Browser contexts per shared browser |
| `warm_shared_browsers` | `0` | Idle shared browsers to keep running for fast allocation. Must not exceed `max_browsers` |
| `queue_capacity` | `64` | Admissions that may wait for capacity. A full queue answers `429` at once |
| `queue_timeout_secs` | `30` | How long an admission may wait. After it: `429 capacity` |
| `browser_max_age_secs` | `3600` | A shared browser older than this takes no new contexts and retires when empty |
| `browser_max_contexts_served` | `1000` | A shared browser that has served this many contexts retires when empty |

## `[session]`

| Key | Default | Meaning |
| --- | --- | --- |
| `default_ttl_secs` | `600` | Time-to-live when the request names none. Must not exceed `max_ttl_secs` |
| `max_ttl_secs` | `3600` | Largest time-to-live a request may ask for (a larger value is refused); also bounds renewals |
| `max_lifetime_secs` | `86400` | Largest absolute lifetime a request may ask for, and the default. Renewals cannot extend past it. A request's `idle_timeout_secs` may not exceed it either. Every duration in this section is limited to ten years |
| `default_idle_timeout_secs` | `300` | Release a session this long after its last controller detached, when the request names no idle timeout |
| `snapshot_interval_secs` | `60` | Interval of periodic snapshots for `snapshot` sessions |
| `snapshot_keep` | `5` | Snapshot versions kept per profile; older ones are pruned. Must be at least 1 |
| `terminal_retention_secs` | `86400` | How long closed and lost sessions stay readable before they are purged |

## `[storage]`

| Key | Default | Meaning |
| --- | --- | --- |
| `state_dir` | `"./.browserx"` | Root of everything BrowserX persists. The worker creates it, `snapshots/`, `profiles/` and `tmp/` with mode `0700` |
| `snapshot_key_file` | `"./.browserx-keys/snapshot.key"` | The active snapshot encryption key (create with `browserx snapshot-key new`). Seals every new snapshot. Mode `0600`. Must be **outside** `state_dir`: browsers run as the worker's uid, so a key inside the state directory could be read through a browser. A path inside `state_dir` is a startup error |
| `retired_snapshot_key_files` | `[]` | Earlier key files that may only open old snapshots; see [key rotation](operations.md#snapshot-key). Each needs a distinct `key_id` |

Layout under `state_dir`:

| Path | Content |
| --- | --- |
| `browserx.db` | SQLite lease registry (WAL mode; `-wal` and `-shm` files appear beside it while running) |
| `snapshots/<profile_id>/` | Sealed snapshots: `<version>.snap` and `<version>.meta.json`, mode `0600` |
| `profiles/<profile_id>/` | Persistent profile directories (`0700`), each with `.browserx.lock` |
| `profiles/.owners/` | One small file per persistent identity naming the API key (owner) that created it |
| `tmp/` | Temporary user-data directories of ephemeral sessions, deleted after the browser is confirmed dead |
| `downloads/<session_id>/` | Where a relay client's browser downloads land (the relay forces the path); removed when the session's last relay connection closes and emptied at startup |

## `[health]`

| Key | Default | Meaning |
| --- | --- | --- |
| `probe_interval_secs` | `5` | Interval between browser health probes |
| `probe_timeout_ms` | `3000` | Deadline of one probe |
| `unresponsive_strikes` | `3` | Consecutive failed probes before a browser counts as lost and is recovered |

## `[egress]`

| Key | Default | Meaning |
| --- | --- | --- |
| `block_private` | `true` | Refuse private, loopback, link-local, CGNAT, multicast, reserved and metadata destinations. See [egress](../design/egress.md#destination-policy) |
| `allow_cidrs` | `[]` | CIDR blocks or single addresses exempt from blocking (at most 1024) |

## `[runtime]`

| Key | Default | Meaning |
| --- | --- | --- |
| `default_launch_profile` | `"default"` | Profile used when a session names none. Must exist |
| `startup_timeout_secs` | `30` | How long a browser launch may take before the process is killed. At most `600` (larger values are a startup error) |
| `cdp_max_message_bytes` | `67108864` | Largest single reply the worker's own DevTools connection to a browser accepts (1 MiB to 256 MiB). A bigger reply drops that connection, which is reopened on the next use; the browser keeps running |

### `[runtime.launch_profiles.<name>]`

| Key | Default | Meaning |
| --- | --- | --- |
| `executable` | discovered | Browser executable. Absent: `BROWSERX_CHROMIUM_PATH`, then `chromium`, `chromium-browser`, `google-chrome`, `google-chrome-stable`, `chrome` on `PATH` |
| `headless` | `true` | Run with `--headless=new` |
| `args` | `[]` | Extra command-line flags. `{persona_seed}` is replaced with a stable per-identity number; see [launch profiles](launch-profiles.md#per-identity-seeds-persona_seed) |
| `env` | `{}` | Environment variables for the browser process, added to a small allow-list the browser inherits from the worker (`PATH`, `HOME`, `TMPDIR`, `LANG`, `LC_*`, `TZ`, `XDG_*` directories, fontconfig and display variables). The rest of the worker's environment, including credentials, is not passed on |

`args` may not set managed flags (`--remote-debugging-*`, `--user-data-dir`, `--proxy-server`, `--proxy-bypass-list`, `--proxy-pac-url`, `--proxy-auto-detect`, `--no-proxy-server`, `--headless`). Such a profile is rejected at startup. If no profile is defined, a `default` profile with the defaults above is created. See [launch profiles](launch-profiles.md).

```toml
[runtime]
default_launch_profile = "default"

[runtime.launch_profiles.default]
headless = true
args = []

[runtime.launch_profiles.wide]
headless = true
args = ["--window-size=1920,1080"]
```

## `[database]` and `[object_store]`

Both are optional. Without them the worker keeps its lease registry in SQLite and its sealed snapshots under `storage.state_dir`. `[database]` moves the lease registry to PostgreSQL or MariaDB (with a required `node`), and `[object_store]` moves sealed snapshots to an S3-compatible object store. Every key is described in the [backends guide](backends.md).

## Environment variables

| Variable | Used by | Meaning |
| --- | --- | --- |
| `BROWSERX_CHROMIUM_PATH` | worker, `doctor` | Browser executable for profiles without `executable` |
| `BROWSERX_SERVER` | client commands | Base URL of the worker (`--server`) |
| `BROWSERX_API_KEY` | client commands | API key (`--api-key`) |
| `BROWSERX_TOKEN` | client commands | Lease token (`--token`) |
| `RUST_LOG` | all | Log filter, for example `info,browserx_pool=debug` |

## Validation rules

`browserx serve` and `browserx config check` reject a file when:

- a key is unknown, or a value has the wrong type;
- no `[[auth.api_keys]]` entry exists;
- an API key name is empty, longer than 64 characters, contains control characters or is duplicated, its `sha256` is not 64 lowercase hex characters, or its `max_sessions` is `0`;
- `listen` or `ops_listen` is not a socket address (`host:port` with an IP, for example `127.0.0.1:7690`), or `public_base_url` is not an `http://` or `https://` URL;
- a count that must be positive is `0`, or a duration is `0`;
- `default_ttl_secs` is greater than `max_ttl_secs`, or `warm_shared_browsers` is greater than `max_browsers`;
- the default launch profile does not exist, or a launch profile sets a managed flag;
- an `allow_cidrs` entry does not parse.
