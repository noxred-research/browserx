# CLI reference

`browserx` is one binary with three kinds of commands: the worker (`serve`), local tools (`config`, `keys`, `snapshot-key`, `doctor`) and clients of a running worker (`session`).

```text
browserx [--log-format json|text] <command>
```

| Global option | Default | Meaning |
| --- | --- | --- |
| `--log-format json\|text` | `text` | Log output format (also `BROWSERX_LOG_FORMAT`). The filter comes from `RUST_LOG` (default `info`) |
| `--version`, `--help` | | Version and usage. Every command has `--help` |

## `browserx serve`

Runs the worker: the public listener, the ops listener, the scheduler and its background tasks.

```sh
browserx serve --config browserx.toml
```

| Option | Meaning |
| --- | --- |
| `--config <path>`, `-c` | TOML configuration; see the [configuration reference](configuration.md). Required; also read from `BROWSERX_CONFIG` |

`SIGINT` and `SIGTERM` start a graceful shutdown: stop admission (`/readyz` fails), close relay connections, give open requests up to 15 seconds, write final snapshots, confirm every browser is gone, exit. The worker refuses to start on an invalid configuration, a missing or unreadable snapshot key file, or an address it cannot bind.

## `browserx config check`

Validates a configuration file without starting anything. Exit status `0` when valid, non-zero with the reason otherwise.

```sh
browserx config check browserx.toml
```

## `browserx keys new`

Creates an API key.

```sh
browserx keys new dev [--max-sessions 16]
```

The name is 1 to 64 characters of letters, digits, `-`, `_` or `.`; `--max-sessions` (default 16, at least 1) is written into the printed snippet. The command prints the key **once** (`bxk_` followed by 64 hex characters, 256 random bits) and the configuration snippet that holds its SHA-256 digest:

```text
API key for `dev` (shown once; store it in a secret manager):
bxk_...

Add this to your configuration file (it contains only the key's SHA-256):
[[auth.api_keys]]
name = "dev"
sha256 = "<digest>"
max_sessions = 16
```

The worker never sees the key itself, only the digest in the configuration. Nothing is written to disk by this command.

## `browserx snapshot-key new`

Generates the snapshot encryption key file.

```sh
browserx snapshot-key new ./.browserx/snapshot.key
```

Missing parent directories are created with mode `0700`. The file is created with mode `0600` and the command **refuses to overwrite** an existing file. The format is `browserx-snapshot-key v1`, then `key_id=<hex8>` and `key=<base64 of 32 bytes>`. Back it up separately from the snapshots; see [operations](operations.md#key-rotation).

## `browserx doctor`

Checks that this machine can run browsers.

```sh
browserx doctor
browserx doctor --config browserx.toml
```

It finds a Chromium executable (`BROWSERX_CHROMIUM_PATH`, then `PATH`), launches the default launch profile, reads the browser version, probes health, creates and disposes a browser context, shuts the browser down with confirmation and prints one line per check (`[ ok ]`, `[warn]`, `[FAIL]`). With `--config` (`-c`), it also validates the file, uses its runtime section (launch profiles, executable, temporary directory) and checks that the state directory is writable and the snapshot key is readable. When the launch fails because of the sandbox, it prints a hint about the `--no-sandbox` launch profile argument. Exit status is non-zero when any check fails.

## `browserx session`

Client commands for a running worker. They call the [HTTP API](api.md).

| Common option | Environment | Meaning |
| --- | --- | --- |
| `--server <url>` | `BROWSERX_SERVER` | Base URL of the public listener. Default `http://127.0.0.1:7690` |
| `--api-key <key>` | `BROWSERX_API_KEY` | API key |
| `--token <token>` | `BROWSERX_TOKEN` | Lease token, for commands that need one |

The options can be given before or after the subcommand. Output is the JSON response, pretty-printed, on standard output; errors go to standard error with a non-zero exit status, and carry the API error `code`. Prefer the environment variables over `--api-key` and `--token`: command-line arguments are visible to other users of the machine.

### `session create`

```sh
browserx session create --persistence snapshot --isolation dedicated
```

| Option | Maps to | Meaning |
| --- | --- | --- |
| `--launch-profile <name>` | `launch_profile` | Launch profile |
| `--persistence <mode>` | `persistence` | `ephemeral`, `snapshot` or `profile` |
| `--isolation <mode>` | `isolation` | `dedicated` (`dedicated_browser`) or `shared` (`shared_browser`) |
| `--profile-id <id>` | `profile_id` | Reuse a persistent identity |
| `--proxy-url <url>` | `proxy.url` | Upstream proxy URL |
| `--proxy-username <template>` | `proxy.username` | May contain `{session}` and `{generation}` |
| `--proxy-password <secret>` | `proxy.password` | Also read from `BROWSERX_PROXY_PASSWORD`; prefer the environment, because arguments are visible in process listings |
| `--ttl-secs <n>` | `ttl_secs` | Lease time-to-live |
| `--max-lifetime-secs <n>` | `max_lifetime_secs` | Absolute lifetime cap |
| `--idle-timeout-secs <n>` | `idle_timeout_secs` | Idle timeout |
| `--recovery <policy>` | `recovery` | `restore` or `none` |
| `--label <KEY=VALUE>` | `labels` | Repeatable |

`--proxy-username` and `--proxy-password` need `--proxy-url`. Flags you leave out are left out of the request, so the server's defaults apply.

Prints the created session, the token (**once**), the `cdp_url` and the `outcome`.

### `session list`

```sh
browserx session list [--status active]
```

Lists your sessions, optionally filtered by status.

### `session get`

```sh
browserx session get <session-id>
```

Prints one session.

### `session attach`

```sh
browserx session attach <session-id> --token <token>
```

Attaches (recovering the browser first if it is gone) and prints the `outcome`, the generation and the `cdp_url`.

### `session renew`

```sh
browserx session renew <session-id> --generation <n> [--ttl-secs <n>]
```

Extends the lease. `--generation` is required: pass the generation you last saw.

### `session handoff`

```sh
browserx session handoff <session-id> --generation <n>
```

Rotates the token. `--generation` is required. Prints the new token (once) and the new `cdp_url`. The old token stops working.

### `session snapshot`

```sh
browserx session snapshot <session-id>
```

Writes a snapshot now and prints its metadata. Only sessions with `persistence = snapshot` can be snapshotted.

### `session release`

```sh
browserx session release <session-id> [--generation <n>]
```

Releases the session. For a snapshot session a final snapshot is written first. The lease token is optional: the owning API key may release without it.

## Exit status

| Status | Meaning |
| --- | --- |
| `0` | Success |
| non-zero | Failure; the message says why. API failures print the HTTP status, the error `code` and the message (for example `409 stale_generation: ...`) |

## Examples

```sh
# one-time setup
browserx doctor
browserx keys new ci
browserx snapshot-key new ./.browserx/snapshot.key

# run a worker
browserx serve --config browserx.toml --log-format json

# use it
export BROWSERX_SERVER=http://127.0.0.1:7690 BROWSERX_API_KEY=<key>
browserx session create --persistence profile --label purpose=smoke
browserx session list --status active,idle
```
