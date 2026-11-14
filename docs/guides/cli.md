# CLI reference

`browserx` is one binary with four kinds of commands: the worker (`serve`), local tools (`config`, `keys`, `snapshot-key`, `doctor`), clients of a running worker (`session`) and the AI-agent tools (`mcp`, `agent eval`).

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
browserx snapshot-key new ./.browserx-keys/snapshot.key
```

Missing parent directories are created with mode `0700`. The file is created with mode `0600` and the command **refuses to overwrite** an existing file. The format is `browserx-snapshot-key v1`, then `key_id=<hex8>` and `key=<base64 of 32 bytes>`. Keep it outside the configured `state_dir` (the worker refuses a key file inside it). Back it up separately from the snapshots; see [operations](operations.md#key-rotation).

## `browserx doctor`

Checks that this machine can run browsers.

```sh
browserx doctor
browserx doctor --config browserx.toml
```

It finds a Chromium executable (`BROWSERX_CHROMIUM_PATH`, then `PATH`), launches the default launch profile, reads the browser version, probes health, creates and disposes a browser context, shuts the browser down with confirmation and prints one line per check (`[ ok ]`, `[warn]`, `[FAIL]`). With `--config` (`-c`), it also validates the file, uses its runtime section (launch profiles, executable, temporary directory) and checks that the state directory is writable, the snapshot key is readable and the lease registry answers (a SQLite database that does not exist yet is created at the first start and reported as such). When the launch fails because of the sandbox, it prints a hint about the `--no-sandbox` launch profile argument. Exit status is non-zero when any check fails.

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

## `browserx mcp`

Serves the [MCP server](mcp.md) and holds its operator tools.

```sh
browserx mcp --config mcp.toml                      # MCP over stdio
browserx mcp --config mcp.toml --http 127.0.0.1:7692   # streamable HTTP
```

| Option | Meaning |
| --- | --- |
| `--config <path>`, `-c` | The MCP configuration (TOML); also read from `BROWSERX_MCP_CONFIG`. Required to serve |
| `--http [<addr>]` | Serve streamable HTTP instead of stdio. Without an address, `mcp.http.listen` is used. Needs `mcp.http.token_sha256`; a non-loopback address logs a warning |
| `--stdio` | With `--http`: serve stdio as well |

The server stops on `SIGINT` or `SIGTERM`, or when stdin closes (stdio only), and releases the sessions it created when `mcp.release_on_exit` is set.

| Utility | What it does |
| --- | --- |
| `browserx mcp check <path>` | Validates a configuration and prints the capabilities, the tools it enables, the browsing scope, the audit path, the safety profile and Rule of Two mode, the manifest and grant paths and whether a model is configured |
| `browserx mcp token new` | Prints an HTTP bearer token (`bxm_...`) **once** and the `[mcp.http] token_sha256` line that authorizes it |
| `browserx mcp audit verify <path>` | Recomputes the audit log's hash chain; exits non-zero at the first edited, removed or reordered entry and prints the last hash to store off the host |
| `browserx mcp operator-key new <key_id>` | Prints a new operator key line, `key_id = <64 hex digits>`, **once**; append it to the key file (mode `0600`) named by `[operator] keys_file` |
| `browserx mcp manifest verify <path> --keys <file> [--signature <file>]` | Checks an engagement manifest and its detached signature offline and prints its engagement, operator, signing key, digest, impact, hosts and whether it is active now; exits non-zero when the signature is missing or invalid |
| `browserx mcp manifest sign <path> --keys <file> [--key-id <id>]` | Checks that the manifest parses and writes `<path>.sig`. `--key-id` is needed when the key file holds several keys |
| `browserx mcp grant verify <path> --keys <file> [--signature <file>]` | Like `manifest verify`, for a scope grant |
| `browserx mcp grant sign <path> --keys <file> [--key-id <id>]` | Like `manifest sign`, for a scope grant or a proposal a model wrote after your review |
| `browserx mcp approvals list --config <path>` | Lists the pending out-of-band approvals: id, tool, action class, origin, reasons and whether each is already approved |
| `browserx mcp approvals approve <id> --config <path> [--key-id <id>]` | Signs one pending approval with the operator key; the client then retries with `approval_id` |

See the [MCP guide](mcp.md#the-action-gate) for what the manifest, grant and approval files mean.

## `browserx agent eval`

Runs an adversarial evaluation of the MCP server's enforcement layers with a real browser and reports, per layer, what was attempted, what was blocked and what escaped.

```sh
browserx agent eval --suite <path> --report report.json --seed 7
```

| Option | Meaning |
| --- | --- |
| `--suite <path>` | The suite to run, described by a versioned `suite.json` |
| `--report <path>` | Where to write the report (JSON) |
| `--seed <n>` | Fixes the order of the cases, so a run can be repeated exactly |
| `--mutate <layer>` | Only in a build with the `fault-injection` feature, which no release build enables: switches one enforcement layer off for a harness self-test. The layers are `scope`, `grant`, `ledger`, `classifier`, `stale_ref` and `redaction`. A run with a layer off is expected to report escapes and fail: that is how the suite proves it notices |

The command starts an offline fixture server on the loopback interface (no external network is used) and launches a real Chromium, found the way [`browserx doctor`](#browserx-doctor) finds it. When Chromium is missing the command exits with status `2` and a message, so a CI lane cannot pass without a browser.

The report is JSON. Besides the individual case results it has a matrix per enforcement layer with the numbers `attempted`, `blocked` and `escaped`.

| Exit status | Meaning |
| --- | --- |
| `0` | Every case passed and there was no deterministic escape |
| `2` | Chromium is missing |
| other non-zero | A case failed, a deterministic layer let an attempt escape, or the run could not complete; the message and the report say which |

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
browserx snapshot-key new ./.browserx-keys/snapshot.key

# run a worker
browserx serve --config browserx.toml --log-format json

# use it
export BROWSERX_SERVER=http://127.0.0.1:7690 BROWSERX_API_KEY=<key>
browserx session create --persistence profile --label purpose=smoke
browserx session list --status active,idle
```
