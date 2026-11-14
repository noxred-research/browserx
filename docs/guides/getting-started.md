# Getting started

This walk-through builds BrowserX, starts a worker on loopback, creates a session, attaches to it and then kills the browser on purpose to show what each persistence mode gives back.

## Requirements

- Linux (x86-64 or arm64). Other platforms are not tested.
- The Rust toolchain named in [`rust-toolchain.toml`](../../rust-toolchain.toml). `rustup` installs it on first use.
- A Chromium executable that can run headless: `chromium`, `chromium-browser`, `google-chrome`, `google-chrome-stable` or `chrome` on `PATH`, or any path in `BROWSERX_CHROMIUM_PATH`.
- A C compiler (SQLite is built into the binary).

## Build

```sh
git clone https://github.com/noxred-research/browserx.git
cd browserx
cargo build --release
```

The binary is `target/release/browserx`. The examples below assume it is on your `PATH`.

## Check the machine

```sh
browserx doctor
```

`doctor` finds Chromium, launches it, reports its version and shuts it down with confirmation. Fix whatever it reports before you go on. In a container the sandbox needs the seccomp profile from [launch profiles](launch-profiles.md#running-in-a-container); do not reach for `--no-sandbox` before you have read why.

## Configure

Create the state directory, an API key and the snapshot encryption key:

```sh
mkdir -p .browserx
browserx keys new dev
browserx snapshot-key new ./.browserx-keys/snapshot.key
```

`keys new` prints the key **once**, together with a TOML snippet holding only its SHA-256 digest. Save the key somewhere safe. Start from the example configuration and paste the snippet:

```sh
cp examples/browserx.toml browserx.toml
$EDITOR browserx.toml        # replace the example [[auth.api_keys]] with the printed snippet
browserx config check browserx.toml
```

## Start the worker

```sh
browserx serve --config browserx.toml
```

The public listener is on `127.0.0.1:7690`, the ops listener on `127.0.0.1:7691`:

```sh
curl -s http://127.0.0.1:7691/readyz
```

## Create a session

In another terminal:

```sh
export BROWSERX_SERVER=http://127.0.0.1:7690
export BROWSERX_API_KEY=<the key from keys new>

browserx session create --persistence snapshot
```

The output has the session id (`ses_...`), the lease token (`bxt_...`, shown **once**), the `cdp_url` and the `outcome` (`fresh_process`). Export the id and token:

```sh
export SES=ses_...
export BROWSERX_TOKEN=bxt_...
```

## Drive the browser

Point any CDP client at the `cdp_url`. To see it work without a library, list the browser's targets with a WebSocket tool of your choice, or use the client you already have: see [integrating CDP clients](cdp-clients.md). Open a page, log in to something you own, or just set a cookie.

Then ask for a snapshot so the state is stored right now, instead of waiting for the periodic one:

```sh
browserx session snapshot $SES
```

## Kill the browser

Find and kill the Chromium process that belongs to the session. Its user-data directory is under the state directory:

```sh
pkill -9 -f 'user-data-dir=.*\.browserx'
```

Within a few seconds the health monitor notices (`health.probe_interval_secs`), moves the session to `recovering` and relaunches. Now attach:

```sh
browserx session attach $SES
```

```json
{ "outcome": "restored_from_snapshot", ... }
```

The browser is new, the cookies are back, the open pages were reopened as new pages. Repeat the experiment with the other modes to see the difference:

| Session created with | After the kill, `attach` reports | What is back |
| --- | --- | --- |
| `--persistence ephemeral` | `fresh_process` | Nothing |
| `--persistence snapshot` | `restored_from_snapshot` | Cookies, `localStorage` of the open origins, the page URLs |
| `--persistence profile` | `restored_from_profile` | Whatever Chromium kept in the profile directory |

And without killing anything, a second `attach` reports `resumed_same_process`: same browser, same pages.

## Hand the session to another client

```sh
browserx session get $SES                      # note the current "generation"
browserx session handoff $SES --generation <n>
```

You get a new token and `cdp_url`; the old token no longer works. See [handoff](../design/handoff.md).

## Release

```sh
browserx session release $SES
```

For a snapshot session this writes a final snapshot first. The session ends `closed`; the snapshots stay under `.browserx/snapshots/<profile_id>/` for the next session that asks for the same `profile_id`:

```sh
browserx session create --persistence snapshot --profile-id <prf_...>
# outcome: restored_from_snapshot
```

## Docker

[`docker/Dockerfile`](../../docker/Dockerfile) builds the worker from source into a non-root image with Chromium from the distribution's packages, and [`docker/compose.yaml`](../../docker/compose.yaml) runs it with a state volume, a larger `/dev/shm`, dropped capabilities and a health check on the ops port. The container configuration [`docker/browserx.docker.toml`](../../docker/browserx.docker.toml) binds the listeners to all interfaces *inside* the container; Compose publishes them on the host's loopback only.

```sh
docker compose -f docker/compose.yaml run --rm --entrypoint browserx browserx \
  snapshot-key new /var/lib/browserx/keys/snapshot.key
docker compose -f docker/compose.yaml run --rm --entrypoint browserx browserx keys new dev
# put the printed sha256 into docker/browserx.docker.toml (or mount your own config), then:
docker compose -f docker/compose.yaml up --build
```

The container keeps Chromium's sandbox on. Compose starts it with [`docker/seccomp-chromium.json`](../../docker/seccomp-chromium.json), the default Docker seccomp profile plus the user-namespace syscalls the sandbox needs; with `docker run` pass `--security-opt seccomp=docker/seccomp-chromium.json`. `--no-sandbox` is an explicit opt-in with a real cost, described in [SECURITY.md](../../SECURITY.md#deployment-requirements). Run one worker per container or network namespace and no other untrusted local users in it: the DevTools port and the forwarders trust every local process. Allow the stop grace period (45 seconds in the Compose file) so final snapshots and confirmed browser shutdown can finish. The Docker files are for development and evaluation, see [SECURITY.md](../../SECURITY.md#supported-versions).

## Where next

- [Configuration reference](configuration.md) for limits, time-to-live and storage.
- [Operations](operations.md) before you put a worker in front of anything real.
- [Recovery](../design/recovery.md) for exactly what each outcome means.
