# Custom launch profiles and browser builds

A *launch profile* names one way to start a browser: which executable, which extra flags, which environment, headless or headed. Sessions select a profile with `launch_profile`; without one the worker uses `runtime.default_launch_profile`.

## Define profiles

```toml
[runtime]
default_launch_profile = "default"

[runtime.launch_profiles.default]
headless = true
args = []

[runtime.launch_profiles.large-viewport]
headless = true
args = ["--window-size=1920,1080", "--lang=en-US"]

[runtime.launch_profiles.pinned-build]
executable = "/opt/browsers/chromium-build-A/chrome"
headless = true
args = ["--disable-gpu"]
env = { TZ = "UTC" }
```

Select one per session:

```sh
browserx session create --launch-profile large-viewport
```

`GET /v1/launch-profiles` (and the CLI) list what a worker offers.

## What the worker controls, and what you control

The worker always starts the browser with a set of **managed** flags:

| Managed | Why |
| --- | --- |
| `--remote-debugging-port=0` (and every `--remote-debugging-*`) | The worker needs a private loopback DevTools endpoint and must be the only one that has it |
| `--user-data-dir=<dir>` | The profile directory is part of the persistence contract and the lock |
| `--proxy-server`, `--proxy-bypass-list`, `--proxy-pac-url`, `--proxy-auto-detect`, `--no-proxy-server` | Egress goes through the forwarder or nowhere |
| `--force-webrtc-ip-handling-policy`, `--webrtc-ip-handling-policy` | With a forwarder, WebRTC may use only proxied UDP (`disable_non_proxied_udp`) |
| `--headless=new` | Controlled by the `headless` key |
| `--no-first-run --no-default-browser-check --disable-background-networking --disable-sync --disable-default-apps --password-store=basic --use-mock-keychain` | A quiet, predictable browser without prompts or stored-password back ends |

Everything else is yours through `args`. A profile that tries to set a managed flag is rejected when the worker starts, so a mistake cannot silently weaken the contract.

## Per-identity seeds: `{persona_seed}`

An argument in `args` may contain the placeholder `{persona_seed}`. At launch the worker replaces it with a decimal number derived from the session's persistent identity: the first 8 bytes of a SHA-256 digest of the profile id, read as an unsigned integer. A session without a persistent identity uses its session id instead. The seed is therefore the same every time the same identity (or, for ephemeral sessions, the same session) gets a browser, including after recovery, and different for different identities. It contains digits only, so it cannot add flags to the command line.

Standard Chromium ignores flags it does not know, so the placeholder only matters for a browser build that accepts a per-identity seed flag; use it to give such a build a stable value per identity, for example `args = ["--example-seed={persona_seed}"]` (a made-up flag name).

## Choosing the executable

Resolution order for a profile:

1. `executable` in the profile, if set;
2. `BROWSERX_CHROMIUM_PATH`;
3. the first of `chromium`, `chromium-browser`, `google-chrome`, `google-chrome-stable`, `chrome` found on `PATH`.

`browserx doctor --config browserx.toml` launches the default launch profile once and prints the browser version, so you can confirm which build it runs. To check another profile, make it the default in a scratch configuration.

## Using a different browser build

The core has no knowledge of which Chromium it runs. A build that is **Chromium-compatible**, meaning it accepts the standard command-line flags and exposes the DevTools Protocol that BrowserX uses, plugs in as a launch profile (`executable` and, if the build needs them, `args` and `env`) and nothing else changes: leases, persistence, recovery, handoff and the relay behave the same.

Reasons to do this: a pinned, reproducible build for testing; a build with additional policies that your organization maintains; a build packaged with its own libraries. Requirements the build must meet:

- It supports `--remote-debugging-port=0` and prints `DevTools listening on ws://...` on standard error, as Chromium does.
- It supports the CDP domains used for state capture and restore: `Browser`, `Target`, `Storage`, `Network`, `Runtime`.
- It honors `--user-data-dir` and `--proxy-server`.
- It exits when asked (`Browser.close`, then `SIGTERM`).

BrowserX makes no claim about how a modified build behaves toward any website. You are responsible for the licenses of the build and for your right to run it.

## Running in a container

Chromium's sandbox needs namespaces that many container runtimes restrict. Prefer a runtime that allows them and a non-root user. If you must disable the sandbox, do it explicitly and knowingly in a profile:

```toml
[runtime.launch_profiles.container]
headless = true
args = ["--no-sandbox", "--disable-dev-shm-usage"]
```

`--disable-dev-shm-usage` makes Chromium use `/tmp` instead of a small `/dev/shm`; alternatively mount a larger `/dev/shm` (`shm_size`). A no-sandbox browser has the privileges of its process: do not run it as root, and treat every page as able to reach whatever the process can.

## Headed browsers

`headless = false` needs a display. On a server, run an X server or compositor for the worker's user and set `env = { DISPLAY = ":99" }` in the profile. Headed profiles are for debugging and for pages that need a real window; they cost more memory.

## Ideas for several profiles

| Profile | Purpose |
| --- | --- |
| `default` | Headless, no extra flags |
| `debug` | Headed with a `DISPLAY`, for looking at what a session does |
| `pinned` | A specific Chromium build for reproducible runs |
| `container` | `--no-sandbox` on a worker you accept that trade-off for |

Keep the set small: every profile is a thing to test and to patch.
