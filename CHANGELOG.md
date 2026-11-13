# Changelog

All notable changes to BrowserX are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The project is pre-1.0; minor versions may contain breaking changes to configuration keys, the HTTP API, command-line interface and on-disk formats, and each such change is listed here.

## [Unreleased]

Initial development toward 0.1.0. Source-only: no binaries or images are published.

### Added

- **Sessions as leases.** Durable lease records with an identity, an owner, a time-to-live with renewal, an absolute lifetime cap, an idle timeout, a lifecycle state machine (`queued`, `allocating`, `active`, `idle`, `recovering`, `draining`, `lost`, `closed`) and a fencing generation. Every lease change is a compare-and-swap on the expected generation; a lost swap surfaces as `stale_generation`.
- **Controller tokens.** `bxt_` lease tokens, returned once and stored only as SHA-256 digests, compared in constant time; rotated by handoff.
- **Snapshot key rotation.** One active key seals new snapshots; retired keys (`storage.retired_snapshot_key_files`) open older ones.
- **Explicit persistence contracts.** `persistence` is `ephemeral`, `snapshot` or `profile`; there is no boolean "persistent" flag. Snapshots capture cookies, per-origin `localStorage` and open page URLs, sealed with AES-256-GCM (metadata bound as associated data), versioned per profile, written atomically with mode `0600`, pruned to `snapshot_keep`. Profile directories are created with mode `0700` under an exclusive lock.
- **Attach outcomes.** Every attach reports `resumed_same_process`, `restored_from_profile`, `restored_from_snapshot` or `fresh_process`.
- **Recovery.** Health monitor with unresponsive strikes, confirmed browser shutdown (graceful close, then process-group termination), relaunch with bounded attempts, `recovery = "none"` to end a session instead, and startup reconciliation of leases orphaned by a worker restart.
- **Handoff.** Token rotation with generation increment; relay connections bound to the old token are closed.
- **Dedicated and shared isolation.** One Chromium process per session, or one browser context per session in a warm shared browser behind a scoped CDP relay that injects the context into `Target.createTarget`, filters targets and events and refuses context, browser and system commands.
- **Scheduler.** Bounded FIFO admission queue with a deadline, per-owner quotas, `max_browsers`, shared-browser slots, warm pool, retirement by age and by contexts served, reaper and periodic snapshotter.
- **Egress forwarder.** A loopback forwarder per dedicated session: direct dialing with a destination policy that refuses private, loopback, link-local, carrier-grade NAT, multicast, reserved and metadata addresses (with an allow-list), or an upstream `http://`, `https://`, `socks5://` or `socks5h://` proxy with credentials kept out of the browser; plain-HTTP requests are tunnelled so CONNECT-only gateways work; `{session}` and `{generation}` username templates.
- **Launch profiles.** Named browser launch configurations (executable, headless, flags, environment); managed flags cannot be overridden. `{persona_seed}` in flags expands to a stable per-identity number.
- **HTTP API.** `/v1/sessions` (create, list, get, attach, renew, handoff, snapshot, release), `/v1/profiles`, `/v1/launch-profiles`, typed JSON errors with stable codes, and the authenticated `/cdp/{session}/{token}` WebSocket relay.
- **Operations.** Ops listener with `/healthz`, `/readyz` and Prometheus `/metrics`; graceful shutdown on `SIGINT` and `SIGTERM` with final snapshots.
- **Command line.** `browserx serve`, `config check`, `keys new`, `snapshot-key new`, `doctor` and the `session` client commands.
- **Documentation.** Design pages (architecture, sessions and leases, persistence, recovery, handoff, isolation and security, egress) and guides (getting started, configuration, API, CLI, CDP clients, upstream proxy, launch profiles, operations).
- **Repository.** CI with a code-owner authorization gate, linting, hashed public-hygiene checks, secret scanning, dependency policy (`cargo deny`) and a CodeQL and security workflow that runs once the repository is public.

### Known limitations

- The relay and the API speak plaintext `ws://` and `http://`; terminate TLS in front for anything beyond loopback or a trusted network.
- Shared-browser isolation is not a boundary against hostile tenants.
- Snapshots can be opened only by the active key or a key listed as retired; a snapshot sealed with any other key cannot be restored.
- Snapshots do not carry the JavaScript heap, `sessionStorage`, IndexedDB, Cache Storage, service workers, open sockets or origins that were never opened.
- Profile directories are not portable between machines or Chromium versions.
- Configuration is read at start; there is no hot reload.
