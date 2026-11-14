# Recovery

Browsers crash, get killed by the kernel and disappear with their worker. BrowserX detects the loss, replaces the browser when the session allows it, and tells the next client precisely what it got.

## Attach outcomes

Every attach reports one of four outcomes. The outcome describes how the session reached the browser you are now connected to.

| Outcome | Browser | State you can rely on |
| --- | --- | --- |
| `resumed_same_process` | The same live process | Everything: open pages, JavaScript heaps, sockets. Only the controller changed |
| `restored_from_profile` | A new process on the same profile directory | What Chromium persisted in the directory. No open pages, heaps or sockets |
| `restored_from_snapshot` | A new process with a snapshot replayed | Cookies, `localStorage` of the origins that were open, and the page URLs, reopened. No heaps, sockets, service workers, cache or other origins |
| `fresh_process` | A new, empty process | Nothing |

Rules for how the outcome is reported:

- If the browser is alive when the client attaches, the outcome is `resumed_same_process`, **unless** the session was recovered since the last attach. In that case the lease's `last_recovery` is reported once, on the first API attach (`POST .../attach`) after the recovery, and later attaches report `resumed_same_process`. A controller that was disconnected while recovery happened therefore always learns about it. Opening the relay WebSocket does not consume the pending outcome, so a client that reconnects its socket first and calls `attach` afterwards still sees it.
- If the browser is dead when the client attaches and recovery is allowed, the worker recovers synchronously (bounded) and reports the recovery's outcome.
- `POST /v1/sessions` also returns an `outcome`: `fresh_process` for a new browser, `restored_from_profile` or `restored_from_snapshot` when the new session started from an existing `profile_id`.

A client should branch on the outcome. For anything other than `resumed_same_process`, re-establish page state (navigate, re-run the steps that build in-memory state) before continuing. See [integrating CDP clients](../guides/cdp-clients.md#handling-the-outcome).

## Recovery policy

| `recovery` | When the browser is lost |
| --- | --- |
| `restore` (default) | Launch a replacement and restore what the persistence mode kept |
| `none` | Do not replace it: the session becomes `lost` (terminal). Choose this when starting over from nothing would be worse than failing |

## Detecting loss

The health monitor probes every browser every `health.probe_interval_secs` with a bounded protocol round trip (`Browser.getVersion`, timeout `health.probe_timeout_ms`) and checks whether the process has exited.

- **Exited:** the process is gone. Recovery starts at once.
- **Unresponsive:** the process is alive but did not answer. After `health.unresponsive_strikes` consecutive failed probes, the browser is treated as lost; it is shut down with confirmation before it is replaced, so two browsers never share a profile directory.
- **Healthy:** the strike counter resets.

## The recovery sequence

1. The lease moves to `recovering` (generation compare-and-swap).
2. The old browser is confirmed dead: `Browser.close` with a short grace period, then `SIGTERM` and, if needed, `SIGKILL` to its process group, then a wait for exit. Only then is the profile lock released and the temporary directory deleted.
3. A replacement is launched according to the persistence mode:
   - `profile`: re-acquire the lock, relaunch on the same directory (`restored_from_profile`);
   - `snapshot`: relaunch, replay the latest snapshot (`restored_from_snapshot`); with no snapshot yet, `fresh_process`;
   - `ephemeral`: relaunch empty (`fresh_process`).
4. The lease gets a new `browser_id`, generation + 1, `recoveries` + 1, and `last_recovery` set to the outcome. A relay connection that was bound to the old browser is closed; clients reconnect.
5. The lease returns to `idle` (it becomes `active` at the next attach), and an event is emitted for metrics (`browserx_recoveries_total{outcome}`).

Shared-isolation sessions recover by creating a fresh context (or a fresh shared browser if theirs died). If the shared browser died, every session that had a context in it recovers independently, but they share the replacement: a shared browser that is still launching counts as a candidate, so concurrent recoveries wait for it instead of each starting another browser. If the replacement fails to launch, the waiters retry and one of them launches the next.

A recovery that was interrupted (a failed lease write, say) leaves the lease in `recovering`; the reaper retries it, or releases it once the lease has expired.

A failed recovery is retried, at most **3 attempts**. After the third failure the session is `lost`.

## Startup reconciliation

A browser runs in its own process group and can outlive a crashed worker, so a starting worker first sweeps: every launched browser has a record (`<state_dir>/tmp/<browser_id>.json`: owner, process id, process group, start time, user-data directory). For each record whose owning worker is gone, the worker kills the process group **only if** a process in it carries the exact `--user-data-dir=` argument of the record (and, for the leader, the recorded start time, so a recycled process id is never signalled), then removes the temporary directory and the record. Records of a worker that is still running are left alone, and persistent profile directories are never deleted. Temporary directories without a record are removed once they are older than ten minutes. The sweep needs `/proc` (Linux); elsewhere it logs a warning and does nothing.

Any lease the worker then finds in a non-terminal state is orphaned: its browser no longer exists, whatever the record says. The worker sorts them:

- Leases that were `queued`, `allocating` or `draining` when the worker stopped, and leases that have passed their expiry, are closed: the session never finished starting or was already ending.
- Leases that were `active`, `idle` or `recovering` are recovered according to their recovery policy (outcome `restored_from_profile`, `restored_from_snapshot` or `fresh_process`), or marked `lost` when their policy is `none` or recovery fails.

A graceful shutdown (`SIGTERM`, `SIGINT`) writes a final snapshot for each snapshot session and stops every browser with confirmation, but leaves the leases non-terminal precisely so that the next worker recovers them. Clients that reconnect after a restart see the outcome on their next attach.

This makes a worker restart a recovery event, not a data-loss event, for sessions that kept `snapshot` or `profile` persistence. It does not make it invisible: page state is gone and the outcome says so.

## What recovery cannot do

- Resurrect page state, JavaScript heaps, sockets or in-flight navigations. Only an uninterrupted process has them.
- Recover a `profile` session on another machine. Use `snapshot` for portability.
- Recover state written after the last snapshot. With `snapshot`, up to `session.snapshot_interval_secs` of cookie and storage changes can be lost; call `snapshot` explicitly after a login or another state change that you cannot afford to lose.
- Guarantee that a site accepts restored cookies. Sites can invalidate sessions server-side.

## Observability

- `browserx_recoveries_total{outcome}` counts recoveries by outcome.
- `browserx_sessions{status}` shows sessions in `recovering` and `lost`.
- The lease's `reason` field says why the latest recovery or terminal transition happened.
