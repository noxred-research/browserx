# Persistence

BrowserX has no `persistent: true` switch. "Keep my state" can mean keeping a directory on disk, keeping a portable copy of the logins, or keeping a running process, and each of those is a different engineering contract with different guarantees and costs. The `persistence` field of the session spec names the contract.

| Mode | Survives | Fidelity | Portable across workers | Cost |
| --- | --- | --- | --- | --- |
| `ephemeral` (default) | Nothing | None | n/a | Cheapest; a lost browser is replaced by an empty one |
| `snapshot` | Cookies and per-origin `localStorage`, plus open page URLs, as encrypted versioned snapshots | Logical state only | Yes | Periodic capture; a sealed file per version |
| `profile` | The browser's own user-data directory | Highest on one worker | No | One locked directory; one browser at a time |

None of the modes preserves a live JavaScript heap, open sockets or in-flight requests. Only the browser process itself does that, which is why an attach that reaches the *same live process* is a separate outcome (`resumed_same_process`) and why a replacement browser is always reported as something else.

## `ephemeral`

The browser runs in a temporary user-data directory under `<state_dir>/tmp`. It is deleted after the process is confirmed dead. If the browser is lost and the recovery policy is `restore`, a fresh empty browser is launched (outcome `fresh_process`).

## `snapshot`

A snapshot is portable authentication state, not a process checkpoint.

### What is captured

| Included | Not included |
| --- | --- |
| All cookies of the session's browser context (`Storage.getCookies` for a context, `Network.getAllCookies` for the default context) | The JavaScript heap, DOM state, scroll positions |
| `localStorage` of each origin that has an open `http` or `https` page at capture time (deduplicated by origin) | `sessionStorage`, IndexedDB, Cache Storage, service worker registrations and runtime |
| The URLs of the top-level pages, which are reopened on restore | Origins that were never opened during the session, open sockets, WebSocket connections, in-flight requests |

`localStorage` is read by the browser itself (the `DOMStorage` DevTools domain), for the origin the browser reports for each page. No script runs in the page, so a page cannot influence which origin its entries are filed under or what they contain. An origin whose storage exceeds the per-origin limit, or whose reply is too large for the worker's own DevTools connection, is skipped with a warning.

Capture is bounded: at most 20,000 cookies, 64 origins, 5 MiB of `localStorage` per origin and 64 page URLs, and 48 MiB in total (the JSON size of cookies, storage and URLs), below the 64 MiB limit of a sealed snapshot. A session whose state is larger than the total budget fails the capture with an `invalid_request` error that names the budget; clear cookies or storage to make it snapshot-able.

### When snapshots are taken

- on demand: `POST /v1/sessions/{id}/snapshot` or `browserx session snapshot` (only sessions with `persistence = "snapshot"`; others answer `conflict`);
- periodically every `session.snapshot_interval_secs` while the session runs;
- once more during release (`draining`), before the browser is closed.

A snapshot write carries the generation of the session that produced it. A writer that has been superseded (by recovery or handoff) is refused, so an old controller's state can never overwrite a newer one.

### How they are stored

Snapshots are keyed by profile id: `<state_dir>/snapshots/<profile_id>/<version>.snap` (sealed bytes) with a `.meta.json` beside it. Versions are monotonic per profile (1, 2, 3, ...). Files are written atomically (temporary file, rename, fsync) with mode `0600`. `session.snapshot_keep` newest versions are retained; older ones are pruned.

The metadata holds the profile id, version, the session and generation that wrote it, the creation time, the ciphertext size and the `key_id` of the encryption key. It holds no cookie values.

### Encryption

Snapshots are sealed before they reach the store, so the store only ever sees ciphertext.

- **Algorithm:** AES-256-GCM with a random 96-bit nonce per snapshot.
- **Bound metadata:** the associated data is the canonical JSON of `(profile_id, version, session_id, generation)`. Moving a sealed blob under a different profile, version or session makes decryption fail, so metadata cannot be swapped.
- **Key file:** `snapshot_key_file`, created with `browserx snapshot-key new <path>` (mode `0600`, parent directories `0700` when created, refuses to overwrite; loading requires an owner-only file owned by the current user). Format: a header line `browserx-snapshot-key v1`, then `key_id=<hex8>` and `key=<base64 of 32 bytes>`.
- **Rotation:** one key is active and seals new snapshots; earlier keys can be loaded as retired, open-only keys (`storage.retired_snapshot_key_files`). The `key_id` in each snapshot's metadata selects the key that opens it.
- **Key hygiene:** keys are held in zeroizing buffers, borrowed rather than copied, and wiped on drop. Plaintext with a `format_version` newer than the worker understands is refused.

Treat snapshots as credentials: a snapshot holds session cookies. Protect the key files separately from the snapshot directory, and back both up (see [operations](../guides/operations.md#key-rotation)).

### How they are restored

When a snapshot session is created with an existing `profile_id`, or when its browser is replaced, the worker launches a new browser, opens the context, replays the cookies (`Storage.setCookies`), then for each origin with stored data opens a blank page in the context, navigates to the origin, sets the `localStorage` entries and closes it, and finally reopens the saved page URLs. The attach that follows reports `restored_from_snapshot`.

A snapshot restored into a new browser starts new pages: page scripts run again, in-memory application state is gone, and a site may decide to log the client out regardless of its cookies. Clients must treat the outcome as "credentials restored, page state not".

## `profile`

The session gets a dedicated user-data directory at `<state_dir>/profiles/<profile_id>`, created with mode `0700` and held under an exclusive, non-blocking lock on `<dir>/.browserx.lock` for as long as a browser runs on it.

- Highest fidelity on one worker: whatever Chromium persists in its profile (cookies, `localStorage`, IndexedDB, caches, and so on) is there when the next browser starts on it.
- A directory belongs to **one** browser process. A second session asking for the same `profile_id` while a session on this worker uses it is refused with `conflict` (HTTP `409`); a directory locked by another process (for example a second worker on the same `state_dir`) is refused with `profile_locked` (also `409`).
- It needs `isolation = "dedicated_browser"`.
- It is **not portable**. A profile directory is tied to the machine, the filesystem and the Chromium version that wrote it. If the worker moves, use `snapshot`.
- Recovery relaunches a browser on the same directory and reports `restored_from_profile`. The lock is released when the browser is confirmed gone, and re-taken for the replacement.
- `DELETE /v1/profiles/{id}` erases the snapshots and the profile directory. It is refused while a session uses the profile.
- Profile sessions are not snapshotted; their durable state is the directory itself.

## Choosing a mode

| You need | Use |
| --- | --- |
| Disposable work, no state | `ephemeral` |
| Logins that follow the session to another worker, small state, encrypted at rest | `snapshot` |
| Highest fidelity (IndexedDB, caches, everything Chromium keeps), staying on one machine | `profile` |
| To keep a *running* page, heap and sockets | Keep the session alive and reconnect: `resumed_same_process`. No persistence mode substitutes for it |
