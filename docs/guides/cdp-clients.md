# Integrating CDP clients

Any client that can connect to a Chrome DevTools Protocol WebSocket can use a BrowserX session. This page describes the integration contract in client-neutral terms. Your client's documentation says how to connect it to a `ws://` browser endpoint; BrowserX supplies the endpoint and the lifecycle around it.

## The flow

1. **Create** a session: `POST /v1/sessions` (or `browserx session create`). Keep the `token` and the `cdp_url`.
2. **Attach**: `POST /v1/sessions/{id}/attach` to learn the `outcome`. (The create response already carries the first one.)
3. **Connect** your CDP client to the `cdp_url`.
4. **Work.** Renew the lease before `expires_at`, or let it lapse when you are done.
5. **Release** the session with `DELETE`, so the browser is shut down and a snapshot is taken, instead of waiting for expiry.

## Which endpoint do I get?

| Session | `cdp_url` points at | Behaves like |
| --- | --- | --- |
| `dedicated_browser` | A browser-level endpoint relayed to your own Chromium process | A normal remote browser: create targets, attach to them, use any domain |
| `shared_browser` | A scoped endpoint | The same, restricted to your browser context. Creating or disposing contexts, `Browser.close` and cross-context attachment are refused |

A client that needs `Target.createBrowserContext` for its own purposes needs dedicated isolation. A client written for a browser-level endpoint usually works unchanged with either.

## Connecting

The URL has the form `ws://<host>:<port>/cdp/<session_id>/<token>`. It is already complete: no extra headers or query string are needed, so it works with clients that accept only a URL. Give it to your client as the browser-level WebSocket endpoint, not as an HTTP debugger address. The worker serves the WebSocket route only (no HTTP endpoint discovery routes), so a client that insists on discovering the endpoint over HTTP must be given the WebSocket URL directly.

- Message size is capped at 64 MiB per message.
- The server pings every 30 seconds and closes a connection that stays silent (no frame, pongs included) for 120 seconds. Ordinary WebSocket clients answer pings on their own.
- Plaintext `ws://` is only suitable on loopback or a trusted network. For remote use, terminate TLS in a reverse proxy and set `server.public_base_url` to the external `https://` address so that `cdp_url` is returned as `wss://...`.
- Do not log the URL: the path is the credential.

## Handling the outcome

Every `attach` (and `create`) returns an `outcome`. Make the client branch on it:

```text
outcome == resumed_same_process  -> continue where you were; pages and state are intact
outcome == restored_from_profile -> new process, on-disk state is back; re-open pages, re-check logins
outcome == restored_from_snapshot-> new process, cookies/localStorage replayed; re-open pages, re-run in-memory setup
outcome == fresh_process         -> nothing restored; treat as a new session
```

A reasonable policy is: on anything but `resumed_same_process`, discard the client's cached targets and page handles, list the browser's targets again, re-establish the state the next step depends on (navigate, wait for the page, verify that you are logged in) and only then continue.

## Reconnecting after a disconnect

A dropped WebSocket does not end the session. The session becomes `idle` when the last connection closes and is released only when its idle timeout (`idle_timeout_secs`) or its lease expires. To reconnect:

1. `attach` again with the same token. If the browser is still the same, you get `resumed_same_process` and your pages are where you left them.
2. Open a new WebSocket to the `cdp_url`.
3. Re-enumerate targets (`Target.getTargets`) and re-attach to the ones you need with `Target.attachToTarget`.

A client that restarts should store only `session_id`, the token and the last generation, and rebuild everything else from the browser.

## Renewal

Leases expire. Renew inside the time-to-live, with the generation you last saw:

```sh
curl -s -X POST "$BASE/v1/sessions/$SES/renew" \
  -H "Authorization: Bearer $KEY" -H "X-BrowserX-Token: $TOKEN" \
  -H 'Content-Type: application/json' -d '{"generation": 1}'
```

`409 stale_generation` means the lease moved (recovery or handoff). Read the session, look at `generation`, `recoveries` and `last_recovery`, and re-attach. A reasonable cadence is half the time-to-live.

## Handing a session to another process

Call `handoff` with the current generation, pass the returned token and `cdp_url` to the other process, and let the old one exit. The browser keeps running and the new controller attaches with `resumed_same_process`. See [handoff](../design/handoff.md).

## Crawlers and automation frameworks

Tools that accept a browser-level `ws://` URL attach through the `cdp_url` of a **dedicated** session; give them nothing else. Tools that launch their own browser need to be switched to "connect to an existing browser" mode. Two things to keep in mind:

- The tool should not close the browser when it finishes (`Browser.close` ends the process; BrowserX will see the loss and recover it, or end the session if recovery is `none`). Close pages and contexts that the tool opened, then disconnect and call `release`.
- Per-session egress is configured in the session spec (`proxy`), not in the tool: the browser can only reach the network through the worker's forwarder.

## Checklist for an integration

- [ ] The token and `cdp_url` are treated as secrets and kept out of logs.
- [ ] The client branches on `outcome` after every attach.
- [ ] Renewals pass `generation`, and `stale_generation` is handled by re-reading the lease.
- [ ] The client releases the session when it is done.
- [ ] Remote use goes through TLS termination.
