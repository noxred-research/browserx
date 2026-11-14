# Handoff

Handoff moves control of a live session from one client to another without touching the browser. The pages stay open, the heap stays intact and the session keeps its identity; what changes is who holds the credential.

## When to use it

- A long-running browser is started by one component (a scheduler, an interactive tool) and finished by another (a worker, a person with a debugger).
- A controller is about to shut down and wants to pass the session on without a recovery.
- You suspect that a token leaked and want to cut off whoever holds it.

## The call

```http
POST /v1/sessions/ses_.../handoff
Authorization: Bearer <api key>
X-BrowserX-Token: <current lease token>
Content-Type: application/json

{ "generation": 3 }
```

Response:

```json
{
  "session": { "session_id": "ses_...", "generation": 4, "status": "active" },
  "token": "bxt_...",
  "cdp_url": "ws://127.0.0.1:7690/cdp/ses_.../bxt_..."
}
```

From the command line: `browserx session handoff <session-id> --token <current token>`.

## What happens

1. The worker verifies the token digest (constant time) and that `generation` equals the stored generation. A stale generation is refused with `stale_generation` (`409`).
2. The lease is replaced by compare-and-swap with `generation + 1` and the digest of a freshly generated token. If a concurrent renewal, recovery or handoff won the race, one of the two fails cleanly instead of both succeeding.
3. The relay is told that the old token is dead and closes every connection that was bound to it.
4. The new token and the new `cdp_url` are returned once. Pass them to the new controller over a channel you trust.

The old token stops working at step 2: attach, renew, snapshot, release and the relay all refuse it.

## Guarantees

- **Single controller.** After a handoff only the new token operates the session. Fencing is by generation, so an old controller that still holds a stale generation cannot renew, hand off or release the session.
- **The browser is untouched.** Handoff does not restart, pause or re-create anything. The new controller attaches and gets `resumed_same_process` as long as no recovery happened in between.
- **No lease extension.** Handoff does not change `expires_at` or the absolute lifetime cap.
- **No silent loss of state.** If a recovery replaced the browser before or after the handoff, the next attach reports it as usual.

## What it does not do

- It does not transfer *knowledge*. The new controller does not know which pages are open or what the old controller was doing. It learns from the browser: list the targets and attach to them through CDP.
- It does not authenticate the new controller. The API key still decides who may call the API; the token decides who may control *this* session. Anyone you give the token to (and who has an API key of the same owner) controls it.
- It is not a revocation list for the old *API key*. Rotating API keys is a configuration change, see [operations](../guides/operations.md#key-rotation).
- Shared-isolation sessions hand off the same way; the scoped relay of the old token is closed and the new one is scoped to the same context.

## Handoff and recovery together

Both increment the generation. A client holding generation 3 whose browser was replaced (generation 4) gets `stale_generation` when it calls `renew` or `handoff` with 3, reads the lease, sees `recoveries` and `last_recovery` change and decides what to do. This is the intended signal that the world changed under the client; it is not an error to retry blindly.

## A safe handoff procedure

1. The old controller finishes or pauses its in-flight work.
2. It calls `handoff` with the current generation and receives the new token.
3. It passes the `cdp_url` to the new controller and disconnects (its relay connection is closed anyway).
4. The new controller connects and calls `attach` to confirm the outcome (`resumed_same_process`) before it starts.
