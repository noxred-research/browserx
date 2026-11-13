# Using an upstream proxy

A session can route all of its browser traffic through an upstream proxy that you are entitled to use. The browser never talks to the proxy itself: it talks to a loopback forwarder owned by the worker, and the forwarder dials the upstream. This page shows how to configure that and what to expect. The mechanics are in [egress](../design/egress.md).

## Configure it per session

Put `proxy` in the session spec:

```sh
curl -s -X POST "$BASE/v1/sessions" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d '{
    "persistence": "snapshot",
    "proxy": {
      "url": "http://gateway.test:8080",
      "username": "acct-sid-{session}-g{generation}",
      "password": "synthetic-password"
    }
  }'
```

| Field | Meaning |
| --- | --- |
| `url` | `http://host:port`, `https://host:port`, `socks5://host:port` or `socks5h://host:port`. No credentials in the URL |
| `username` | Optional. May contain `{session}` and `{generation}` |
| `password` | Optional. Write-only: never returned by the API |

A proxy needs `isolation = "dedicated_browser"` (the default). A `shared_browser` session with a `proxy` is refused with `invalid_request`.

There is no global proxy setting. If every session of a deployment uses the same upstream, set it in your client's create request, or put a small wrapper around session creation; the worker deliberately keeps credentials in the session spec so that recovery can re-create the same egress.

## Choose the scheme

| Scheme | Use when | Destination policy |
| --- | --- | --- |
| `http://` | The upstream is an HTTP proxy. This is the common case | Name resolved by the upstream |
| `https://` | The connection to the upstream itself must be TLS-protected | Name resolved by the upstream |
| `socks5://` | The upstream is SOCKS5 and you want the worker's private-range policy applied to the address | Resolved locally; every address checked |
| `socks5h://` | The upstream must resolve names (for example to see geography-dependent DNS) | Name resolved by the upstream; the policy cannot check it |

## CONNECT-only gateways

Some gateways accept only `CONNECT` and refuse ordinary absolute-form requests (`GET http://...`). The forwarder converts: for a plain-HTTP request it opens a `CONNECT host:80` to the upstream and sends the origin-form request through the tunnel. Browsers can therefore load `http://` pages through such gateways.

## Sticky exits with username templates

A gateway that pins an exit by a token in the username (a pool with sticky sessions) is configured with the placeholders:

- `{session}`: an opaque per-session sticky key. Every connection of the session sends the same value, so the gateway keeps one exit for the whole session.
- `{generation}`: the lease generation. After a recovery or handoff the generation changes, so the gateway is asked for a new exit.

Pick the username grammar of *your* gateway and put the placeholders where it expects the sticky token. If you want an exit to survive recovery, leave `{generation}` out and keep only `{session}`.

```json
{ "url": "http://gateway.test:8080", "username": "acct-region-eu-sid-{session}", "password": "synthetic-password" }
```

The sticky key is derived per session; it is not the session id and is not a secret by itself, but treat usernames as sensitive because they identify your account at the gateway.

## What happens on failure

| Failure | Result |
| --- | --- |
| The upstream refuses the credentials | The page load fails inside the browser; the forwarder counts it. Creation itself does not verify credentials |
| The upstream is unreachable | Connection errors in the browser (`ERR_PROXY_CONNECTION_FAILED` or `ERR_TUNNEL_CONNECTION_FAILED`); `502 egress` for requests that surface through the API |
| A destination is blocked by policy | `403` from the forwarder with a short reason; counted in `browserx_egress_refused_total` |

The forwarder does not retry by itself and does not rotate to another upstream. Rotation is a decision your client makes by creating a session with a different route, or by handoff and recovery changing `{generation}`.

## Verify what the browser sees

Do not assume. With a session created as above, navigate to a page that you operate and that reports the client address, and compare it with the exit you expect. If it differs, check the upstream's username grammar first.

## Security notes

- The browser command line holds only `--proxy-server=http://127.0.0.1:<port>`. Credentials stay in the worker.
- The lease store holds the session spec including the proxy password, because recovery needs it. Protect `state_dir`.
- Use only upstreams whose operator permits your use. BrowserX does not vouch for an upstream's policies, logging or legality.
