# Egress

Every dedicated session gets a **forwarder**: a small HTTP proxy that listens on `127.0.0.1` on a random port and is the only network path of that session's browser. The worker, not the browser, dials the network. This gives BrowserX one place to apply destination policy, keep proxy credentials out of the browser, pin an upstream exit per session and count what happened.

```text
browser --(--proxy-server=http://127.0.0.1:PORT)--> forwarder --> direct dial, or
                                                                  upstream http(s) / socks5(h) proxy --> destination
```

The forwarder always exists for a dedicated session: with `proxy` unset it dials directly (after the destination policy); with `proxy` set it dials the upstream. Shared-browser sessions have no forwarder and use the worker's direct egress; a per-session `proxy` requires dedicated isolation.

## What the forwarder accepts

HTTP/1.1 proxy requests from the browser, on loopback only:

| Request | Handling |
| --- | --- |
| `CONNECT host:port` | A tunnel to the destination, used for HTTPS and anything else the browser tunnels |
| Absolute-form `GET http://host/path` and the other methods | Plain HTTP requests |

Request heads are bounded at 16 KiB, connecting (including upstream handshakes) is bounded at 15 seconds, idle tunnels are closed after 5 minutes, and at most 512 connections are served at once; further ones receive `503`. Plain-HTTP requests are rewritten to origin form and sent through a tunnel, one request per connection (`Connection: close`). A policy refusal answers `403` with a short reason, upstream failures `502` or `504`, malformed requests `400`. Credentials are never logged and never appear in error responses.

## Destination policy

When `egress.block_private = true` (the default) and the session dials directly, the forwarder resolves the destination name, then refuses the request if any resolved address is in a blocked class:

- loopback (`127.0.0.0/8`, `::1`);
- private and unique-local ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`);
- link-local (`169.254.0.0/16`, `fe80::/10`), which includes the cloud metadata address `169.254.169.254`;
- carrier-grade NAT (`100.64.0.0/10`);
- multicast, the unspecified address and other reserved ranges, and the IPv6 equivalents including IPv4-mapped, NAT64 and 6to4 forms.

The check applies to the address that is actually dialed, after resolution, so a hostname that resolves to a private address is refused as well as a literal one.

`egress.allow_cidrs` lists CIDR ranges or single addresses that are exempt (at most 1024 entries), for example an internal test environment the browsers are allowed to reach:

```toml
[egress]
block_private = true
allow_cidrs = ["10.20.0.0/16"]
```

Setting `block_private = false` disables the policy entirely. Do that only on workers whose network position makes it harmless.

## Upstream routes

`proxy` in the session spec routes the session through an upstream proxy:

```json
{
  "proxy": {
    "url": "http://gateway.test:8080",
    "username": "pool-sid-{session}-g{generation}",
    "password": "synthetic-password"
  }
}
```

| `url` scheme | Behavior |
| --- | --- |
| `http://`, `https://` | For `https://` the connection to the upstream is TLS-protected (built-in root certificates, independent of the system store). The forwarder opens a `CONNECT host:port` to the upstream with `Proxy-Authorization: Basic`, then tunnels. Plain-HTTP requests are sent *through the tunnel* in origin form, so gateways that only support `CONNECT` work for `http://` pages too |
| `socks5://` | SOCKS5 with RFC 1929 username/password authentication. The forwarder resolves the name locally, checks the policy against the resolved address and sends the address |
| `socks5h://` | SOCKS5 where the **upstream** resolves the name: the hostname is sent. The destination policy cannot check the address the upstream resolved to, so private-range blocking does not apply to the resolved address. Use it only when you trust the upstream's resolver and network position |

Validation happens at admission: the scheme must be one of those, and the URL must not contain credentials (`user:pw@`). Put them in `username` and `password`.

Where the policy can be enforced depends on who resolves the name:

| Route | Who resolves | Policy |
| --- | --- | --- |
| Direct | The forwarder | Every resolved address is checked; only checked addresses are dialed |
| `socks5://` upstream | The forwarder | Every resolved address is checked before the address is sent to the upstream |
| `http://`, `https://` upstream | The upstream | Only IP literals and `localhost` names are checked by the forwarder. Enforcing the policy on remote resolution is the upstream operator's responsibility |
| `socks5h://` upstream | The upstream | Same as above |

If you need strict private-range blocking for every destination, use direct egress or `socks5://`, or enforce it at the upstream.

## Sticky exits: `{session}` and `{generation}`

Pools of rotating exits usually pin an exit by a token in the username. Two placeholders in `proxy.username` are substituted per connection:

- `{session}` becomes an opaque per-session sticky key (not the session id), identical for every connection of the session, so every request takes the same exit;
- `{generation}` becomes the lease generation, so a recovery or handoff, which increments it, naturally asks for a new exit.

`pool-sid-{session}-g{generation}` on generation 3 becomes `pool-sid-<key>-g3`. A template without placeholders is sent as written. Passwords are not templated.

## Credentials

The browser is started with `--proxy-server=http://127.0.0.1:PORT` only. Upstream usernames and passwords exist in the forwarder's memory and in the session spec in the lease store; they are never put on a command line, in an environment variable of the browser, in a log line or in an API response (`password` is write-only).

## Lifecycle

The forwarder starts before the browser and stops after it. On recovery a new forwarder is started with the new generation, so the rendered username changes with it. When the session is released the forwarder shuts down and its counters (connections, bytes up, bytes down, refusals) are folded into metrics (`browserx_egress_refused_total`).

## Limits

- **Local trust.** The forwarder binds `127.0.0.1` only, but any local process can connect to it and borrow the session's upstream route, because a browser cannot authenticate to a proxy through a command-line flag. Run the worker on a host where local processes are trusted, or in its own network namespace.

- The forwarder carries the traffic of one browser; it is not a general-purpose proxy and it listens only on loopback.
- It does not inspect, modify or capture TLS traffic: HTTPS stays a tunnel.
- UDP (for example QUIC or WebRTC media) does not pass through an HTTP proxy. Chromium falls back to TCP for QUIC; WebRTC can reveal local addresses unless a launch profile restricts it. If that matters to you, restrict it with launch flags and network policy.
- Whether an upstream pins, rotates or filters exits is the upstream's behavior. BrowserX only passes the username.
