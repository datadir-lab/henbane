# ForwardAuth / auth_request sidecar

**Status:** shipped · **Date:** 2026-11-15

## Problem

Henbane ships three form factors (reverse proxy, embeddable middleware, Caddy
module), but the two most common front proxies — **nginx** and **Traefik** —
can't load a Go plugin. Operators running them had no way to put Henbane's
classifier in front of their site without replacing their proxy. Both, however,
support an **external authorization** pattern (nginx `auth_request`, Traefik
`forwardAuth`): the proxy asks an HTTP endpoint whether to allow each request.

## Approach

Add an auth-server form factor that reuses the existing decision gate. The key
realisation is that the embeddable-middleware machinery already does almost all
of it: `proxy.Handler` built with `NewGate` runs the full pipeline (verifiers,
detectors, PoW layering, bomb, maze, block) and delegates only the *allowed*
action to a supplied handler via `Wrap`. The sidecar is simply:

```
authz.New( gate.Wrap(204-handler), verifyPath )
```

`internal/adapters/authz` adds two things around that gate:

1. **Request reconstruction.** The auth subrequest's own path/method are the
   endpoint's, not the client's, so `reconstruct` rewrites the request in place
   from the forwarded headers (`X-Forwarded-Uri`/`X-Original-URI`,
   `X-Forwarded-Method`, `X-Forwarded-Host`). The client IP already flows through
   `clientip.Resolver` via `X-Forwarded-For`.

2. **Status adaptation (`authWriter`).** ForwardAuth treats any `2xx` as "allow".
   The gate writes `204` for allow but `200` for a challenge page or maze — which
   would be misread as allow. `authWriter` passes `204` and genuine non-`2xx`
   through unchanged, but rewrites any *other* `2xx` to the deny status (`403`)
   while preserving the body, so Traefik forwards the challenge/maze to the client
   and nginx sees a deny status.

The PoW verify path is routed through the gate **without** `authWriter`, so its
`200`-plus-cookie response isn't rewritten into a deny.

## Why reuse the gate instead of a new decision path

The gate already encodes subtle logic: solved-token clears a challenge,
"challenge everyone" turns an allowed-but-unauthed request into a challenge,
block/tarpit are never reinterpreted, the bomb replaces a tier's response. A
second decision path would drift from it. Wrapping it keeps one source of truth;
the sidecar only translates transport semantics.

## Zero-trust / threat model

- **Trust boundary is the front proxy.** The forwarded headers are authoritative
  only because the operator binds the sidecar to the internal network and sets
  `trusted_proxies`. The docs make both requirements explicit.
- **Strict header parsing.** The URI is parsed with `url.ParseRequestURI` (bad
  input leaves the subrequest untouched); the method is accepted only as a short
  all-letter token, so a forwarded header can't inject bytes into the decision or
  the logs.
- **Fail toward the proxy's own handling**, not toward allow: a reconstruction
  that can't parse a header leaves the field as-is rather than guessing.

## Config and caveat

`sidecar.enabled` (or `--sidecar`) selects the form factor; `upstream` is then
forbidden (they're mutually exclusive — caught at parse time). The maze/poison
postures are delivered as the deny body rather than a `200` page, because `2xx`
means allow to the front proxy; operators who want a `200` maze or precise
byte-metering run the reverse-proxy or Caddy form factor. The sidecar is first
and foremost an authorization gate for infrastructure already in place. Full
nginx and Traefik recipes live in `docs/deploy/sidecar.md`.
