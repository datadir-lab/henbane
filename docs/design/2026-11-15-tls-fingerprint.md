# TLS client fingerprinting

## Goal

Detect automated clients by their TLS handshake, which they cannot trivially
fake and which survives a lie in the User-Agent. Go's `net/http`, Python, curl,
and headless tools present TLS characteristics that differ from real browsers.

## What's possible with the standard library

Go's `crypto/tls` hides the raw ClientHello, so a **full JA3 is not possible** —
the exact extension list and ordering are unavailable. But `tls.ClientHelloInfo`
exposes cipher suites, supported groups/curves, EC point formats, ALPN,
signature schemes, and versions. A hash of those is a **coarse** fingerprint:
less precise than JA3, but enough to separate TLS stacks (a Go client's
fingerprint differs from Chrome's). **GREASE** values (RFC 8701) are filtered so
a given client's fingerprint is stable run to run.

This is a direct-exposure feature: it only works when **Henbane terminates TLS
itself**. Behind a TLS-terminating proxy or CDN the fingerprint is empty.

## Capture plumbing

The fingerprint is computed during the handshake and must reach the HTTP request
on the same connection. `internal/tlsfp`:

1. `WrapListener` wraps accepted connections in a type carrying a holder.
2. `DecorateConfig` installs `GetConfigForClient`, which computes the fingerprint
   and stores it on the connection's holder during the handshake.
3. `ConnContext` (the `http.Server` hook) stashes the holder in the request base
   context; `FromContext` reads it while serving.

The handshake and the request run on the same connection goroutine (handshake on
first read, then `ServeHTTP`), so the holder needs no synchronization.

## Wiring

- `ports.Event` gains a `TLSFingerprint` field; `ports.TLSFingerprinter` is an
  **optional** `RequestView` capability (type-asserted), so adding it churned no
  existing detector or stub.
- `proxy.requestView` implements it via `tlsfp.FromContext`; `core.Decide`
  populates `Event.TLSFingerprint` when the view supports it; the slog sink logs
  it as `tls_fp` (only when non-empty).
- `cmd` terminates TLS with the fingerprint-capturing listener when `tls.cert`/
  `tls.key` are set (`MinVersion` TLS 1.2); otherwise plain HTTP, unchanged.

## The signal

`deny.tls_fingerprints` blocks (`403`) clients whose fingerprint matches — the
same operator-curated denylist model as `deny.cidrs`/`deny.user_agents`. Because
a coarse fingerprint is shared by every client of the same TLS library, the
operator lists only fingerprints they've confirmed (seen in the `tls_fp` log).
A future signal could auto-flag UA↔TLS inconsistency, or federation could share
fingerprint lists — both build on this capture + log.

## Verification

`internal/tlsfp` drives a real TLS handshake and asserts the handler sees a
16-hex fingerprint; the detector and the `Event` population are unit-tested; and
the full binary was smoke-tested over TLS — two curl requests both logged
`tls_fp=de7fd8549b99c53c` (stable), confirming capture → event → log end to end.
