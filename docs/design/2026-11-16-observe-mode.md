# Observe mode (dry run)

**Status:** shipped · **Date:** 2026-11-16 · **Issue:** #53

## Problem

The classifier benchmark (`research/classifier-benchmark.md`) documented a real
false-positive surface — browsers predating Fetch Metadata are flagged — and the
base-rate analysis shows precision collapses if thresholds are set carelessly.
Operators can't safely turn up aggressive detection without first seeing what it
would do to *their own* traffic. This is the first-deploy adoption blocker: a
capable classifier sits installed-and-disabled because people fear false
positives (the documented Anubis/Cloudflare collateral).

## Approach

A dry-run mode: the engine runs the full pipeline and the verdict it *would* take
is recorded, but no request is acted on — everything is served normally. The
operator tunes from real traffic, then enforces.

The key insight is that all three serving form factors (standalone reverse proxy,
embeddable middleware, nginx/Traefik sidecar) share **one** decision gate,
`proxy.Handler`. Implementing observe there covers all of them at once.

- **`ports.Event.Observed bool`** — set when observe mode suppressed enforcement.
  In observe mode `Event.Action` is the action that *would* have been taken (the
  full post-PoW-layering verdict), so the decision log and the Prometheus
  `{action,tier}` counters show the would-be distribution; `Observed` disambiguates
  it from an enforced action.
- **`proxy.Handler.WithObserve(bool)`** — a chainable toggle (matching the engine's
  `WithVerifiers`/`WithScoring` style), so no constructor signatures or call sites
  churn. In `serve`, after computing the final action and emitting the enriched
  events, observe mode serves `origin` (upstream / next handler / 204) and returns
  before the action dispatch.
- **Config `observe: true`** (top level), wired onto the gate in all three form
  factors (`cmd` proxy + sidecar, and the middleware `henbane.go`).
- **The slog sink** adds `observe=true` to the decision line.

## What is and isn't suppressed

Only the *action* is suppressed. The full pipeline still runs, including stateful
detectors — a honeypot hit still marks the client (that is part of "what would
happen"), and velocity still accumulates. So the would-be verdicts reflect the
real enforcing behaviour, not a weakened one. In the sidecar, observe means the
auth endpoint always answers `204` (allow) while logging the would-be action.

## Tests

- `proxy`: a would-be *Block* is served by upstream (200/body) while the emitted
  Event carries `Action=Block, Observed=true`.
- `cmd` end-to-end: with `observe: true` and a denylisted User-Agent, the request
  reaches the upstream (not a 403), yet `/metrics` still records `action="block"`
  — proving the would-be verdict is measured while nothing is enforced.

## Config

```yaml
observe: true
```
Recommended as the first-deploy step; remove it to enforce.
