# Henbane Slice 2 — Detector Framework + Honeypot Tripwire (Design Addendum)

- **Status:** Approved for planning
- **Date:** 2026-11-14
- **Builds on:** the main design (`2026-11-13-henbane-design.md` §4/§6) and Slice 1 (`2026-11-14-slice-1-denylist-block.md`).

## Goal

Make the classifier **extensible**: replace the hardcoded `Decide` if-ladder with a
pluggable **`Detector` pipeline**. Convert Slice-1's denylist into detectors (proving the
framework), then add the first *behavioral* detector — a **honeypot tripwire** that flags a
client as `Confirmed` when it fetches a hidden trap path, so subsequent requests are
escalated. New honeypot types and signals (rate, known-ASN, …) become new detectors, each
its own vertical slice or a user-supplied plugin.

## In scope
- `ports.Detector` interface + `ports.Result`.
- `core.Engine` refactor: compose detectors (highest tier wins), map tier→action.
- `internal/detect/denylist` (IP + UA detectors — the Slice-1 logic, relocated).
- `internal/detect/honeypot` (trap-path detector) + `internal/flagstore` (bounded TTL store).
- Config: `honeypot.{enabled,path,flag_ttl,max_flagged}`.
- Arch purity test extended to the new domain packages.
- Shipped operator guidance (hidden-link + robots.txt setup).

## Out of scope (deferred)
- Auto-injecting the hidden link into HTML responses (no response-body rewriting; large/
  risky surface). Operator places the link.
- A runtime Go-plugin loader (fragile; loading third-party `.so` into a security gateway is
  anti-zero-trust). Custom compiled-in detectors are available via the library/middleware
  form factor (Slice 9).
- Labyrinth/poison (Slices 3–4): `Confirmed` maps to `Block` (403) *interim*.
- Other honeypot types (timing traps, form traps, etc.) — future per-type slices.

## The Detector port

```go
// internal/ports
type Result struct {
	Signal Signal
	Tier   Tier
}
type Detector interface {
	Name() string
	// Inspect examines a request; if it fires it returns its Result. Detectors
	// may hold state and have side effects (e.g. a honeypot flagging a client).
	Inspect(r RequestView) (Result, bool)
}
```

## Engine as composer (`internal/core`)

`NewEngine(detectors ...ports.Detector)`. `Decide` runs every detector, raises the tier to
the highest that fired, collects the fired signals, then maps tier→action:

- Pass → Allow; Suspect/Confirmed/Blocked → **Block (403) interim** (Slice 3 remaps
  Confirmed→Tarpit, Suspect→Challenge). The emitted `Event.Tier` is the *accurate* tier
  (e.g. `confirmed`), only the interim action is Block.

Running all detectors (not first-match) collects all signals and lets stateful detectors
(honeypot) always apply their side effect. `core` keeps importing only `ports` + stdlib;
`core.Policy` is removed (denylist config now lives in the denylist detector's constructor).

## Detectors (`internal/detect/*`)

- `denylist.NewIP(cidrs []netip.Prefix) ports.Detector` — fires `{denylist_ip, Blocked}` when
  `r.IP().Unmap()` ∈ cidrs.
- `denylist.NewUA(uas []string) ports.Detector` — precomputes lowercased UAs; fires
  `{denylist_ua, Blocked}` on case-insensitive substring match.
- `honeypot.New(trapPrefix string, store Store) ports.Detector`:
  - request path has prefix `trapPrefix` → `store.Flag(ip)` then fire `{honeypot, Confirmed}`.
  - else `store.Flagged(ip)` → fire `{flagged, Confirmed}`.
  - else no fire. (`ip = r.IP().Unmap()`; invalid IPs are not flagged/looked-up.)
  - `Store` is a consumer-defined interface (`Flag(netip.Addr)`, `Flagged(netip.Addr) bool`).

Detectors import only `ports` + stdlib — transport-pure, arch-test enforced. They obtain the
client IP via `RequestView.IP()` (already resolved + spoofing-hardened by `clientip`).

## Flag store (`internal/flagstore`) — zero-trust bounds

In-memory, concrete, stdlib-only (`sync`, `time`, `net/netip`); satisfies honeypot's `Store`
structurally (no import cycle):

- `New(max int, ttl time.Duration) *Store`.
- `Flag(ip)`: no-op on invalid IP; under a mutex, record `ip → expiry(now+ttl)`; **when at
  `max`, evict expired entries first, then (if still full) the soonest-to-expire** — a hard
  memory bound so an attacker tripping the trap from many IPs cannot exhaust memory.
- `Flagged(ip) bool`: under a mutex, present-and-unexpired (lazy-delete on expiry).
- Keyed on the resolved client IP → an attacker can only flag *themselves* (self-harm);
  flagging a third party requires spoofing the resolved IP, which `clientip` already prevents
  for untrusted connections.
- Interface boundary so a shared *Poison Garden* feed can later implement the same `Store`.

## Configuration

```yaml
honeypot:
  enabled: false
  path: "/.well-known/hb-trap"   # prefix; any request under it trips the flag
  flag_ttl: "1h"
  max_flagged: 100000            # hard cap (memory-DoS bound)
```

`config.Config` gains a `Honeypot` struct. Eager validation in `Parse`: if `enabled`,
`path` is required and must be absolute (`/`-prefixed); `flag_ttl` parses via
`time.ParseDuration` (default `1h`, must be > 0); `max_flagged` defaults to 100000 and must
be > 0. A `Config.HoneypotTTL()` helper parses the duration.

## Wiring (`cmd/henbane`)

Build `[]ports.Detector` from config, in order: `denylist.NewIP`, `denylist.NewUA` (when
configured), then `honeypot.New(path, flagstore.New(max, ttl))` (when enabled). Pass to
`core.NewEngine(detectors...)`. No detectors ⇒ allow-all (passthrough).

## Operator guidance (shipped)

`deploy/honeypot/README.md`: a copy-paste CSS-hidden, `rel=nofollow` link pointing at the
trap path, plus a `robots.txt` `Disallow:` stanza — so a crawler that fetches it is provably
ignoring the rules. (fail2ban already bans `honeypot`/`flagged` reasons via the existing
`reason=\S+` filter; no filter change needed.)

## Testing (TDD)
- `flagstore`: flag/flagged; expiry; invalid-IP no-op; eviction at `max`; concurrent access (`-race`).
- `detect/denylist`: IP match (incl. IPv4-mapped), UA case-insensitive, no-match.
- `detect/honeypot`: trap hit flags + fires `honeypot`; previously-flagged fires `flagged`; normal path no fire; invalid IP not flagged.
- `core`: composition (highest tier wins, signals collected, tier→action), passthrough with no detectors.
- `config`: honeypot parse/validate (path required when enabled, ttl parse, max default).
- `cmd` integration: trap hit → that client subsequently `403`; denylist still works; allowed path proxies.

## Arch / deps impact
- No new third-party module (stdlib only; allowlist unchanged).
- Arch purity test extended: `internal/detect/...` and `internal/flagstore` must not import
  `net/http*`, `internal/adapters/*`, `internal/config`, or `internal/clientip` (alongside
  the existing `core`/`ports` targets).
