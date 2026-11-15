# Request-velocity signal

## Goal

Add a detector that fires when a single client IP exceeds a configured request
rate, so aggressive automated clients are classified without relying on their
User-Agent or any header they control.

## Mechanism

A fixed-window per-IP counter. Each request increments the resolved client IP's
count in the current window; when the count exceeds the limit within the window,
the detector fires. The window then rolls over on the next request after it
elapses.

- **Resolved IP only.** The detector keys on `RequestView.IP()`, which is the
  trusted-proxy–resolved client address (`.Unmap()`ed so an IPv4-in-IPv6 form
  cannot split a client's rate). A spoofed `X-Forwarded-For` cannot shift or
  dodge the count unless the operator has mis-trusted the proxy — the same
  boundary every other IP-keyed detector depends on.
- **Hard-bounded store.** The counter map is capped at `max_tracked` entries.
  At capacity, inserting a new IP first evicts expired windows, then one
  arbitrary entry — a memory bound against counter-flooding from many source
  IPs (mirrors `flagstore`). Invalid IPs are never tracked.
- **No unbounded growth per IP.** The per-IP count saturates at `limit+1`, so a
  sustained flood inside one window cannot overflow the counter.

## Response tier (configurable)

Velocity is a weaker signal than a honeypot hit: shared NAT/CGNAT, CDNs, and
asset-heavy page loads can all push a legitimate IP over a threshold. So the
response is the operator's choice of graduated-response rung:

- `tier: suspect` (default) → **Challenge** (PoW toll). The gentlest response:
  a real browser solves one proof-of-work and continues; a flood crawler pays
  CPU per request. Recoverable for the common (JS browser) false positive.
- `tier: confirmed` → **Tarpit** (labyrinth/poison). Standalone — needs no PoW.
  Trips a fast crawler straight into the maze. A legitimate shared-IP false
  positive is *not* recoverable (they get garbage), so this is opt-in, not the
  default.

Because a `suspect` verdict with no PoW gate configured would fail closed to a
500, config validation rejects `velocity.tier: suspect` unless `pow.mode` is
`suspect` or `all`. The error tells the operator to enable PoW or pick
`confirmed`.

## Configuration

```yaml
velocity:
  enabled: false        # off by default
  requests: 600         # max requests per window per IP before firing; 0 => 600
  window: "1m"          # the fixed counting window; default 1m
  tier: "suspect"       # suspect (PoW toll) | confirmed (tarpit); "" => suspect
  max_tracked: 100000   # hard cap on tracked IPs (memory bound); 0 => 100000
```

**Tuning caveat (documented for operators):** the proxy fronts the whole site,
so the counter sees *every* request including CSS/JS/image/XHR subresources, not
just page navigations. A single asset-heavy page view can be dozens of requests.
Set `requests` well above a heavy human session, or keep static assets off the
proxied path. The default (600/min ≈ 10 req/s sustained) clears typical human
browsing while still catching sustained crawlers; tune per deployment.

## Scope / non-goals

- No sliding-log or token-bucket accounting — a fixed window is cheap, bounded,
  and sufficient to populate a tier. (Documented approximation, like the
  perplexity trigram in the study.)
- No per-path exclusions or method weighting (YAGNI); operators who need that
  keep assets off the proxied path.
- Disabled by default, like the PoW gate and the decompression bomb.
