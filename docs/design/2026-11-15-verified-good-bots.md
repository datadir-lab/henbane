# Verified good bots (reverse DNS) + the Verifier seam

## Goal

Recognise the search crawlers an operator *wants* (Googlebot, Bingbot) so they
are not tarpitted or poisoned, and catch clients that spoof a crawler's
User-Agent. This is the classic, standard-free half of "verified good bots"
(the cryptographic half is Web Bot Auth); the two share the new Verifier seam.

## The Verifier seam

The engine only ever *raised* a request's tier (highest-firing detector wins),
so it could not express "this is a trusted good bot — allow it, overriding the
detectors". Added `ports.Verifier`:

```go
type Verifier interface {
    Name() string
    Verify(RequestView) (sig Signal, tier Tier, ok bool)
}
```

Verifiers run **before** detectors; the first to fire (`ok`) forces the verdict —
`TierPass` allows (and sets `Verdict.Allowlisted`, which the proxy honours to skip
"challenge everyone"), `TierBlocked` blocks. `ok=false` is "no opinion" and lets
the detectors decide. A verified good bot thus bypasses the whole suspicion
pipeline, including `pow.mode: all`.

## FCrDNS verification

`internal/detect/goodbot`: a request whose User-Agent matches a known crawler
(Googlebot/Bingbot/Applebot by default) is verified by **forward-confirmed
reverse DNS** — the client IP must reverse-resolve (PTR) to a hostname under the
crawler's domain (e.g. `.googlebot.com`), and that hostname must forward-resolve
back to the same IP. The forward-confirm is what makes it spoof-proof: anyone can
set a PTR, but no one can make Google's forward DNS point at their IP. The domain
suffix match requires the leading dot, so `evil-googlebot.com` does not match
`.googlebot.com`.

- **Verified** → `TierPass` (allow). **Claims a crawler but not verified** →
  spoofer, acted on at `spoof_tier` when enabled (default off — only verified
  bots are acted on, which is the safe default).

## Non-blocking lookups (zero-trust)

Reverse DNS is network I/O, so it must never run on the request path. Lookups run
in a **bounded background** pool: a cache miss triggers a resolution (deduped per
IP, capped by a semaphore) and the current request gets "no opinion"; subsequent
requests use the cached, TTL'd result. A flood of crawler-UA requests from many
IPs therefore cannot stall request goroutines or stampede the resolver — excess
misses simply stay unresolved. Transient resolver errors are not cached (they
retry); a definitive "no PTR" (NXDOMAIN) is cached as a non-confirmation.

## Scope / future

- Reverse-DNS-verifiable crawlers only. GPTBot/ClaudeBot publish IP ranges but no
  reverse DNS; range-based verification is a separate follow-up.
- A verified good bot bypasses detectors including the denylists (the operator who
  enables good-bot verification intends to trust them); documented.
