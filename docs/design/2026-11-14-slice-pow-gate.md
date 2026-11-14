# Henbane Slice — Proof-of-Work Gate (Design Addendum)

- **Status:** Draft for review
- **Date:** 2026-11-14
- **Builds on:** main design §6 (tiers/actions), Slice 3/4 (generators), the branded
  `assets/logo/challenge.html` interstitial.

## Goal

Implement the `Challenge` action: a Hashcash-style **proof-of-work gate** that makes a
suspicious client's browser solve a small puzzle before it's let through — cheap for a
human (~2 s), expensive for a crawler reading millions of pages. Stateless (HMAC tokens,
no storage), zero-dependency (stdlib `crypto/*`), and wired into the existing branded
challenge page.

Honest framing (per research / STRATEGY.md): PoW is **leaky individually** (one solve =
a session per IP; native solvers beat browser JS) — its value is the *toll* and, at
scale, **federation**. We ship it as a real, graduated, low-false-positive-cost gate, not
a silver bullet.

## Mechanism (stateless Hashcash)

1. **Issue.** For a request that must be challenged and has no valid access token, the
   gate builds a **challenge token**, HMAC-signed so it is unforgeable and self-describing:
   `challenge = b64(nonceRand16 ‖ expiryUnix ‖ ipHash) ‖ "." ‖ b64(HMAC_secret(that))`.
   It carries its own short expiry (default 5 min) and a hash of the client IP. No
   server-side state.
2. **Solve (client).** The challenge page's JS finds a `solution` integer where
   `SHA-256(challenge ‖ solution)` has **≥ difficulty leading zero bits**, using
   `crypto.subtle.digest('SHA-256', …)` in a loop, updating the progress bar. (The brand
   page's fake animation script is replaced by this real solver.)
3. **Verify (server).** Client POSTs `{challenge, solution}` to
   `POST /.well-known/henbane/verify`. The gate: re-checks the challenge HMAC (constant
   time), rejects if expired or IP-mismatched, recomputes `SHA-256(challenge‖solution)`
   and checks the leading-zero-bit count. On success it issues an **access token**
   `access = b64(expiryUnix ‖ ipHash) ‖ "." ‖ b64(HMAC_secret("access" ‖ that))`, sets it
   as the cookie `hb_pow` (HttpOnly, Secure, SameSite=Lax, short TTL), and returns the
   original URL for the JS to redirect to.
4. **Pass.** Subsequent requests carry `hb_pow`; the gate verifies the HMAC + expiry + IP
   and returns `Allow` (no challenge). Fully stateless.

**Secret:** `pow.secret` (config). If empty, generated from `crypto/rand` at startup
(tokens then reset on restart and differ per instance — fine single-node; set an explicit
secret for multi-instance/persistent).

**Difficulty:** `pow.difficulty_bits` leading zero bits (default 20 ≈ ~1 M hashes ≈ a
couple seconds in-browser). Bounded `[8, 32]`.

## Privacy reconciliation (the branded page says "no cookies")

The access token **is** a cookie — but an **opaque HMAC** of `(expiry, ipHash)`: no
identifier, no account, no cross-site value, no tracking, dropped at TTL. We keep the
privacy promise but make it accurate. Update `challenge.html` footer:

- from: `no cookies · no account · nothing tracked`
- to: `one anonymous session cookie · no account · nothing tracked`

and the lead copy's "with no login and nothing tracked" stays true.

## Trigger — who gets challenged

New config `pow.mode`:
- `off` (default) — gate disabled.
- `suspect` — challenge `TierSuspect` requests (populated later by the signals-detector
  slice).
- `all` — challenge **every** request that isn't `Allow`-via-token, `Confirmed`
  (honeypot → tarpit), or `Blocked` (denylist → 403). This is the design's documented
  "challenge everyone" posture and makes the gate useful **now**, before the signals slice.

`actionForTier` / the engine gains: a request lacking a valid `hb_pow` token, under an
active `pow.mode`, routes to `ActionChallenge`.

## Serving the challenge page

- Embed `challenge.html` (+ its CSS already inline) as a Go `html/template` via `go:embed`;
  inject `{{.Challenge}}`, `{{.DifficultyBits}}`, `{{.VerifyPath}}`, `{{.Target}}` and the
  real solver `<script>`.
- The page's asset refs (`favicon*`, `fonts.css`, `henbane-flower-dark.png`) are served by
  the gate under a reserved prefix `GET /.well-known/henbane/assets/*` from `go:embed`
  (bounded, immutable, cached). Keeps the page self-contained without polluting the
  operator's namespace. Themeable: `pow.template_path` overrides the embedded page.

## Zero-trust / security invariants

- **HMAC with `hmac.Equal` (constant-time)** for every token check; SHA-256 via stdlib.
- **Short challenge expiry** (default 5 min) bounds solve-farming/replay; access TTL
  configurable (default 1 h, like Anubis).
- **IP-bound** challenge + access tokens (hash of the resolved client IP via the existing
  `clientip` resolver) — a solved token can't be shared to another IP. (Caveat, documented:
  NAT / changing mobile IP → re-challenge.)
- **Bounded verify endpoint:** cap request body, reject malformed/oversized fast; the
  verify + token checks are O(1) and cheap — the server never does PoW work.
- **Difficulty + body-size + nonce-length bounds**; fail closed on any parse error.
- Secret never logged; tokens are opaque.
- The gate only ever *adds* a `Challenge`/token-check step; a client with a valid token is
  indistinguishable from normal `Allow` downstream.

## Architecture

- New pure package `internal/pow` (stdlib + maybe `internal/ports` only; arch-pure):
  `New(secret, difficultyBits, challengeTTL, accessTTL)`; `Issue(ip) challenge`;
  `VerifySolution(challenge, solution, ip) (accessToken, ok)`; `ValidAccess(token, ip) bool`.
  Transport-free, deterministic-testable.
- New adapter `internal/adapters/challenge` (or extend proxy): serves the challenge page,
  the verify endpoint, the embedded assets; owns the `go:embed` template.
- `proxy` `ActionChallenge` case → if request has the reserved verify/asset path, handle it;
  else render the challenge page. `ActionAllow`-with-token short-circuit added to request
  handling (check `hb_pow` before engine decision, or as a detector).
- Config `pow.{mode,difficulty_bits,challenge_ttl,access_ttl,secret,template_path}`.
- `cmd/henbane` wires it; arch purity extended to `internal/pow`.

## Testing (TDD)

- `pow`: issue→solve→verify round-trip; forged/expired/ip-mismatched challenge rejected;
  solution below difficulty rejected; access token valid/expired/ip-mismatch; constant-time
  path; difficulty/bounds clamps; deterministic with a fixed secret.
- `challenge` adapter: challenge page renders with injected params + solver; verify endpoint
  accepts a correct solution (sets cookie, returns target) and rejects bad ones; assets
  served; oversized body rejected.
- `proxy`/engine: `pow.mode=all` → unauthenticated request gets the challenge page (not the
  upstream); a request with a valid `hb_pow` cookie proxies through; `Confirmed` still
  tarpits and `Blocked` still 403s (PoW doesn't override them); `mode=off` → no challenge.
- `cmd` integration: end-to-end challenge → (simulated) verify → cookie → upstream.

## Out of scope (deferred)
- WASM solver (JS-only v1).
- The signals detectors that populate `TierSuspect` (own slice; `mode=all` covers the gap).
- Difficulty auto-tuning / adaptive difficulty.
- Multi-instance shared secret distribution (operator sets `pow.secret`).

## Arch / deps impact
- No new third-party module (stdlib `crypto/sha256`, `crypto/hmac`, `crypto/rand`,
  `encoding/base64`, `net/http`, `html/template`, `embed`). Allowlist unchanged.
- Arch purity: `internal/pow` must stay transport-pure (may import `ports`); the
  `challenge` adapter is an adapter (may use net/http).
