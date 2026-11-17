# Fail-safe audit: the invariants a change must preserve

**Status:** audit complete across three lenses, fail-open, resource-exhaustion, and
header-trust. Two findings, both fixed; every deliberately-designed security path was
already sound. This records what was checked so the posture is a maintained contract,
not an assumption.

## Why

A sloppy config edit during live testing renamed `honeypot.enabled` to an unknown key,
and the gateway ran with the honeypot silently disabled: a fail-OPEN, where a typo turns
a protection off with no error. That is the worst failure mode for a security tool, so
every "accept or deny" path was reviewed for the same shape, then the sweep was widened
to resource exhaustion (can an attacker make Henbane itself expensive?) and header trust
(does Henbane trust a client header it should not?).

## The findings

Both findings lived in the *seams*, config parsing and output generation, not in the
designed decision paths, which were all already correct.

- **Lenient config parsing dropped unknown keys** (fail-open). A typo in a
  security-relevant setting silently disabled it. Fixed: the config now decodes with
  `KnownFields(true)`, so an unrecognised key is a hard startup error naming the field.
  Pinned by `config.TestLoadFileRejectsUnknownKey`.
- **The maze echoed the full request path into every link** (resource exhaustion). The
  honeypot path is public in robots.txt and tarpits on the first hit, so an
  unauthenticated large-URL request could draw a response 15-100x its size: egress
  amplification against the operator. Fixed: the echoed path prefix is capped at 256
  bytes. Pinned by `labyrinth.TestLongPathDoesNotAmplifyOutput`.

## Fail-closed invariants: trust is granted only on proof

Every path that can grant trust was checked to grant it only on positive proof, and to
deny or abstain on error, absence, or malformation.

1. **Good-bot allowlisting requires forward-confirmed reverse DNS.** Only a PTR that
   forward-resolves back to the client IP and matches the crawler's official domain
   allowlists. A mismatch is a spoofer; a lookalike domain does not match.
   Tests: `goodbot.TestVerifiedGooglebotAllowed`, `TestForwardConfirmMismatchIsSpoofed`,
   `TestMatchesDomainRejectsLookalike`.

2. **A transient DNS error never allowlists and is never cached.** The verifier
   distinguishes a definitive NXDOMAIN (a cacheable non-confirmation) from a transient
   resolver failure (not cached, so it retries). A DNS outage cannot freeze a client's
   verification state, and never grants trust.
   Tests: `goodbot.TestFcrdnsTransientVsStable`,
   `TestTransientErrorNotCachedAndNeverAllowlists`.

3. **AI-crawler verification requires the IP inside a published range.** An invalid IP
   gets no opinion (never an allowlist); a crawler UA from outside the ranges is a
   spoofer. Bundled ranges that fail to parse are skipped, never trusted.
   Tests: the `crawlerips` suite.

4. **Web Bot Auth requires a valid Ed25519 signature bound to this host.** Any
   malformation returns not-verified; the signature must cover `@authority` (no
   cross-host replay) and sit inside its validity window.
   Tests: the `webbotauth` suite, including the RFC 9421 reference vector.

5. **Proof-of-work tokens are verified constant-time and length-guarded.** The HMAC is
   checked with `hmac.Equal` before the payload is used, lengths are validated before
   slicing, the difficulty is actually re-checked, and challenge and access tokens are
   domain-separated. A forged or tampered token is rejected.
   Tests: `pow.TestForgedChallengeRejected`, `TestWrongSolutionRejected`.

6. **Client IP ignores forwarding headers unless the connection is a trusted proxy.**
   The default (no `trusted_proxies`) is edge mode: `X-Forwarded-For` is ignored, so the
   denylist and honeypot flags cannot be spoofed and no client can frame another. The
   header walk is the rightmost-non-trusted algorithm and is length-bounded.
   Tests: the `clientip` suite (edge-mode and untrusted-connection cases).

7. **A panic cannot become an allow.** There is no `recover()` in the core: a panic in a
   detector surfaces as net/http's 500, never a pass. Unhandled verdict actions fail
   closed to a 500 in the proxy, not through to the upstream.

8. **Scoring only ever raises the tier.** The soft-signal layer cannot lower a definitive
   detector verdict, so accumulating evidence can never downgrade a block to an allow.

## Resource invariants: attacker input cannot make Henbane expensive

Every attacker-reachable path does work bounded independently of the input size, so a
hostile client cannot turn the gateway's own CPU, memory, or egress against the operator.

9. **Request bodies are read under a byte cap.** The PoW verify endpoint, the federation
   feed fetch, and the Web Bot Auth directory fetch all read through `io.LimitReader`.
   No unbounded `io.ReadAll` on a request path.

10. **Generation cost is amortized, not per-request.** The Markov poison model is built
    once at startup; each maze page walks the pre-built chain for a clamped number of
    links (<=100) and paragraphs (<=20). The decompression bomb streams with O(block)
    memory and a decompressed-size cap, so a tiny compressed response costs the attacker,
    not the operator.

11. **The maze response is bounded independently of the URL.** The attacker-controlled
    path echoed into links is capped (see the finding above), so response size depends on
    the link count and the cap, never the request URL length.
    Test: `labyrinth.TestLongPathDoesNotAmplifyOutput`.

12. **Attacker-sized inputs are capped before processing.** The User-Agent
    (`maxUABytes`), the X-Forwarded-For hop count (`maxXFFEntries`), the PTR forward-lookup
    fan-out (`maxPTRNames`), the TLS/h2 sniff deadline, and the 1 MiB request-header cap
    each bound a value a hostile client controls.

## Header-trust invariants: a client header is a signal, never a grant

13. **Client headers raise suspicion; they never grant trust.** The consistency and
    browser-hint signals read `User-Agent`, `Sec-Fetch-*`, `Accept`, etc. only to *add*
    score when they are missing or wrong. The only trust-granting header inputs are the
    gated `X-Forwarded-For` (invariant 6), the HMAC+IP-bound PoW cookie, and the
    Ed25519-verified Web Bot Auth signature (invariant 4). Henbane injects no verdict
    header the upstream could be fooled by.

14. **The PoW cookie is scoped and unforgeable.** `HttpOnly`, `Secure` when Henbane
    terminates TLS, `SameSite=Lax`, carrying an opaque token that is HMAC-verified,
    IP-bound, and time-limited. A stolen cookie is useless from another IP or after
    expiry.

15. **The sidecar trusts only overwrite-required forwarded headers.** It reads the
    request from the canonical `X-Forwarded-*` names (not `X-Original-*` aliases), rejects
    a duplicated `X-Forwarded-Uri` (a sign a client value survived), matches the verify
    path on the endpoint's own path *before* reconstruction, sanitizes the method, and
    fails closed on a bad forwarded request. The auth endpoint must be bound to the
    internal network. (Hardened across the round-1/round-2 audits.)

## Conclusion

Across all three lenses the posture is sound: trust is granted only on cryptographic or
forward-confirmed proof, attacker input does work bounded independently of its size, and
a client header is a signal rather than a grant. The two findings were isolated lapses in
the seams, config parsing and output generation, not in the decision paths, which already
had this discipline applied uniformly. These fifteen invariants are the contract: a change
that makes any of them grant trust on error, do unbounded work on attacker input, or trust
a client header is a regression, and the named tests are there to catch it.
