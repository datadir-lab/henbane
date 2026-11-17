# Fail-safe audit: the invariants a change must preserve

**Status:** audit complete. One finding (fixed in the strict-config change); the rest of
the security-critical paths were already fail-closed. This records what was checked so
the posture is a maintained contract, not an assumption.

## Why

A sloppy config edit during live testing renamed `honeypot.enabled` to an unknown key,
and the gateway ran with the honeypot silently disabled: a fail-OPEN, where a typo turns
a protection off with no error. That is the worst failure mode for a security tool, so
every other "accept or deny" path was reviewed for the same shape.

## The finding

- **Lenient config parsing dropped unknown keys.** A typo in a security-relevant setting
  silently disabled it. Fixed: the config now decodes with `KnownFields(true)`, so an
  unrecognised key is a hard startup error naming the field. Pinned by
  `config.TestLoadFileRejectsUnknownKey`.

## The invariants (each verified, each pinned by a test)

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

## Conclusion

The posture is systematically fail-closed: trust is granted only on cryptographic or
forward-confirmed proof, and every error, absence, or malformation denies or abstains.
The config footgun was an isolated lapse because it lived in parsing, outside the
decision paths that had this discipline applied. These invariants are the contract: a
change that makes any of them grant trust on error is a regression, and the named tests
are there to catch it.
