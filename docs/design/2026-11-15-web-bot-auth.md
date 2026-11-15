# Web Bot Auth: verifying signed AI agents

## Goal

Act on a *proven* agent identity instead of a spoofable User-Agent. Web Bot Auth
(draft-meunier-web-bot-auth, built on RFC 9421 HTTP Message Signatures) lets an
agent sign each request with an Ed25519 key and publish the public key in a
directory. OpenAI's ChatGPT agent, DuckDuckGo, Cloudflare, and others already
sign their traffic. Henbane verifies the signature and applies a configured tier
to verified agents.

## Mechanism

A signed request carries three headers: `Signature-Input` (covered components +
`created`/`expires`/`keyid`/`alg`/`tag`), `Signature` (the Ed25519 signature),
and `Signature-Agent` (the directory URL). The verifier:

1. parses `Signature-Input`, requires `tag="web-bot-auth"` and (if present)
   `alg="ed25519"`, and checks the validity window;
2. looks up the key by `keyid`, which is the **RFC 7638 JWK thumbprint**;
3. rebuilds the RFC 9421 **signature base** from the covered components and the
   request, and runs `ed25519.Verify`.

Keys come from operator-configured agent directories (`webbotauth.directories`),
fetched from each origin's `/.well-known/http-message-signatures-directory` at
startup. Only operator-listed directories are fetched — an attacker's
`Signature-Agent` URL is never fetched, which avoids an SSRF/DoS vector.

Failure is always safe: a wrong base, unknown key, or expired signature makes
verification return false, so the request is treated as *not a verified agent* —
never as a trusted one. A forgery can never pass (Ed25519 is sound).

## Integration

- Ed25519 only (the profile Cloudflare's verifier and signer use).
- A `ports`-less optional `hoster` interface (`Host() string`), implemented by
  `proxy.requestView`, supplies the `@authority` the signature covers — no change
  to the core `RequestView` interface.
- The detector fires `webbotauth.tier` (`block`/`confirmed`/`suspect`) with a
  signal carrying the verified directory origin. `suspect` requires a PoW gate
  (as with velocity).
- Wired through `assembly.WebBotAuth` (shared by the CLI and the library), which
  does the startup directory fetch; keys refresh on restart.

## Validation — the crux

The risk in this feature is the signature base: a one-byte deviation makes real
agents fail to verify. It was validated against the canonical implementation,
not just self-consistency:

- **Cloudflare's reference `web-bot-auth` signer** (npm) was run with the RFC
  9421 Appendix B.1.4 Ed25519 test key to produce a real signed request, captured
  as `testdata/reference.json`.
- Our verifier must accept it (`TestVerifiesReferenceSignature`) and reject
  tampered/expired/unknown-key variants.

Doing this surfaced the one non-obvious detail: the real covered set is
`("@authority" "signature-agent";key="sig1")`, and the `signature-agent`
component value is the Dictionary **member including its parameters**
(`"https://…";type=directory`), not the bare string — which the fixture caught
immediately.

## Scope / future

- No nonce replay protection yet (the nonce is signed over, but uniqueness is not
  enforced); no RSA-PSS; keys refresh only on restart (a background refresh is a
  clean follow-up).
- The reverse-DNS / published-IP-range good-bot verifier (Googlebot/Bingbot) is
  the complementary half of "verified good bots" and ships separately.
