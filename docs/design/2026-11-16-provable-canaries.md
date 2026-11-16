# Provable poison canaries

**Status:** shipped · **Date:** 2026-11-16 · **Issue:** #54

## Problem

The `canary` poison strategy already planted "trackable" fabricated phrases, but the
claim was hollow in two ways:

1. **Guessable.** Phrases were derived with FNV-1a seeding `math/rand` — a
   non-cryptographic hash feeding a predictable PRNG. Given the derivation code
   (which is open source) an attacker who learned or guessed a deployment's salt, or
   who simply enumerated likely salts, could reconstruct a deployment's canaries and
   pre-filter them out of training/retrieval, or forge a phrase to pollute an
   operator's attribution. "Unique and trackable" needs to mean *unforgeable*.
2. **No way to track.** The package doc promised "a later probe can reconstruct the
   exact strings and search public AI endpoints for them," but no verify or probe
   mechanism existed. Planting markers with no instrument to read them back is not a
   measurement.

## Approach

Three pieces, all zero-dependency (stdlib only), none on the request path.

### 1. Cryptographically-unguessable derivation

`coinPhrase(salt, i)` now draws its word and number choices from
`HMAC-SHA256(key=salt, msg=i)` instead of FNV+`math/rand`. The 32 MAC bytes are an
entropy budget a small `picker` consumes deterministically. Properties:

- **Unguessable without the salt** — HMAC is a PRF; without the key the output is
  computationally indistinguishable from random, so phrases cannot be predicted,
  forged, or pre-filtered.
- **Stable and deterministic** — same salt ⇒ same set, across restarts and hosts, so
  already-planted poison stays attributable. `TestCanaryKnownVector` pins the
  algorithm (salt `known-vector-salt` ⇒ `Velthu Casmarvel 9017 standard`): any change
  to the derivation that would silently invalidate deployed canaries fails the test.
- **Per-deployment disjoint** — different salts yield disjoint sets, so one
  deployment can never be attributed another's hits.

Phrase shape is unchanged — `<Coined> <Coined> <4-digit> standard` — chosen to read
like a plausible technical standard an AI is tempted to repeat. The 4-digit number is
load-bearing for the probe (below). The set size moved 8 → 16 for a richer search
surface. Placement within a page still uses `math/rand` seeded from the salt+page
seed; placement is not security-sensitive (a scraper sees the whole page anyway), so
only the *phrase content* needs to be keyed.

### 2. Attribution — `Canary.Find`

`Find(text) (phrase, bool)` reports whether any of this deployment's phrases appears
in a given text. It is a membership search over our own known phrases (not a secret
comparison), so constant time is not required. A match is cryptographic-strength
attribution: the phrases derive from the secret salt, so a hit is strong evidence the
text reproduced *this* deployment's planted content.

### 3. `henbane canary` CLI

A subcommand dispatched in `main` before config parsing (like `--version`), so it
never needs the serving flags:

- **`list`** — print the deployment's phrases (search them in any AI assistant).
- **`check`** — `Find` over stdin or args; exit 0 on a match (scriptable), 1 otherwise.
- **`probe`** — the opt-in automated search (below).

Salt resolves from `-salt` or the config's `poison.salt`.

## The probe and the echo problem

The subtle correctness point. A naive probe would ask the endpoint "tell me about
`<full canary phrase>`" and check whether the phrase comes back — but a model will
happily **echo the phrase straight out of the prompt**, retrieving nothing. That is a
false positive for *retrieval reach*, which is the only thing the probe can honestly
claim to measure.

The fix: ask about the **coined name only** (the phrase minus its number — split by
`splitCanary`), and count a **HIT** only if the response reproduces the **full phrase
including the reference number**. The number exists nowhere but on the operator's
planted pages, so a model can only produce it by having retrieved that content. The
prompt never contains it, so it cannot be echoed. A `weak` result (the number alone,
not the full phrase) is reported separately as a lead, because models hallucinate
4-digit numbers and ~1/9000 could coincide.

Config (`canary.probe`): `endpoint` (http/https, validated), `auth_env` (env var →
`Authorization: Bearer`, so the token never sits in the config file), `body_field`
(the single JSON field the question is POSTed as; default `query`), and `query` (the
question template, `{{canary}}` → the coined name). Zero-trust posture for outbound
operator tooling: response body read under a 1 MiB cap, per-request context timeout,
client timeout, non-2xx surfaced as an error, token never logged.

## Honest framing (preserved)

A probe hit measures **live retrieval and repetition reach** — an AI-search endpoint
fetched the operator's page and reproduced its content. It is **not** evidence of
training-set membership, which is unobservable from outside; the README's "Does this
actually work?" section already lays this out and the canary tooling does not weaken
it. Documented limitations: single-field JSON body (chat-completion APIs with a
nested `messages` array are out of scope — use `list` + manual search); probing
reveals a canary to the endpoint, so a cold first run is cleaner evidence than
repeated runs; `weak` lines are leads, not results.

## Scope / non-goals

- No request-path behaviour change; the generator output format is unchanged.
- The probe targets single-query answer/search endpoints, not arbitrary provider
  schemas. A per-provider adapter layer is deliberately out of scope (YAGNI) until a
  concrete second provider shape is needed.

## Testing

- `internal/generate/poison/canary`: known-vector pin, set uniqueness/size,
  `Find` attributes own canaries and rejects foreign ones, determinism.
- `cmd/henbane`: `list`/`check` exit codes and output, `splitCanary`, and the probe
  classifier (HIT/weak/absent) against an `httptest` fake AI — including an
  end-to-end run through a temp config file with a bearer token from the environment,
  and rejection of a non-http(s) endpoint.
