# Verified AI crawlers by published IP range

**Status:** shipped · **Date:** 2026-11-15

## Problem

Henbane can already verify *good bots* two ways: forward-confirmed reverse DNS
(`goodbot`, for search engines like Googlebot) and cryptographic Web Bot Auth
(`webbotauth`, for agents that sign their requests). Neither covers the biggest
AI crawlers. OpenAI's GPTBot/ChatGPT-User/OAI-SearchBot, Anthropic's ClaudeBot
family, and PerplexityBot:

- expose **no reverse DNS**, so FCrDNS can't confirm them, and
- **don't sign** their requests, so Web Bot Auth doesn't apply.

What they *do* is publish, on a first-party URL, the **IP ranges** their requests
originate from. An operator who wants these crawlers to index them needs a way to
recognise the real ones (and not tarpit/poison them) while still catching the
many scrapers that spoof their User-Agents.

## Approach

A third good-bot verifier on the existing `ports.Verifier` seam, identical in
shape to `goodbot`, but the proof is **IP membership in a published CIDR set**
instead of a DNS round-trip:

1. The client's User-Agent matches a known crawler token (`gptbot`,
   `chatgpt-user`, `oai-searchbot`, `claudebot`/`claude-searchbot`/`claude-user`,
   `perplexitybot`, `perplexity-user`).
2. If the client IP is inside that crawler's published prefixes → **allow**
   (`TierPass`, signal `ai_crawler:<name>`), bypassing the suspicion pipeline.
3. If the UA claims a crawler but the IP is **outside** its ranges → **spoofer**
   (`spoofed:<name>`), acted on at `verified_ai_crawlers.spoof_tier`
   (`off` by default → no opinion, detectors decide).
4. UA matches nothing → no opinion.

Verification is a pure in-memory check. Unlike FCrDNS, there is **no I/O at
all** on (or off) the request path.

## Bundled data, generated from first-party feeds

`internal/detect/crawlerips/gen/main.go` fetches each vendor's own feed
(`openai.com/gptbot.json`, `claude.com/crawling/bots.json`,
`perplexity.ai/perplexitybot.json`, etc., all sharing Google's
`{prefixes:[{ipv4Prefix|ipv6Prefix}]}` schema) and writes `data_gen.go`. Every
prefix is parsed and re-emitted in masked, sorted, de-duplicated form, so the
bundled snapshot is guaranteed valid and produces stable diffs. Refresh with
`go generate ./internal/detect/crawlerips/...`.

**Only first-party feeds** are used, never a community aggregator, so the trust
root is the vendor itself. `Defaults()` skips any prefix that fails to parse
rather than panicking, so a bad snapshot can never crash the gateway at startup.

## Zero-trust / threat model

- **No request-path I/O**, no network at request time: a flood of crawler-UA
  requests just does ~N `Prefix.Contains` comparisons (N bounded by the bundled
  set) and can't stall the server or trigger outbound traffic.
- **Fail safe**: the default `spoof_tier: off` means an unverified claimant gets
  *no opinion* (the normal detectors handle it), never an accidental allow. Only
  a positive IP-range match grants the allow.
- **UA is never trusted on its own**: it only selects *which* range set to check
  the IP against. The IP is the authority.
- **Allow-listing is opt-in and bounded**: OAI-AdsBot is deliberately excluded
  from the bundled set (ad infrastructure, not a content crawler).

## Staleness

Published ranges drift. The bundled snapshot is a point-in-time copy; the safe
failure mode dominates (a newly-published crawler IP is simply *not yet verified*
→ no opinion → detectors decide). The one residual risk, a retired crawler IP
reassigned to a spoofer, is mitigated by periodic regeneration. A background
refresher that re-fetches the feeds and swaps the set atomically (reusing the
federation-style async pattern, off by default) is a clean follow-up.

## Config

```yaml
verified_ai_crawlers:
  enabled: true
  spoof_tier: block   # off (default) | suspect | confirmed | block
```

Wired in `assembly.buildVerifiers` alongside `goodbot`; the shared
`parseSpoofTier` helper maps the tier string for both verifiers.
