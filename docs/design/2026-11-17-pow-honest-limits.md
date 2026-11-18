# Proof-of-work: honest limits

**Status:** documentation. No behaviour change. This records what the 2026 evidence says
about proof-of-work as an anti-scraper measure, so Henbane neither over-sells it nor an
operator over-relies on it.

## What Henbane's PoW is

A challenged client (only `Suspect` traffic under `pow.mode: suspect`, or everyone under
`all`) solves a small SHA-256 puzzle in the browser, receives an anonymous, **IP-bound,
time-limited** session token, and passes through until the token expires (`access_ttl`,
default 1h). It is off by default.

## What the evidence says (2026)

Two independent critiques, both now well documented against the most-deployed
open-source PoW wall (Anubis):

1. **It is weak against a determined scraper, because the economics favour the
   attacker.** A proof-of-work solver written in native code (Go, Rust, C) computes the
   puzzle *far faster* than the JavaScript a real browser runs, so the per-challenge cost
   is **lower for the scraper than for an ordinary visitor** (a proof-of-concept 25-line
   C solver mined a token in ~0.017s; Tavis Ormandy estimated the attacker's compute bill
   would not reach a cent a month until millions of sites deployed it). And because the
   access token is per-IP and lasts for its TTL, a scraper **solves once and then crawls
   freely** for the window, rather than paying per page. By August 2025, scraper bots had
   learned to solve Anubis challenges in bulk.

2. **It is a regressive accessibility tax when applied to everyone.** At a moderate
   difficulty the puzzle is a couple of seconds on a flagship laptop but up to minutes on
   an old phone, and it breaks no-JS browsers and some assistive tech. A wall that
   challenges *every* visitor punishes the slowest, cheapest devices hardest.

## How Henbane positions PoW given this

- **It is a speed-bump against low-effort scrapers, not a wall.** The honest claim is
  that it imposes a one-time cost on an unsophisticated crawler and filters the laziest
  automation; it does not stop a determined scraper with a native solver.
- **The real deterrent is the labyrinth and poison** a confirmed crawler is served, plus
  verified-good-bot allowlisting, not the puzzle. PoW is one mild layer in front of
  those, which is why it is off by default.
- **Henbane already avoids the worst of the regressive tax**: unlike a challenge-everyone
  wall, `pow.mode: suspect` challenges only traffic the classifier already flagged, so an
  ordinary reader is never asked to solve anything; and there is a no-JS fallback. The
  accessibility cost is bounded to already-suspect clients, not the whole audience.

The takeaway for an operator: enable PoW if you want a cheap filter on low-effort
automation, but do not treat it as the defense. The defense is the deterrent and the
good-bot verification. If PoW is the only thing you turn on, you have the weakest layer
and none of the strong ones.

## References

- LWN, "Anubis sends AI scraperbots to a well-deserved fate" (2025), and the Codeberg
  report (Aug 2025) that bots had learned to solve the challenges.
- Tavis Ormandy's native-solver cost estimate; the 25-line C solver proof of concept.
- "Who Pays the Proof-of-Work Tax: The Accessibility Cost of Anti-Scraping Walls" (2026).
