# Henbane: Strategy

> The short version: **consent is the line.** Train on content with permission,
> fine. Take it without, and you get a tollbooth, a maze, and poison. Henbane is the
> European, open-source defense that enforces that line for the people the big,
> centralized, proprietary platforms can't or won't serve.

This document is the north star for product and business decisions. It is
deliberately opinionated; when a choice conflicts with it, the choice is wrong
until proven otherwise.

## Identity

Three pillars, one direction:

1. **EU-native.** The company (datadir s. r. o.) and the data are European.
   Sovereignty is structural, not a badge: EU entity, EU hosting, EU vendor
   stack, EU data residency. A US competitor is bound by the CLOUD Act; we are
   not. That is a moat no amount of their engineering can close.
2. **Open-source first.** The gateway is free software (AGPL-3.0). Trust comes
   from being auditable, not from a brand promise. The free tier is genuinely
   useful, not crippled bait.
3. **Pro-consent, against non-consensual scraping.** We are **not** anti-AI as a
   technology; we use it ourselves. We are against taking content to train on
   it **without consent**. The hook is "anti-AI-scraping"; the spine is "your
   content, your rules, your border."

The authenticity rule: never blur pillar 3 into anti-AI absolutism. It shrinks
the market, ages badly, and invites hypocrisy charges. Consent is the whole
argument; hold that line and the irony evaporates.

## The problem we attack

AI crawlers scrape the web at industrial scale, largely ignoring `robots.txt`,
to build training sets and answer engines, imposing real bandwidth and compute
costs on sites (FOSS projects, publishers, artists, the small web) and taking
content without permission or compensation. The operators hit hardest are
exactly those least able to afford a centralized commercial gatekeeper.

## Competitive stance

**We do not compete with Cloudflare the company.** It is a multi-billion-dollar
global network with ~15 product lines; matching it is a lost game. We compete
with Cloudflare's *bot / AI-scraping product*, for the segment that **rejects
Cloudflare's model**. Cloudflare is now in this lane (AI Labyrinth, pay-per-crawl).
That is validation that the market is real, and a signal to differentiate on
the things they structurally cannot be:

| Cloudflare's structural weakness | Our wedge |
|---|---|
| Centralized chokepoint; can deplatform | Self-hosted, sovereign, no single point of control |
| Terminates TLS; sees all your traffic (MITM) | Privacy-by-design; self-host sees nothing |
| Not self-hostable; US-controlled | EU entity, on-prem/air-gap capable, data-residency |
| Proprietary black-box detection | Open, auditable, hackable |
| Gatekeeper that brokers AI access | You decide: poison, don't negotiate |

Depth over breadth: be the undisputed best at **one** thing (defending against
non-consensual AI scraping), not the 10th-best at everything.

## Product philosophy

- **Don't fight the classification arms race.** Perfect bot detection is
  unwinnable (agentic headless browsers defeat fingerprinting; vision models
  solve CAPTCHAs). We don't need certainty. Detection just cheaply populates a
  *Suspect* tier; the **graduated response** keeps false-positive cost bounded:

  | Tier | Response | Cost to a mis-flagged human |
  |---|---|---|
  | Suspect | Proof-of-work toll (challenge) | ~2 seconds |
  | Confirmed (honeypot) | Tarpit / labyrinth + poison | served a junk page |
  | Blocked / high-confidence hostile | Decompression-bomb of poison (opt-in) | (guarded; see below) |

- **Privacy-by-design is a feature, not a constraint.** No behavioral biometrics
  (mouse/keystroke), no canvas/WebGL/audio fingerprinting. Cheap, server-side,
  privacy-respecting signals only (coarse TLS fingerprint, client-hint/`Sec-Fetch`
  consistency, datacenter-ASN, request velocity). This is simultaneously the
  ethos, GDPR-by-design, and a differentiator against DataDome/HUMAN.

- **Zero third-party runtime dependencies.** Stdlib-only, hexagonal, TDD,
  architecture-enforced. Auditability and supply-chain integrity are part of the
  trust story, not just engineering hygiene.

## Business model: open-core, EU-hosted

- **Data plane (the gateway): AGPL-3.0, free, self-hostable.** AGPL so a
  hyperscaler cannot run a modified Henbane as a managed service without sharing
  changes. The commons stays a commons.
- **Control plane: commercial.** Dashboard, custom poison/`babble` configuration,
  site visualization, analytics, SSO: the things operators pay for. Runs on an
  EU-only vendor stack (e.g. Bunny, Hetzner, Scaleway; EU billing/email).
- **The moat: the Poison Garden federation.** A community-owned, EU-hosted,
  privacy-preserving shared bot-intelligence feed that gets more valuable the
  more sites join, the one network effect buildable without a global fiber
  network, and the one thing that can't be self-hosted away.
- **Where the money actually is:** not volume indie subscriptions (the self-host
  crowd pays least), but (a) **enterprise / public-sector** who need
  self-hosted, sovereign, privacy-respecting anti-scraping with support/SLA, and
  (b) the **federation feed**. Target EU public sector, healthcare, finance,
  publishers.

## Compliance & sovereignty

GDPR-by-design is nearly free given our data minimization. Pursue ISO 27001 /
NIS2 / EUCS when chasing public sector. Keep an EU-only vendor stack as a
written, contractual guarantee; every vendor choice is a sovereignty decision.

## Explicit non-goals

- **Crypto mining via PoW.** Economically dead (~$0.01/day/browser non-stop;
  Coinhive died in 2019), only runs on the JS-executing minority of scrapers, and
  brands the tool as cryptojacking malware. We make scrapers *pay* (asymmetric
  cost), we do not *mine* off them. [Rejected.]
- **Behavioral biometrics & device fingerprinting.** Privacy-corrosive, heavy, a
  losing arms race, and against the ethos.
- **Becoming a CDN / DNS / DDoS-scrubbing network / Zero-Trust suite.** Every one
  dilutes the wedge. Integrate (Bunny/Fastly) or recommend a provider; do not
  build.
- **Anti-AI absolutism.** See the authenticity rule.

## Phased roadmap

1. **Postures (OSS data plane).** Denylist, honeypot, labyrinth, poison: done.
   Next: **PoW gate** (Suspect → challenge), **privacy-respecting signals**
   detectors (feed Suspect), **decompression-bomb poison** (guarded, opt-in).
2. **Adoption.** Form-factor adapters, so deployment is frictionless: standalone
   proxy (done), Caddy module, embeddable middleware. Themeable challenge
   pages. TLS/ACME.
3. **Control plane.** Dashboard, custom `babble`, visualization, analytics
   (commercial, EU-hosted).
4. **Federation (the moat).** Poison Garden: shared, sovereign, community-owned
   bot intelligence.

The biggest near-term lever is **shipping**: a product under the flag beats a
manifesto without one.
