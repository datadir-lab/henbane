# jsprobe: an opt-in device/behavioural fingerprinting module

**Status:** design, not yet built. This is a deliberately-gated proposal because it
crosses a line the core refuses, and should not be implemented until the design is
agreed.

## The ethos problem, stated first

Henbane's core **does not fingerprint real visitors.** That is a product value, not an
accident: a tool built to frustrate surveillance of readers should not surveil them to
catch bots. The deep-research survey confirmed the strategic cost of holding that line:
the sophisticated scraper (a real headful browser, human-paced, on a residential IP)
defeats every network- and header-layer signal, and the *only* thing that reliably
unmasks it is **device and behavioural fingerprinting** executed in the client. So the
core, by design, cannot catch that adversary.

This module is the explicit, opt-in way to cross that line for operators who decide the
tradeoff is worth it for their site. **It is surveillance.** The design's job is to keep
that surveillance (a) out of the core entirely, (b) off by default, (c) scoped as
narrowly as the mechanism allows, and (d) honestly labelled, including its ceiling.

## Why a separate module (not a core flag)

The same reason `h2capture` is separate: the thing that must never touch the core lives
in its own Go module, excluded from the dependency-allowlist and purity tests. Here the
thing to quarantine is not a dependency but a *capability* and a *posture*. A core build
of Henbane must be provably incapable of device fingerprinting; an operator who wants it
runs a different binary and has made a conscious choice. Structure:

- `jsprobe/`: its own `go.mod`, middleware that injects the probe and scores the result.
- `jsprobe/cmd/henbane-surveil`: a drop-in reverse proxy that is the core engine plus
  the probe, mirroring `h2capture/cmd/henbane-h2`.
- The core `henbane` binary never imports it and rejects a `jsprobe:` config key.

## Scope mitigation: probe only already-suspect traffic

The strongest in-design mitigation: the probe does **not** run on every visitor. It runs
on the **challenge/interstitial that a `Suspect` client already receives** (the same
place the proof-of-work page lives). A reader the classifier never flagged is never
probed, never fingerprinted. This keeps the surveillance scoped to traffic that has
already failed the cheap, non-invasive checks, consistent with Henbane's "only act on
flagged traffic" principle even inside the surveillance build. (An operator could be
given a more aggressive "probe everyone" switch, but it is off by default and loudly
flagged.)

## Tiers (build smallest first)

1. **Passive automation tells (MVP).** Collected on page load, no interaction, not
   user-identifying: `navigator.webdriver` (the W3C automation flag), the presence/shape
   of `window.chrome`, a WebGL renderer string that is a software rasterizer
   (`SwiftShader`, `llvmpipe` -> headless/server), an empty `navigator.plugins` on a
   Chrome claim, and missing or inconsistent browser APIs. These catch default and
   lightly-stealthed automation. They are automation signals, not tracking fingerprints.
2. **Behavioural (phase 2, adds friction).** An interstitial that watches for human-like
   input (pointer curvature, timing jitter, scroll variance) before issuing the pass
   token. This is the tier the literature says actually separates a residential-proxy
   agent from a human, and the tier with real UX cost.
3. **Device fingerprint (phase 3, most invasive).** Canvas/font/WebGL hashing for
   cross-request identity. The strongest signal and the most straightforwardly
   "surveillance"; included for completeness, gated hardest, documented loudest.

## Mechanism

- The probe is a small inline script on the challenge page. It computes the tier's
  signals and POSTs them to a verify endpoint alongside the PoW solution (reusing the
  existing token machinery), so one round-trip both proves work and reports the probe.
- The server validates and feeds the signals into the engine as `ports.Scorer` results
  (`jsprobe:webdriver`, `jsprobe:swiftshader`, `jsprobe:no_human_input`, ...), which the
  existing fusion scoring accumulates exactly like the header and fingerprint signals. A
  strong automation tell can escalate a client that solved the PoW but is clearly a bot.
- Data handling: the raw signals are used to compute a score and are **not** stored as a
  per-user record; the decision log keeps the derived signal names, not canvas hashes.
  (Phase 3's device hash is inherently identifying; its retention is a documented
  operator choice.)

## Honest ceiling

Even fully built, this does not win. The current research adversary, a source-modified
browser fingerprint behind a residential IP (`CloakBrowser` in the 2026 benchmarks),
presents a clean device fingerprint and human-like behaviour and is not reliably
separable. The module raises the cost and catches the large middle tier of automation
that the core cannot; it does not catch the top tier, and it spends the core's
anti-surveillance posture to do it. That tradeoff is the operator's to make, which is
exactly why it is a separate, opt-in build.

## Dependencies

Can be stdlib-only despite being an allowed-deps module: the probe is static JavaScript,
the endpoint and scoring are plain Go. Keeping it stdlib-first matches the project's
minimalism and keeps the surveillance auditable.

## Scope / non-goals

- The core stays provably surveillance-free; this never merges into it.
- No third-party anti-bot SDK; the whole point is a self-hosted, auditable alternative.
- Behavioural and device tiers are phases, not part of the MVP. The MVP is the passive
  automation tells, which are the least invasive and catch the most per unit of risk.

## References

- "What Does It Take to Detect an AI Agent? Minimal Feature Sets for Behavioral
  Detection under Browser Automation" (arXiv 2607.26935).
- "On the Internet, Nobody Knows You're an LLM Bot: Unmasking Web Agents with
  Multi-Layer Fingerprinting" (arXiv 2606.30119); "FP-Agent" (arXiv 2605.01247).
- cside, "How to Detect AI Agents and Stealth Browsers" (2026).
