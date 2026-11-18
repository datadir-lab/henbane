# jsprobe: an opt-in device/behavioural fingerprinting module

**Status:** shipped. Built as designed after explicit sign-off (all three tiers,
selectable with `--jsprobe-tier`), as the separate `jsprobe` module and the
`henbane-surveil` binary. It crosses a line the core refuses, which is why it is a
separate, opt-in build; the design below is what was implemented.

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

Even fully built, this does not win, and the reason is sharper than "a sophisticated
adversary evades it." The probe signals are **client-reported**: the browser computes
them and POSTs them, so unlike the TLS and HTTP/2 fingerprints, which the server observes
from the actual handshake and connection and the client cannot easily fake, these are
whatever the client says they are. A determined bot does not even need a browser: it can
POST a clean report (an empty `{}` passes the passive tier; `{"humanInput":true,...}`
passes the behavioural one) to the verify endpoint and get a pass token. The device
fingerprint tier is denylist-only for the same reason: a forger reports a fresh hash each
time.

So the module catches automation that **honestly runs the probe**, the large population
of default and lightly-stealthed headless browsers that expose `navigator.webdriver` or a
software renderer, and it raises the cost for that middle tier. It does not catch a client
that chooses to lie, which includes both the `CloakBrowser`-class modified browser and a
plain scripted client that forges the report. It spends the core's anti-surveillance
posture to get the middle tier; that tradeoff is the operator's to make, which is exactly
why it is a separate, opt-in build. If the signals could be made server-observable they
would be worth far more, but by construction a browser probe cannot be.

## Dependencies

Can be stdlib-only despite being an allowed-deps module: the probe is static JavaScript,
the endpoint and scoring are plain Go. Keeping it stdlib-first matches the project's
minimalism and keeps the surveillance auditable.

## Scope / non-goals

- The core stays provably surveillance-free; this never merges into it.
- No third-party anti-bot SDK; the whole point is a self-hosted, auditable alternative.
- All three tiers are built and selected with `--jsprobe-tier passive|behavioural|device`,
  each including the ones before it. The default is `passive`, the least invasive tier.
  Probe scope follows `pow.mode`: `suspect` probes only flagged clients (the default and
  the designed-for case), `all` probes everyone.

## As built

The core gained a single `henbane.WithChallenger(c, verifyPath)` seam (an exported
`Challenger` interface alias) so an embedder can replace the built-in proof-of-work
challenge; the core ships no challenger of this kind itself. `henbane-surveil` passes the
`jsprobe.Gate` into it. The Gate implements the challenger: it serves the probe
interstitial, and its verify endpoint issues an IP-bound, time-limited HMAC pass cookie
only when the probe report looks human, refusing (403) a client reporting
`navigator.webdriver`, a software WebGL renderer, no human-like input (behavioural tier),
or a denylisted device fingerprint (device tier). Verified live end to end.

## References

- "What Does It Take to Detect an AI Agent? Minimal Feature Sets for Behavioral
  Detection under Browser Automation" (arXiv 2607.26935).
- "On the Internet, Nobody Knows You're an LLM Bot: Unmasking Web Agents with
  Multi-Layer Fingerprinting" (arXiv 2606.30119); "FP-Agent" (arXiv 2605.01247).
- cside, "How to Detect AI Agents and Stealth Browsers" (2026).
