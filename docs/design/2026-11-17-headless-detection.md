# Headless browser detection: scope, the automation-UA signal, and the honest ceiling

**Status:** partially implemented (the automation-UA signal). The rest is a deliberate
scope decision, documented here so the boundary is a choice, not an omission.

## The problem

Henbane's classifier is strong against cheap scrapers and honest about where it stops.
Its documented ceiling is the **headless browser**: a real browser engine (Chromium,
Firefox) driven by automation (Puppeteer, Playwright, Selenium, or their stealth
successors). Because it is a real engine, it carries a real browser's TLS fingerprint,
a real browser's HTTP/2 fingerprint, and sends the full set of browser headers. Every
signal Henbane has is, by construction, satisfied by it.

This doc records what is feasible for a reverse proxy to do about that, what Henbane now
does, and what it deliberately declines to do.

## The 2026 detection landscape

Dividing the signals by what a reverse proxy can and cannot observe:

**Server-side, no JavaScript (what a proxy reads from the request itself):**

| Signal | Catches | Defeated by |
|---|---|---|
| TLS fingerprint vs claimed browser | A Linux/Go TLS stack claiming Windows Chrome | A real browser engine (its TLS is genuine) |
| HTTP/2 (Akamai) fingerprint | Go/httpx/curl h2 stacks wearing a browser UA | A real browser engine (its h2 frames are genuine) |
| Sec-Fetch / Accept / Accept-Language coherence | Libraries that do not send browser metadata | A real browser engine (it sends all of them) |
| User-Agent sanity (automation tokens) | Default headless that announces `HeadlessChrome` | A one-line UA override |
| IP ASN category (datacenter vs residential) | Cloud-hosted headless fleets | Residential-proxy networks |

**JavaScript-required (needs code execution in the client):**

| Signal | Catches | Defeated by |
|---|---|---|
| `navigator.webdriver` (W3C automation flag) | Default Selenium/Puppeteer/Playwright | `puppeteer-extra-plugin-stealth`, rebrowser, nodriver (all patch it) |
| CDP artifacts (`Runtime.enable`, serialization tells) | Instrumented Chrome | The May 2025 V8 inspector fix plus CDP-minimal drivers (nodriver, selenium-driverless) |
| WebGL renderer / render timing (SwiftShader, llvmpipe) | Server-side software rasterizers | A headless browser given a real or emulated GPU |
| Behavioural scoring (pointer, scroll, typing cadence) | Scripted interaction | Expensive to synthesize per-session, but the hardest to read passively |

The pattern is consistent across the current reporting: the network-layer fingerprints
(TLS, h2) persist because stealth tools operate at the application layer, not the
network stack, but a real browser engine satisfies them anyway. The JavaScript tells
are an arms race measured in months, and the single highest-signal one,
`navigator.webdriver`, is the first thing every stealth tool patches. What remains hard
is behavioural analysis over a session, which a stateless reverse proxy is not
positioned to do and the dedicated anti-bot vendors (Cloudflare, DataDome) build their
products around.

## What Henbane already covers

The TLS fingerprint, HTTP/2 fingerprint, and Sec-Fetch/Accept coherence signals are all
shipped (see `internal/detect/consistency` and the h2 fingerprint design doc). They
catch the scraper that wears a browser UA without a browser's transport. They do not
catch a real browser engine, headless or not, because there is nothing inconsistent
about it at the network layer.

## This slice: the automation-UA signal

Default headless Chrome keeps a self-identifying token in its User-Agent:
`HeadlessChrome` in place of `Chrome`. No shipping graphical browser emits it. The
consistency scorer now flags a browser-claiming UA that also carries a definitive
automation token (`HeadlessChrome`, and the legacy `PhantomJS` / `SlimerJS` engines),
matched case-sensitively exactly as the tools emit them.

Weight: the same as a strong header miss (2, a challenge on its own). The token is
definitive that the client is automated, but a thin legitimate population also ships a
`HeadlessChrome` UA, Lighthouse, PageSpeed Insights, and some uptime monitors, so it
earns a challenge rather than an outright tarpit, and compounds to Confirmed only
alongside another mismatch. This is consistent with the project rule that no single
soft signal exceeds a challenge on its own; definitive handling is reserved for the
denylist and honeypot.

What it catches: the naive population that leaves the default UA in place. What it does
not catch: anything that overrides its UA, which is one line of automation code. This is
a real but bounded win, honestly scoped.

## Considered and rejected

**A JavaScript automation probe on the proof-of-work challenge.** Henbane already runs
client JavaScript in one place: the PoW challenge page. It could collect
`navigator.webdriver` and a few automation tells there and escalate a client that solves
the PoW but reports them. Rejected for three reasons:

1. It catches only the default `navigator.webdriver` flag, which every stealth tool
   (puppeteer-stealth, nodriver, rebrowser) patches. The marginal population over the
   automation-UA signal is small.
2. **Ethos.** Henbane is an anti-surveillance tool. Collecting browser and device
   signals from real visitors to score them is precisely the behaviour it opposes. The
   line is narrow: reading a single W3C automation boolean a client volunteers is not
   user fingerprinting, but the moment the probe reaches for canvas hashes, font lists,
   or WebGL vendor strings to raise confidence, it is building the tracking fingerprint
   the project exists to frustrate. Rather than police that line, this slice does not
   cross it.
3. Cost/benefit is poor: real client JavaScript, a data-collection surface, and new
   failure modes, to catch a population a UA substring already catches.

**A datacenter/hosting-ASN signal.** The research lists IP ASN category as a server-side
signal that still works against cloud-hosted headless fleets. It is deferred, not
rejected: it needs an IP-to-ASN dataset (large, periodically refreshed, a maintenance
and staleness burden like the AI-crawler IP ranges), and residential-proxy networks,
which the sophisticated headless operators use, defeat it. It may be worth a future
slice as another soft signal, weighted low.

## The honest ceiling

Stealth headless, a real browser engine whose UA has been overridden, with a residential
IP, is not detectable by a reverse proxy at the request layer. Henbane does not pretend
otherwise and does not attempt behavioural or device fingerprinting of real users to
close the gap, by design. Two things remain true in its favour:

1. The deterrent does not depend on the classifier. Once any signal escalates a client,
   or it trips the honeypot, the labyrinth and poison impose asymmetric cost regardless
   of how good the fingerprint was. The classifier decides who to deter; it was never
   the whole defence.
2. Operators who need to stop evasive headless at scale should layer a dedicated
   behavioural anti-bot service in front of Henbane. The two compose: the anti-bot
   service handles the headless tier, Henbane handles the cheap-scraper majority and
   turns confirmed hostiles into poisoned dead ends.

## Testing

- `internal/detect/consistency`: the automation-UA token raises the signal on a
  `HeadlessChrome` UA that is otherwise a perfect browser (every header, a real h2
  fingerprint); it compounds to Confirmed with one missing header; and a stealth
  headless with a spoofed UA scores 0 (the pinned honest limitation).
- `research/classifierbench`: a `headless-chrome-naive` profile (default UA) is caught
  as a spoofer; the `headless-chrome` / `headless-playwright` profiles (UA-spoofed
  stealth) stay Pass. The ceiling recall is 0.85, with the two stealth profiles the only
  remaining misses.

## References

- Castle, "How to detect Headless Chrome bots instrumented with Puppeteer / Playwright" (2025).
- "CDP Detection in 2026: After the Runtime.enable Fix"; usefoil.com, "CDP detection in 2026"; "Headless browser detection in 2026, the signals that still work."
- cside.com, "Headless Browser Detection: Signals, Methods, and What Works in 2026."
