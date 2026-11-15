# Scoring classifier (signal fusion)

**Status:** shipped · **Date:** 2026-11-15

## Problem

Henbane's pitch is that its *classifier* is the differentiator vs. single-trick
tools. But the engine was `max()` over independent detectors: each one raised the
tier on its own, and signals never combined. A real adversary beats each tripwire
in isolation — and the most common evasion (spoofing a browser `User-Agent`)
tripped at most one weak signal. The engine couldn't express "a datacenter IP
*and* a browser-UA-with-no-Sec-Fetch *and* HTTP/1.1 is a confident bot, but any
one alone is not."

## Approach: a `Scorer` seam + weighted accumulation

Additive to the existing engine — the `Detector` and `Verifier` seams are
untouched:

- **`ports.Scorer`** returns `[]ScoreResult{Signal, Points}` — soft evidence, not
  a verdict. The engine sums every scorer's points; the total escalates the tier
  to Suspect at `suspect_threshold` and Confirmed at `confirm_threshold`.
- Scoring runs **after** the detectors and **only raises** the tier, so a
  definitive detector (honeypot, denylist) or a verifier short-circuit (verified
  good bot / impostor) always wins.
- Every scorer signal is recorded on the Event even when the total stays below a
  threshold, so the decision log shows *why* — the evidence, not just the verdict.

Thresholds default to 2 (Suspect → challenge) and 4 (Confirmed → tarpit+poison),
tuned so one strong mismatch costs a brief PoW while two compound into the maze.

### The first scorer: browser consistency

`internal/detect/consistency` scores how well a browser-claiming request actually
behaves like that browser. It only fires on clients wearing a mainstream-browser
UA (honest curl/Python are left to other detectors), keeping false positives
narrow. Weighted misses: no `Sec-Fetch-Site` (2), no `Accept` (2), no
`Accept-Language` (1), `Accept-Encoding` without gzip/br (1), and HTTP/1.1 while
claiming a modern browser (1, via the optional `ports.ProtocolViewer`). This
subsumes the old standalone `browserhint` detector, which is dropped when scoring
is on to avoid double-counting.

## Why not deep HTTP/2 fingerprinting (yet)

The strongest anti-spoofing signal is the **Akamai HTTP/2 fingerprint** — a
client's `SETTINGS` frame (values + order), connection `WINDOW_UPDATE` increment,
`PRIORITY` tree, and pseudo-header order (`:method,:authority,:scheme,:path`).
These are emitted deep in the HTTP/2 engine and are **not request-level options**,
so a scraper can't mimic a browser's h2 fingerprint without replacing its
transport. Worked examples from the research:

- Chrome: `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
- Firefox: `1:65536;4:131072;5:16384|12517377|3:0:0:201,…|m,p,a,s` (its 5-frame
  PRIORITY tree is the single most reliable discriminator)
- Go `net/http`: `2:0;4:4194304;6:10485760|1073741824|0|a,m,p,s` (the `a,m,p,s`
  pseudo-header order is the dead giveaway of a stdlib bot)

The first three fields need **no HPACK** — they're in the plaintext connection
preface frames. **But to read any of them, something must see the raw HTTP/2 byte
stream before the server parses it.** Go's stdlib makes that impossible
zero-dep: `http.Server` couples HTTP/2 to the concrete `*tls.Conn` type (wrap it
and Go silently drops to HTTP/1.1), and the only override hook (`TLSNextProto`)
hands you the conn but then expects *you* to be the whole HTTP/2 server. So deep
h2 fingerprinting needs either `golang.org/x/net/http2`'s Framer (a third-party
dependency, forbidden in the core) or a hand-rolled h2 server.

**Decision:** keep it out of the zero-dep core and track it as a future
**optional-dependency module** (the same pattern as the Caddy plugin — a separate
Go module so its deps never touch the core). The zero-dep protocol signal ("did
the client negotiate HTTP/2 at all?") is a lighter stand-in that scoring already
uses. JA4H (method/version/cookie/referer/header-count/Accept-Language) is a
partial zero-dep option for a later slice — though Go's header map loses the
header *order* that JA4H's strongest component needs.

## Tests

- Engine fusion: below-threshold records-but-allows, reaches-Suspect,
  compounds-to-Confirmed, only-raises (a definitive Blocked isn't downgraded),
  inert-when-disabled, verifier-short-circuits-before-scoring.
- Consistency scorer: real browser scores 0, non-browser UA ignored, bare bot
  compounds, single miss is Suspect-level, protocol signal present/absent.
- **End-to-end** (`cmd/henbane`): a real HTTP client through the full stack — a
  well-formed browser request reaches the upstream, one missing header is
  challenged, and a bare client wearing a Chrome UA is tarpitted (not passed, not
  merely challenged) — proving the compounding a `max()` engine can't do.

## Config

```yaml
pow: { mode: suspect }
scoring: { enabled: true, suspect_threshold: 2, confirm_threshold: 4 }
```

Scoring requires the PoW gate (`pow.mode` suspect or all), since a scored-Suspect
client is challenged.
