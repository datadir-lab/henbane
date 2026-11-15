# Classifier benchmark & competitive comparison

*How Henbane's classifier is built, how it performs on a labelled corpus, and
where it honestly sits against the rest of the field.*

## TL;DR

- Henbane's classifier is a **weighted scoring engine** (hard rules + verifier
  short-circuit + soft-signal fusion) — the same architectural class as Anubis's
  `WEIGH` engine and OWASP CRS's anomaly score, and richer than fail2ban.
- On a labelled corpus it catches **6/6 representative HTTP-library scrapers**
  wearing a spoofed browser User-Agent with **0 false positives** on 5 real
  browsers — and it **documents the two things it cannot catch** (a real headless
  browser; an honest non-browser client).
- The honest frame: **Henbane competes with Anubis / go-away / OWASP CRS, not with
  Cloudflare / DataDome.** It is *ahead* of Anubis on good-bot verification (full
  reverse-DNS + Web Bot Auth + IP-range triad; Anubis still has Web Bot Auth only
  as an open issue) and on the deception layer (labyrinth + poison), and *behind*
  the commercial ML systems on raw fingerprint depth (no device/behavioural ML, a
  coarse TLS fingerprint, no HTTP/2 frame fingerprint).
- Like **every** system — Cloudflare included — it concedes that determined
  headless browsers behind residential proxies can't be blocked on request
  metadata alone. Against those, **deception (tarpit + poison) is a more honest,
  lower-collateral tool than a proof-of-work wall**, and is Henbane's real
  differentiator.

---

## 1. Benchmark: the scoring classifier on a labelled corpus

Reproducible: `go test -v ./research/classifierbench`. The harness runs
representative request shapes through the scoring engine + the browser-consistency
scorer (the layer that judges "does this client that *claims* to be a browser
actually behave like one?"). Header sets are the defaults these clients typically
send; exact values drift by version, so the corpus is representative, not a
version-pinned capture.

The corpus: **6 real browsers** (incl. a legit HTTP/1.1 Firefox), **8 scraper
libraries** wearing a spoofed Chrome UA (Go net/http, Python requests/httpx, curl,
Scrapy, node, Java HttpClient, wget), and **3 out-of-scope** cases (two headless
real browsers, one honest curl).

**Metrics** (positive = caught at tier ≥ Suspect):

| framing | precision | recall | F1 |
|---|---|---|---|
| naive scrapers vs. real browsers | **1.00** | **1.00** | **1.00** |
| + headless browsers counted as positives | 1.00 | **0.73** | 0.84 |

Every naive scraper is caught (5 → tarpit, Scrapy → challenge) with **zero false
positives** on 6 real browsers. The second row is the honest ceiling: once real
headless browsers are counted as things that *should* be caught, recall falls to
0.73 — they send the full browser shape and this layer can't tell them apart.

**Per-signal ablation** (spoofers caught of 8 with one weight disabled): removing
any single signal *except* fetch-metadata still catches **8/8** — the signals are
**redundant**, because a naive scraper misses several browser behaviours at once.
Detection therefore survives any one signal being individually spoofed; removing
Sec-Fetch alone drops it to 7/8.

**Threshold sweep** (the detection / false-positive tradeoff):

| `suspect_threshold` | spoofers caught | false positives |
|---|---|---|
| 1 | 8/8 | **1/6** (flags the HTTP/1.1 Firefox) |
| **2 (default)** | **8/8** | **0/6** |
| 3 | 8/8 | 0/6 |
| 4 | 7/8 | 0/6 |
| 5 | 3/8 | 0/6 |

The default threshold of 2 is the sweet spot — maximal detection at zero false
positives; lowering it to 1 would flag a legitimate HTTP/1.1 browser, which is
exactly why 2 is the floor.

### What this does and does not show

- **Scope.** It measures the UA-spoofing classifier *in isolation* — not the full
  stack (which adds denylists, velocity, good-bot verification, TLS-fingerprint
  denylist, and federation). It is deliberately the hardest-to-game part to
  self-benchmark, so the corpus includes the cases it **fails**.
- **`headless-chrome` (miss, by ceiling).** A real headless browser sends the full
  browser request shape; nothing at the header layer separates it from a human.
  This is the industry-wide ceiling (see §3). A TLS/HTTP-2 or behavioural signal
  is required — tracked as future work.
- **`honest-curl` (miss, by design).** An honest non-browser client doesn't claim
  to be a browser, so the consistency scorer correctly ignores it. Honest
  automated clients are the job of the denylist / velocity / good-bot layers, not
  this scorer.
- **Self-benchmark caveat.** The same author wrote the corpus and the detector.
  That is mitigated by using realistic client defaults (not strawmen), including
  the failing cases, and keeping the harness open so anyone can add profiles — but
  it is a benchmark of Henbane's behaviour, not an independent audit.

---

## 2. Signal-coverage matrix

Y = built-in · N = no · opt = optional/off by default · ~ = partial/indirect.
Commercial effectiveness figures are vendor self-reported and not independently
audited.

| System | OSS / self-host | Classifier | TLS fp | HTTP/2 fp | Device/JS fp | Behavioural | Good-bot verify | PoW | Tarpit | Poison | Reputation / federation |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Henbane** | **AGPL / yes** | weighted score + rules + verifier | ~ coarse | N (planned, opt-dep) | N | ~ velocity | **Y (rDNS + Web Bot Auth + IP ranges)** | Y | **Y** | **Y** | Y (feed + reporter) |
| Anubis | MIT / yes | weight score + rules | N | N | N | N | Y (UA + CIDR + rDNS) | Y | N | N | opt DNSBL |
| go-away | MIT / yes | CEL rules + fp | **Y (JA3N/JA4)** | ~ | ~ | N | Y (IP ranges) | opt | N | N | DNSBL |
| Nepenthes | MIT / yes | none (trap you link to) | N | N | N | N | N | N | **Y** | **Y (Markov)** | N |
| Iocaine | MIT / yes | per-request script | N | N | ~ | N | ~ | N | ~ | **Y (Markov)** | ~ |
| CrowdSec | MIT / yes | behavioural + crowd reputation | N | N | **Y (1.8)** | Y | Y | **Y (1.8)** | N | N | **Y (federation)** |
| OWASP CRS | Apache-2 / yes | anomaly score | N | N | N | N | ~ (UA blocklist) | N | N | N | N |
| fail2ban | GPL / yes | per-IP threshold | N | N | N | ~ | N | N | N | N | ~ local |
| Cloudflare Bot Mgmt | no / cloud | **ML score 1–99** | **Y (JA3+JA4)** | **Y** | Y | Y | Y (+ Web Bot Auth) | N (AI Labyrinth) | **Y** | ~ decoys | Y |
| DataDome / HUMAN / Kasada | no / cloud | **ML** | **Y** | **Y / ~** | Y | Y (biometrics) | Y | ~/Y | N | N | Y |

Reading of the matrix: on the **left** (fingerprint depth / ML) Henbane sits with
the open-source field and well below the commercial ML systems. On the **right**
(good-bot verification, PoW, tarpit, poison, federation) it is at or ahead of the
whole open-source field — notably the **only** open-source entry that pairs a
full good-bot-verification triad with a content-poisoning layer.

---

## 3. What each signal is actually worth (the evasion reality)

Valuing a simple classifier honestly means admitting no single network-layer
signal is a wall:

- **TLS JA3/JA4** is cheaply forged for one function argument — `curl_cffi`
  `impersonate="chrome"`, uTLS `ClientHelloID` — and JA3 is effectively obsolete
  (Chrome 110+/Firefox 114+ randomise extension order, so one browser yields many
  JA3s). JA4 is better but still non-unique.
- **HTTP/2 frame fingerprint** is more robust against *simple* clients (">95% of
  automated HTTP/2 clients don't match any known browser") but is reproduced by
  impersonation toolkits.
- **IP reputation / ASN** is defeated by residential/mobile proxies (85–99%
  success) and CGNAT makes range-blocking dangerous.
- **Proof-of-work taxes, it does not classify.** A native solver reportedly clears
  ~11,000 Anubis sites in minutes for well under 1¢; the cost lands asymmetrically
  on every low-end *human* device.
- **Headless real browsers** (nodriver / patchright / Camoufox) defeat header and
  TLS signals and increasingly behavioural ones.
- **Scale:** Imperva 2024 put bad bots at 32% of traffic with **60.5% of bad-bot
  traffic "evasive"** (real-browser automation).

Academic consensus: TLS/header features classify *simple* bots well but "cannot
distinguish humans from bots using full-stack emulation"; behaviour is the most
evasion-resistant layer and the least faked; the strongest systems **fuse** layers
and look for **cross-layer contradiction** (TLS vs HTTP/2 vs header order vs
claimed UA). Henbane's consistency scorer is a small, cheap instance of exactly
that contradiction-detection idea, at the header+protocol layer.

---

## 4. Honest positioning

1. **Right league.** A weighted header/path/IP scoring classifier is the same
   class as Anubis's `WEIGH` and CRS's anomaly score, and richer than fail2ban.
   Anubis — the headline comparator — *also* has no TLS/HTTP-2 fingerprinting and
   its author calls PoW "a placeholder… so more time can be spent on
   fingerprinting." So "no ML, no raw TLS/h2 fingerprint" is **parity** with the
   open-source field, not a gap.
2. **Effective where it counts, cheaply.** Header/UA/protocol signals reliably
   catch the plain HTTP-library scrapers (curl/requests/Scrapy/Go) that make up a
   large share of volume and are exactly what overwhelmed FOSS infrastructure —
   the benchmark in §1 bears this out.
3. **Honest ceiling.** The same signals are near-worthless against the ~60% of
   bad-bot traffic that is evasive (headless + residential + impersonation). We
   don't claim otherwise; §1 includes the headless miss on purpose.
4. **Deception is the real differentiator.** Precisely because fingerprinting
   can't reliably block evasive crawlers, the labyrinth + poison stage degrades
   the exact adversary (LLM-training crawlers) that a wall can't stop — at lower
   collateral than taxing every human with PoW. Henbane already leads with
   "classify cheaply → poison the bots → PoW only as a weight tier," which answers
   the loudest criticism of the PoW-everyone approach head-on.
5. **Ahead of Anubis where it matters for this niche:** shipped **Web Bot Auth**
   (RFC 9421; still an open issue in Anubis), the full reverse-DNS + IP-range
   good-bot triad (so verified crawlers aren't poisoned — the mistake Nepenthes
   makes on purpose), metrics, and federation.

> A no-ML header/scoring classifier catches the simple-HTTP-client majority as
> well as Anubis or OWASP CRS do, verifies good bots the way the big players do,
> and concedes — as every system including Cloudflare effectively does — that
> determined headless browsers behind residential proxies can't be blocked on
> request metadata alone. Against those, deception is a more honest, lower-
> collateral tool than a proof-of-work wall.

---

## 5. Cheap future wins (ranked by value/cost)

1. **HTTP/2 SETTINGS / pseudo-header-order fingerprint** — flags >95% of naive
   HTTP/2 clients and is the single strongest anti-spoofing signal reachable
   without device JS. Not reachable in the zero-dep core (Go hides the raw
   frames); ships as an optional-dependency module. See
   `docs/design/2026-11-15-scoring-classifier.md`.
2. **ASN / datacenter-IP scorer** — a weighted soft signal that compounds with
   consistency (needs an embedded dataset). Residential proxies evade it, so it's
   a contributor, never a gate.
3. **Observe mode** — classify-and-log without acting, so an operator can tune
   thresholds from their own traffic before turning scoring up. The cheapest way
   to reduce the false-positive risk that bites every aggressive bot defence.

---

## Sources

Project docs & code: Anubis (`TecharoHQ/anubis` policies.mdx, botPolicies.yaml,
issue #744 for Web Bot Auth), go-away (`git.gammaspectra.live/git/go-away`),
Nepenthes (zadzmo.org/code/nepenthes), Iocaine (codeberg.org/iocaine), CrowdSec
1.8 bot detection (crowdsec.net), OWASP CRS anomaly scoring (coreruleset.org).
Commercial: Cloudflare bot-score / detection-engines / JA4 Signals / AI Labyrinth
/ Web Bot Auth blogs (developers.cloudflare.com, blog.cloudflare.com), DataDome /
HUMAN / Kasada / Akamai / AWS WAF Bot Control docs. Evasion & measurement:
curl-impersonate, uTLS, ntop "is JA4 obsolete", Scrapfly HTTP/2 tool, Imperva 2024
Bad Bot Report, arXiv 2602.09606 (TLS classification) and 2412.02266 (BOTracle
feature importance), and the Anubis false-positive discussions (LWN, GNOME
Discourse, HN). Full URLs were gathered in the competitive survey that produced
this document; figures marked vendor-reported are not independently audited.
