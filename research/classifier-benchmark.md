# Classifier study: benchmark, false-positive analysis, and competitive comparison

*How Henbane's classifier is built, how it performs on a verified labelled corpus,
where it draws false positives, and where it honestly sits against the field.*

This is a **critical** study: it is written to find the classifier's weaknesses,
not to flatter it. The headline is not a single number but a tradeoff.

## Headline

- Against **naive HTTP-library scrapers** wearing a spoofed browser User-Agent
  (Go, Python, curl, wget, axios, Java, Scrapy), the classifier is near-perfect:
  **8/8 caught**, because they each omit *several* things a browser sends.
- **But the single signal doing most of that work (a missing `Sec-Fetch-Site`
  header) also flags legitimate browsers released before Fetch Metadata shipped**
  (Chrome <76 / 2019, Firefox <90 / 2021, Safari <16.4 / 2023). On the corpus,
  **all 3/3** such browsers are flagged (FPR 0.33).
- At realistic bot base rates this **collapses precision**: with FPR 0.33, at a
  **1% bot rate precision is 0.03**. 97% of "catches" would be legitimate old
  browsers. The balanced-corpus F1 of 1.00 hides this entirely.
- A **careful scraper that omits only `Sec-Fetch-Site` is header-identical to an
  old Safari**: no *header* signal can separate them (the header-layer ceiling). The
  non-header signal that *does* separate them is the **HTTP/2 fingerprint** (optional
  `h2capture` module, #55). The corpus now carries each client's measured h2
  fingerprint, and **§2.7** shows the signal moving the careful scraper to the tarpit
  while every old browser stays at a challenge, with **zero new false positives**.
- Three things make the default defensible anyway: the false-positive cost is a
  one-time **proof-of-work challenge, not a block** (every JS-capable old browser
  solves it); the **good-bot verifier rescues real crawlers** (Googlebot is
  flagged by the scorer alone but allowed once FCrDNS-verified); and the flagged
  population **shrinks over time**. The classifier is one soft signal in a fusion
  engine, not a standalone wall, which is why the **labyrinth + poison, not the
  classifier, are Henbane's real differentiator.**

Everything below is reproducible: `go test -v ./research/classifierbench`.

---

## 1. Methodology

**Corpus.** 23 representative request shapes. Each client's headers are its
**verified defaults**, read from project source or official docs (cited in §7),
not guessed. The first version of this study got some of these wrong (e.g. axios sends `gzip, compress, deflate, br`,
not zstd; Java HttpClient defaults to HTTP/2 and sends no `Accept-Encoding`;
wget/urllib3 send `Accept-Encoding: identity`). `br`/`zstd` are treated as
environment-dependent and only included where a client sends them by default.

**Classes.**

| class | meaning | ideal verdict |
|---|---|---|
| `human` | modern mainstream browser | pass |
| `human-edge` | legitimate browser predating Fetch Metadata | pass (but is flagged, the FP surface) |
| `good-bot` | verified crawler (Googlebot) | pass (rescued by the verifier, not the scorer) |
| `spoofer` | naive scraper library wearing a browser UA (and default headless Chrome, which announces `HeadlessChrome`) | caught |
| `spoofer-hard` | careful scraper, header-identical to an old browser | caught, but indistinguishable from `human-edge` |
| `known-miss` | stealth headless browser (UA overridden to a normal browser string) | out of this signal class |

**What is measured.** The `consistency` scorer *in isolation* (not the full
stack, which adds denylists, velocity, TLS-fp denylist, good-bot verification,
and federation). This is deliberate: it is the hardest part to self-benchmark, so
the corpus is built to expose where it fails. Each profile also carries its client's
measured Akamai HTTP/2 fingerprint, so the HTTP/2 signal can be isolated (§2.7).

**Metrics.** Precision / recall / F1 (positive = escalated to ≥ Suspect);
false-positive rate measured against the *legitimate* population (modern + edge
browsers); and base-rate-adjusted precision `p = (b·TPR) / (b·TPR + (1−b)·FPR)`
for bot base rate `b` (Axelsson's base-rate correction, ref [10]).

### The 10 critical iterations

This study was hardened in ten passes, each fixing a specific weakness of the
previous one:

1. **Verified headers.** Replaced guessed client defaults with source-cited real
   ones (§7); fixed axios/Java/wget/Scrapy errors.
2. **Edge-case legitimate clients.** Added the pre-Fetch-Metadata browsers that a
   `Sec-Fetch-Site` check wrongly flags (the real false-positive surface).
3. **Hard spoofers.** Added a careful scraper that sets every header but Sec-Fetch.
4. **Baselines.** Compared against the cheap rules real tools use (empty-UA,
   UA-token blocklist, no-Accept).
5. **Base-rate precision.** Reported precision at 1 to 50% bot priors, not just on a
   balanced corpus.
6. **Per-difficulty confusion.** Split detection by adversary difficulty rather
   than one aggregate F1.
7. **Weight-tuning tradeoff.** Quantified that lowering the Sec-Fetch weight
   spares old browsers but drops careful scrapers. No free lunch.
8. **Honest FPR in the base-rate math** (counting edge browsers as legitimate),
   which is what makes the precision collapse visible.
9. **Methodology + references.** This section, plus the verified reference list.
10. **Threats to validity.** §6: every remaining limitation, stated.

---

## 2. Results

### 2.1 Detection by adversary difficulty

Negatives = modern browsers only (the edge-browser FP is reported separately in §2.2).

| adversary set | precision | recall | F1 |
|---|---|---|---|
| naive scrapers | 1.00 | 1.00 | 1.00 |
| + careful (header-perfect) scraper | 1.00 | 1.00 | 1.00 |
| + real headless browsers | 1.00 | **0.85** | 0.92 |

Naive and even a careful single-signal scraper are caught, and so is default headless
Chrome: it keeps a self-identifying `HeadlessChrome` User-Agent that no real browser
emits. What is NOT caught is stealth headless, a real browser engine whose UA has been
overridden to a normal browser string: it sends the full browser shape and a genuine
browser h2 fingerprint, so nothing at this layer separates it from a human. That is the
ceiling. §2.7 shows the HTTP/2 fingerprint lifting the careful-scraper case above it;
stealth headless remains the gap.

### 2.2 The false-positive surface (the critical finding)

| legitimate browser | released | flagged? |
|---|---|---|
| Safari < 16.4 | pre-2023-03 | **yes → challenged** |
| Firefox < 90 | pre-2021-07 | **yes → challenged** |
| Chrome < 76 | pre-2019-07 | **yes → challenged** |

**3/3 (FPR 0.33 on the corpus's legitimate population).** These browsers predate
`Sec-Fetch-Site` and are indistinguishable, at the header layer, from a scraper.

### 2.3 Base-rate precision (the collapse)

With the measured FPR of 0.33 (driven by the edge browsers):

| bot base rate | precision |
|---|---|
| 1% | **0.03** |
| 5% | 0.14 |
| 10% | 0.25 |
| 30% | 0.56 |
| 50% | 0.75 |

This is the base-rate fallacy (ref [10]): when bots are rare, even a moderate FPR
means most "catches" are legitimate. The honest reading is that the *raw*
consistency score is **not a block-grade signal**. It is a challenge-grade one,
which is exactly how Henbane uses it (→ PoW, not → 403).

### 2.4 Baseline comparison

| detector | spoofers caught | false positives |
|---|---|---|
| **Henbane scoring** | **8/8** | 3/9 |
| empty-UA block (fail2ban-style) | 0/8 | 0/9 |
| UA-token blocklist (Anubis/CRS-style) | **0/8** | 0/9 |
| no-Accept single rule | 2/8 | 0/9 |

A **UA-token blocklist catches 0/8** of the spoofers. They wear a clean Chrome
UA, invisible to a UA-regex. That is the empirical reason the scorer exists: it
catches a population the cheap rules can't, at the cost of the old-browser FPs the
cheap rules don't have. They are complementary layers.

### 2.5 The weight-tuning tradeoff

| configuration | naive caught | edge-browser FP | careful scraper |
|---|---|---|---|
| header layer, Sec-Fetch weight **2** | 8/8 | **3/3** | caught |
| header layer, Sec-Fetch weight **1** | 8/8 | **0/3** | **missed** |
| **+ HTTP/2 fingerprint**, weight 1 | 8/8 | **0/3** | **caught** |

At the header layer there is no free lunch, because the careful scraper and an old
browser are the same bytes. Weight 2 catches the scraper but flags every old
browser (edge-FP 3/3). Weight 1 spares the old browsers (edge-FP 0/3) but misses
the scraper. The **HTTP/2 fingerprint resolves it**: at weight 1 it still catches
the careful scraper while the old browsers stay spared, because the scraper's h2
fingerprint is not a browser's. Measured in `TestWeightTuningTradeoff`; the full
breakdown is §2.7.

### 2.6 Header-layer indistinguishability

At the header layer, `safari-15.6 → suspect` and `stealth-scraper → suspect`:
identical bytes, identical verdict. No header feature separates a careful scraper
from an old real browser. Separating them requires a *different layer*: TLS or
HTTP/2 fingerprinting (refs [3][7][9]), or behaviour (ref [8]). The **HTTP/2
fingerprint shipped** (optional `h2capture` module, #55), and the corpus now carries
each client's measured h2 fingerprint. With it on, `stealth-scraper → confirmed`
while `safari-15.6 → suspect` stays put: the tie is broken, with no new false
positive. §2.7 measures this. Behavioural fingerprinting remains future work for the
headless case, and deception handles the ones no signal can block.

**Quantified evasion floor.** The checks are presence-only, so the evasion cost is
a fixed, tiny number of header lines. A default `python-requests`/`httpx` client
(which already sends `Accept: */*` and `Accept-Encoding: gzip`) needs only **two**
added headers (`Sec-Fetch-Site` and `Accept-Language`) to drop below the Suspect
threshold and be allowed: being HTTP/1.1 it retains a single legacy-http point
(score 1 < 2), while an HTTP/2 client scores **0** outright *at the header layer*.
(With the optional `h2capture` module wired, that HTTP/2 client no longer scores 0:
its HTTP/2 fingerprint (pseudo-header order, or a `HEADER_TABLE_SIZE` of 4096) is a
non-header signal it cannot shed by adding headers; that is exactly what #55 adds.)
So the *header-layer* floor is two to three header lines. This layer is a filter for
*low-effort* bots, not a wall;
its value is catching the large volume of scrapers that haven't bothered, not the
ones that have. (An adversarial scorer audit established this floor; it is why the
layer feeds a challenge and the deception stage, not a block.)

### 2.7 What the HTTP/2 fingerprint adds (measured)

The corpus carries each client's measured Akamai HTTP/2 fingerprint: the real
browser-engine fingerprints for the human and old-browser profiles, and the Go,
curl, Java, and httpx fingerprints for the libraries. Rerunning the scorer with the
h2 signal on (`TestHTTP2Signal`) isolates its contribution.

The careful scraper is the one case the header layer cannot touch: it is identical
to an old browser, so both sit at Suspect and you cannot act on one without acting
on the other. The h2 fingerprint breaks that tie.

| client | header layer alone | with HTTP/2 fingerprint |
|---|---|---|
| Safari <16.4 (old browser) | suspect | **suspect** (unchanged) |
| Firefox <90 (old browser) | suspect | **suspect** (unchanged) |
| Chrome <76 (old browser) | suspect | **suspect** (unchanged) |
| careful scraper, Go h2 (`a,m,p,s`) | suspect | **confirmed** |
| careful scraper, httpx (`HEADER_TABLE_SIZE 4096`) | suspect | **confirmed** |

Detection at the Confirmed (tarpit) threshold, where it matters:

| | careful scrapers to tarpit | old-browser false positives |
|---|---|---|
| header layer alone | 0/2 | 0/3 |
| with HTTP/2 fingerprint | **2/2** | **0/3** |

The h2 signal moves both careful scrapers to the tarpit and adds **zero** false
positives on old browsers, because an old browser carries a real browser h2
fingerprint while a Go or httpx scraper does not. Both tells fire: the Go client by
its `a,m,p,s` pseudo-header order (no browser leads with `:authority`), and the httpx
client by its bare `HEADER_TABLE_SIZE 4096` even though it copies Chrome's
pseudo-header order.

What it does **not** do: catch stealth headless browsers (a real browser engine whose
UA has been overridden to hide the `HeadlessChrome` token). They send a genuine
browser's h2 fingerprint, so under the h2 signal they stay at Pass, the same ceiling the
header layer hits. Only behavioural or device fingerprinting would separate those.

**Caveat.** A scraper can forge its h2 fingerprint too (curl-impersonate and
curl_cffi do). Forging a browser-grade h2 stack is far more work than copying
headers, so the signal raises the evasion cost sharply, but it is not a wall. That
is why it feeds the fusion score (a challenge, then a tarpit), not an outright block.

### 2.8 What the cloud/hosting-IP signal adds (orthogonal to this corpus)

The header corpus above fixes a single client IP, so it cannot measure a
network-layer signal; the cloud/hosting-IP signal (`hosting_ip`, optional) is
reported here rather than scored in the table. It adds a compounding point when a
browser-claiming request originates from a published cloud range (AWS, GCP,
DigitalOcean, Linode, 12,875 IPv4 + 3,411 IPv6 prefixes from the providers' own
feeds). A real person browses from a residential or mobile ISP; a scraper fleet runs
on cloud compute, so a Chrome User-Agent from an EC2 address is itself a mismatch.

Its honest ceiling is the same one §4 names for IP reputation generally:
**residential proxies defeat it.** Imperva's 2025 data attributes 21% of bot attacks
to residential proxies used specifically to beat this signal, and a large study found
78% of residential-IP bot sessions evaded conventional IP feeds. So it tilts the
cheap, datacenter-hosted case, nothing more: weight 1, below the challenge threshold
on its own (a legitimate cloud-VPN or corporate-gateway browser is not challenged),
compounding a browser-claimer that also trips a header or h2 tell toward Confirmed.
Off by default, and verified good bots are exempt (they are allowlisted before
scoring runs). It is the cheap network-layer tier the commercial stacks check first,
built from first-party ranges with no third-party dependency, and honestly scoped.

---

## 3. Signal-coverage matrix

Y = built-in · N = no · opt = optional · ~ = partial. Commercial effectiveness
figures are vendor self-reported and not independently audited.

| System | OSS/self-host | Classifier | TLS fp | HTTP/2 fp | Device/JS fp | Behavioural | Good-bot verify | PoW | Tarpit | Poison | Reputation |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Henbane** | **AGPL/yes** | weighted score+fusion | ~coarse | **~opt** (h2capture) | N | ~velocity | **rDNS+WBA+IP** | Y | **Y** | **Y** | Y (hosting+feed) |
| Anubis | MIT/yes | weight score | N | N | N | N | UA+CIDR+rDNS | Y | N | N | opt DNSBL |
| go-away | MIT/yes | CEL+fp | **JA3N/JA4** | ~ | ~ | N | IP ranges | opt | N | N | DNSBL |
| Nepenthes | MIT/yes | none | N | N | N | N | N | N | **Y** | **Y** | N |
| Iocaine | MIT/yes | per-req script | N | N | ~ | N | ~ | N | ~ | **Y** | ~ |
| CrowdSec | MIT/yes | behavioural+crowd | N | N | Y (1.8) | Y | Y | Y (1.8) | N | N | **Y** |
| OWASP CRS | Apache/yes | anomaly score | N | N | N | N | ~UA | N | N | N | N |
| Cloudflare | no/cloud | **ML 1-99** | **JA3+JA4** | **Y** | Y | Y | Y+WBA | N (AI Labyrinth) | **Y** | ~ | Y |
| DataDome/HUMAN/Kasada | no/cloud | **ML** | **Y** | **Y/~** | Y | Y | Y | ~/Y | N | N | Y |

On fingerprint depth / ML Henbane sits with the open-source field, below the
commercial systems. On good-bot verification, PoW, tarpit, poison, and federation
it is at or ahead of the open-source tools in this comparison. It is the only one here
pairing a full good-bot-verification triad with content poisoning (not a claim to
have surveyed every open-source project).

---

## 4. What each signal is worth (the evasion reality)

No single network-layer signal is a wall:

- **TLS JA3/JA4** is forged for one argument (`curl_cffi impersonate="chrome"`,
  uTLS), and JA3 is effectively obsolete (Chrome 110+/Firefox 114+ randomise
  extension order); JA4 is better but still non-unique (refs [1-5]).
- **HTTP/2 fingerprint** flags >95% of *simple* h2 clients but is reproduced by
  impersonation toolkits (ref [7]).
- **IP reputation / ASN** is defeated by residential proxies (85-99% success).
  Henbane's own `hosting_ip` signal (§2.8) sits exactly here: a real win against the
  cheap datacenter-hosted majority, nothing against the residential-proxy adversary,
  which is why it is a compounding point rather than a block.
- **Proof-of-work** taxes, it does not classify; a native solver clears thousands
  of Anubis sites for cents, and the cost lands on every low-end human device.
- **Headless real browsers** defeat header, TLS, and increasingly behavioural
  signals.
- The literature supports the direction without over-claiming: TLS/JA4 features
  classify *simple* bots at high accuracy in the lab (ref [9], AUC 0.998) but
  full-stack-emulation / impersonation evades the network layer (refs [5][9]);
  header/browser-dimension features are the *least* evasion-resistant and
  behavioural features the most (ref [8]). The broader multi-layer-fingerprinting
  practice (not ref [9], which is TLS-only) is to **fuse** layers and flag
  **cross-layer contradiction**; Henbane's consistency scorer is a small, cheap
  instance of that contradiction idea at the header layer. (These are paraphrases
  of the cited findings, not verbatim quotations.)

Real-world scale (ref [Imperva 2025]): automated traffic is ~51% of the web, bad
bots ~37%, and a large and growing share is "evasive" real-browser automation,
precisely the traffic the header layer can't touch.

---

## 5. Honest positioning

1. **Right league.** A weighted header/scoring classifier is the same class as
   Anubis's `WEIGH` engine and OWASP CRS's anomaly score; Anubis also has no
   TLS/HTTP-2 fingerprinting and its author calls PoW a placeholder. Henbane
   competes with the open-source gates, **not** Cloudflare/DataDome.
2. **Effective where it's cheap.** It reliably catches the plain HTTP-library
   scrapers that dominate volume and overwhelmed FOSS infrastructure.
3. **Honest ceiling + honest FP.** It cannot separate a careful scraper or a real
   headless browser from a human on headers, and it flags browsers older than
   ~2021-2023. Both are stated, measured, and mitigated, not hidden.
4. **Ahead of Anubis** on Web Bot Auth (an open issue there), the good-bot triad
   (so verified crawlers aren't poisoned, the mistake Nepenthes makes on
   purpose), metrics, and federation.
5. **Deception is the differentiator.** Because no header signal blocks evasive
   crawlers, the labyrinth + poison degrade exactly that adversary at lower
   collateral than taxing every human with PoW, and lower collateral than the
   documented old-browser blocking of Cloudflare/Anubis (refs [11-18]).

---

## 6. Threats to validity

- **Synthetic corpus.** These are *representative* shapes from verified defaults,
  not captured live traffic. Real distributions vary; a user can set a
  non-default client config. The corpus is small (23). Treat the numbers as
  illustrative of the *mechanism*, not population estimates.
- **Self-benchmark.** The same author wrote the corpus and the detector. The
  mitigations are using cited real defaults, including the failing cases, and an
  open harness anyone can extend. It is still not an independent audit.
- **The FP surface is a floor, not a ceiling.** More niche legitimate clients
  exist (SeaMonkey, K-Meleon, old WebViews, some feed readers) that this corpus
  doesn't enumerate; the real-world FPR on old browsers could be higher. IE 11,
  Pale Moon, and text browsers happen to *escape* this scorer only because their
  UAs lack a `Chrome/Firefox/Safari/Edg/OPR` token, a fragile accident, not a
  designed carve-out.
- **Base-rate numbers are a model.** The precision-at-prior table uses the
  corpus FPR (0.33), which is inflated by a corpus deliberately rich in edge
  browsers; a real deployment's edge-browser fraction is smaller, so real
  precision is better than the 1%-base-rate figure. The table's purpose is to show
  the *shape* of the collapse, not to predict a deployment's precision.
- **Version drift.** Client defaults change (Accept-Encoding `br`/`zstd` depend on
  installed codecs; UA strings and header sets evolve). Citations are pinned to
  versions in §7; re-verify before quoting.
- **Scorer-in-isolation.** The full engine adds the good-bot verifier (which
  rescues the flagged crawlers), denylists, velocity, and TLS-fp, so the
  deployed false-positive and detection behaviour differ from this isolated view.

---

## 7. References

**Verified client default headers** (primary source per client):
curl `lib/http.c` + manpage; wget `src/http.c`; requests `utils.py`; urllib3
`connection.py`/`util/request.py`; httpx `_client.py`; aiohttp `client_reqrep.py`;
CPython `http/client.py` (`Accept-Encoding: identity`, `Python-urllib`); Go
`net/http/request.go` + `transport.go` (`Go-http-client/1.1`, auto-gzip, h2 via
`DefaultTransport`); axios `lib/defaults`/`adapters/http.js`; got, node-fetch,
undici source; Java `HttpClient` (HTTP/2 default); OkHttp `BridgeInterceptor`;
Apache HttpClient 5 `HttpClientBuilder`; Scrapy `settings/default_settings.py`.

**Sec-Fetch / Fetch Metadata timeline:** W3C *Fetch Metadata Request Headers*
(w3.org/TR/fetch-metadata); MDN + caniuse per-header; Chrome 76 (web.dev);
Firefox 90 (Mozilla security blog, 2021-07-12); Safari 16.4 (WebKit blog;
WebKit bug 246508: Sec-Fetch-User deliberately not implemented).

**Bot base rates:** [Imperva 2025] Imperva/Thales *2025 Bad Bot Report* (automated
51%, bad bots 37%); Imperva 2024 (bad bots 32%); Cloudflare *Application Security
Report 2024* (bots 31.2%); DataDome *State of Bot & Agent Security 2026* (bad bots
15.4%, post-mitigation lower bound); Akamai SOTI 2024 (42%).

**Fingerprinting & detection literature:**
[1] Althouse, *TLS Fingerprinting with JA3/JA3S*, Salesforce Eng., 2017.
[2] `salesforce/ja3`, 2017.
[3] `FoxIO-LLC/ja4` (JA4+), 2023.
[4] Anderson & McGrew, *Accurate TLS Fingerprinting using Destination Context and Knowledge Bases*,
arXiv:2009.01939, 2020 (fingerprint ≠ identity).
[5] Frolov & Wustrow, *The use of TLS in Censorship Circumvention*, NDSS 2019 (uTLS).
[6] Anderson & McGrew, *TLS Beyond the Browser*, ACM IMC 2019.
[7] Segal & Shuster (Akamai), *Passive Fingerprinting of HTTP/2 Clients*, Black Hat
EU 2017 (the Akamai h2 fingerprint).
[8] Kadel et al., *BOTracle*, arXiv:2412.02266 / ESORICS 2024 Workshops
(behavioural vs header features).
[9] Jarad & Bicakci, *When Handshakes Tell the Truth: Detecting Web Bad Bots via
TLS Fingerprints*, arXiv:2602.09606, 2026 (JA4+CatBoost, AUC 0.998, a lab result;
contrast with base-rate limits).
[10] Axelsson, *The Base-Rate Fallacy and the Difficulty of Intrusion Detection*,
ACM TISSEC 3(3), 2000 (false-alarm rate is the limiting factor).

**Documented false-positive harm from aggressive bot walls:**
[11] Iaso, *Block AI scrapers with Anubis*, 2025 (text browsers / old machines
locked out). [12] Brockmeier, *Anubis…*, LWN, 2025-07-10. [13] Proven,
*Cloudflare's bot bouncer blocks weirdo browsers*, The Register, 2025-03-04 (Pale
Moon, Falkon, SeaMonkey, Firefox ESR). [14] Perry, *The Trouble with CloudFlare*,
Tor blog, 2016. [15] DeVault, *Please stop externalizing your costs…*, 2025.
[16] Venerandi, *FOSS infrastructure is under attack by AI companies*, LibreNews,
2025. [17] Read the Docs, *AI crawlers need to be more respectful*, 2024.
[18] Bort, *Open source devs are fighting AI crawlers…*, TechCrunch, 2025.

*Figures marked vendor-reported are not independently audited. Several facts here
corrected the first version of this study; see §1 iteration 1.*
