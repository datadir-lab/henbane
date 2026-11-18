<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/henbane-flower-dark.png">
    <img src="assets/logo/henbane-flower.png" alt="Henbane" width="150">
  </picture>
</p>

<h1 align="center">henbane</h1>

<p align="center">Self-hosted gateway that keeps abusive AI scrapers off your site without taxing real visitors</p>

<p align="center">
  <img alt="License: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-2f5233">
  <img alt="Go 1.27+" src="https://img.shields.io/badge/go-1.27%2B-2f5233">
  <img alt="Dependencies: stdlib + yaml" src="https://img.shields.io/badge/deps-stdlib%20%2B%20yaml-2f5233">
  <img alt="Status: pre-1.0" src="https://img.shields.io/badge/status-pre--1.0-8fae63">
</p>

---

Scrapers that train AI models now hit small sites thousands of times an hour. They ignore `robots.txt`, run up the hosting bill, and copy content wholesale.

Henbane sits in front of your site as a reverse proxy. It identifies hostile automated crawlers and, depending on how confident it is, either bans them or detains them in an endless maze of generated pages seeded with poison text.

The design point is restraint. Tools that make every visitor solve a proof-of-work puzzle also punish people on no-JS browsers, screen readers, and old devices. Henbane acts only on traffic that proves itself hostile, so a real reader passes through without noticing it is there.

> **Status: pre-1.0, under active development.** Everything documented here is built and tested: four serving form factors (reverse proxy, `net/http` middleware, Caddy module, nginx/Traefik sidecar), four poison strategies, the proof-of-work gate, the full classifier, Prometheus metrics, and federation. The embeddable Go API is v0 and may change before a tagged 1.0. Zero third-party runtime dependencies (standard library plus `gopkg.in/yaml.v3` for config).

## How it works

Every request is classified into a tier, and the tier picks an action.

| Tier | Trigger | Action | Response |
|---|---|---|---|
| `Pass` | normal traffic | Allow | proxied to your upstream |
| `Suspect` | spoofed browser UA (`pow.mode: suspect`), or `pow.mode: all` | **Challenge** | a proof-of-work interstitial, then passed through |
| `Confirmed` | tripped a honeypot trap | **Tarpit** | `200`, a labyrinth maze page with poison text, no ban |
| `Blocked` | on a denylist (IP or UA) | **Block** | `403`, plus a fail2ban ban line if configured |

The split is deliberate:

- A denylisted actor is banished (`403` and fail2ban).
- A honeypot-confirmed crawler is detained instead. The aim is to keep it crawling the maze and spending its own budget, so banning it would be counterproductive.

With `robots.serve` on, Henbane publishes a `/robots.txt` that `Disallow`s the honeypot trap. Well-behaved crawlers avoid it, so any client that fetches it is provably ignoring `robots.txt` and gets confirmed as a bad bot. Set `robots.ai_usage` and Henbane also emits machine-readable AI-usage preferences in both the IETF AIPREF (`Content-Usage`) and Cloudflare Content-Signals (`Content-signal`) syntaxes, the standard way to state what your content may be used for (training, live AI answers, search), in robots.txt and, for AIPREF, as a `Content-Usage` response header on every page. These are preferences, not enforcement, but a confirmed AI crawler that ignores them is a *provable* violator, not just a visitor.

Two optional suspicion signals feed the `Suspect` tier:

- **Proof-of-work** (`pow.mode: suspect`, or `all` for everyone). A challenged browser solves a small SHA-256 puzzle once, gets an anonymous IP-bound session token, and passes through until it expires. Off by default. Be clear-eyed: this is a speed-bump against low-effort scrapers, not a wall. A determined crawler solves it once per IP with a native solver (far faster than browser JavaScript) and then crawls freely for the token's lifetime, so the real deterrent is the labyrinth and poison a confirmed crawler gets, not the puzzle. Because only `Suspect` traffic is challenged, the puzzle never taxes an ordinary reader. See [proof-of-work honest limits](docs/design/2026-11-17-pow-honest-limits.md).
- **Request velocity** (`velocity.enabled`). Any client IP that exceeds `velocity.requests` within `velocity.window` is classified at `velocity.tier`. This is a weaker signal than a trap hit (shared NAT, CDNs, and asset-heavy pages all inflate a single IP's rate), so `tier: suspect` makes a fast client pay the recoverable PoW toll while `tier: confirmed` trips it into the tarpit. The counter sees every request including subresources, so set `requests` above a heavy human session or keep static assets off the proxied path. Off by default.

## Quick start

```bash
git clone https://github.com/datadir-lab/henbane
cd henbane
go build -o henbane ./cmd/henbane

# proxy a local app on :8081, listening on :8080
./henbane --upstream http://127.0.0.1:8081
```

Flags: `--upstream` (required), `--listen` (default `:8080`), `--config`. Flag values override the config file. The binary is static (`CGO_ENABLED=0`), and a distroless `Dockerfile` is included.

## Install

**Go:**

```bash
go install github.com/datadir-lab/henbane/cmd/henbane@latest
```

**Docker:**

```bash
docker pull ghcr.io/datadir-lab/henbane:latest
docker run -p 8080:8080 ghcr.io/datadir-lab/henbane --upstream http://host.docker.internal:3000
```

**Binaries:** download the archive for your platform from the
[latest release](https://github.com/datadir-lab/henbane/releases/latest), then verify it (see [Verifying releases](#verifying-releases)).

## Embed in your Go app

Henbane is also an embeddable `net/http` middleware. It runs the same engine the CLI runs, wrapping your own handlers instead of a reverse-proxy upstream:

```go
import "github.com/datadir-lab/henbane"

var cfg henbane.Config          // zero value = fully passive; set fields as needed
cfg.PoW.Mode = "all"            // e.g. challenge everyone
cfg.Poison.Strategy = "splice"

hb, err := henbane.New(cfg, henbane.WithLogger(logger))
if err != nil {
    log.Fatal(err)
}

mux.Handle("/", hb.Handler(app))           // net/http
// r.Use(hb.Handler)                        // chi / alice: Handler is func(http.Handler) http.Handler
adminMux.Handle("/metrics", hb.MetricsHandler())
```

- Allowed requests fall through to your handler. Suspect, confirmed, and blocked requests are challenged, tarpitted, or blocked first.
- Build **one** `*Henbane` and reuse it across routes. It holds the shared protection state.
- If you use [federation](#federation), call `hb.Start(ctx)` once with a context tied to your server's lifetime to run its background tasks (feed refresh, reporting). Cancelling the context stops them.
- The package is v0 and experimental. The API may change before a tagged 1.0.

### Caddy plugin

Henbane is also a [Caddy v2](https://caddyserver.com) HTTP handler module. It lives in its own Go module (`caddy/`) so Caddy's large dependency tree never touches the zero-dependency core. Build it into Caddy with [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/datadir-lab/henbane/caddy
# before the first tagged release, build against a local checkout:
# xcaddy build --with github.com/datadir-lab/henbane/caddy=./henbane/caddy
```

```caddyfile
example.com {
    henbane /etc/henbane.yaml   # same YAML the standalone binary reads
    reverse_proxy localhost:8081
}
```

Requests Henbane allows continue down the handler chain (to `reverse_proxy` here). The rest are challenged, tarpitted, or blocked first. With no config file the directive is passive.

### nginx / Traefik (ForwardAuth sidecar)

If you already run **nginx** or **Traefik**, you don't need to replace it. Run Henbane as an **auth sidecar**: your front proxy asks Henbane about each request, Henbane runs the full decision pipeline, and it answers `204` to let the request through or a non-`2xx` deny carrying the challenge page, maze, or `403`.

```bash
henbane --sidecar --config /etc/henbane.yaml   # same YAML; no upstream
```

Henbane reconstructs the original request from the forwarded headers (`X-Forwarded-Uri`/`X-Original-URI`, `X-Forwarded-Method`, `X-Forwarded-Host`, `X-Forwarded-For`), so the classifier sees the real path, method, host, and client IP.

- **Bind the sidecar to your internal network.** Only the front proxy should reach it, since those headers are trusted.
- Set `trusted_proxies` to your front proxy so the client IP is taken from `X-Forwarded-For`.
- **Traefik** forwards a non-`2xx` auth response straight to the client, so the challenge and maze render directly.
- **nginx** `auth_request` reads only the status, so the deny body is surfaced with an `error_page` recipe.

```yaml
http:
  middlewares:
    henbane:
      forwardAuth:
        address: "http://henbane:8080/auth"
        authResponseHeaders: ["X-Henbane-Action"]
```

Full copy-pasteable configs for both, including routing the proof-of-work verify path so the challenge can be solved, are in [`docs/deploy/sidecar.md`](docs/deploy/sidecar.md).

## Configuration

Zero-config works: a single `--upstream` passes all traffic through. For anything more, point `--config` at a YAML file. Every key below is one Henbane reads today; an unrecognised key is a startup error, not a silent no-op, so a typo in a security-relevant setting (say `enabld` for `enabled`) fails loud instead of quietly disabling the protection.

```yaml
# henbane.yaml
listen: ":8080"
upstream: "http://127.0.0.1:8081"

tls:                      # terminate TLS here to enable TLS fingerprinting
  cert: ""                # PEM cert file; empty = plain HTTP (TLS terminated upstream)
  key: ""                 # PEM key file

# Trust X-Forwarded-For only from these source ranges (your proxy or load balancer).
# Leave empty if henbane faces the internet directly, so the denylist cannot be spoofed.
trusted_proxies:
  - "10.0.0.0/8"

deny:
  cidrs:
    - "203.0.113.0/24"
  user_agents:            # case-insensitive substrings
    - "GPTBot"
    - "CCBot"
    - "ClaudeBot"
  tls_fingerprints:       # JA4 TLS fingerprints (see logs; requires tls.cert/key)
    - "de7fd8549b99c53c"

honeypot:
  enabled: true
  path: "/.well-known/hb-trap"   # link this invisibly from your pages
  flag_ttl: "1h"
  max_flagged: 100000

labyrinth:
  links_per_page: 15

poison:
  strategy: babble               # babble | splice | article | canary | none
  paragraphs_per_page: 3         # clamped to [0, 20]
  corpus_path: ""                # optional BYO corpus for babble, splice
  salt: ""                       # per-deployment; required for canary

pow:
  mode: off                      # off | suspect | all (challenge everyone)
  difficulty_bits: 20            # leading zero bits; clamped [8, 32]
  challenge_ttl: "5m"
  access_ttl: "1h"
  secret: ""                     # optional; random per start if empty

bomb:
  trigger: off                   # off | confirmed | blocked (serve a gzip bomb)
  decompressed_cap_mb: 64        # inflated-size cap; clamped [1, 1024]

robots:
  serve: false                   # if true, Henbane serves /robots.txt
  disallow:                      # extra paths to Disallow (the honeypot trap is auto-added)
    - "/private"
  ai_usage:                      # optional machine-readable AI-usage preferences
    train: false                 # no foundation-model training on this content
    ai_input: false              # no live AI input (RAG / answer engines)
    search: true                 # search indexing is fine

velocity:
  enabled: false                 # rate-based detector; off by default
  requests: 600                  # max requests per window per IP before firing
  window: "1m"                   # the fixed counting window
  tier: "suspect"                # suspect (PoW toll, needs pow) | confirmed (tarpit)
  max_tracked: 100000            # hard cap on tracked IPs (memory bound)

metrics:
  listen: ""                     # e.g. "127.0.0.1:9090"; empty = disabled.
                                 # Served on a SEPARATE, private listener, never
                                 # the same address as `listen`.

federation:
  feed_url: ""                   # consumer: remote denylist to pull (http/https); empty = off
  refresh: "1h"                  # how often to re-fetch the feed
  max_entries: 1000000           # hard cap on fetched prefixes
  report_url: ""                 # reporter: POST confirmed-bad detections here; empty = off
  report_token: ""               # optional bearer token for the report endpoint
  deployment_id: ""              # stable ID so the feed can require cross-reporter consensus

webbotauth:
  enabled: false                 # verify cryptographically-signed AI agents
  tier: "block"                  # suspect | confirmed | block; action for a verified agent
  directories:                   # agent key directories (https) to trust
    - "https://chatgpt.com"

verified_bots:
  enabled: false                 # allow reverse-DNS-verified search crawlers (Googlebot, Bingbot)
  spoof_tier: "off"              # off | suspect | confirmed | block; action for a UA-spoofer

sinks:
  fail2ban:
    enabled: true
    path: /var/log/henbane/ban.log
```

## Poison strategies

The maze's pages are filled by a pluggable `Poisoner`, selected by config:

- **`babble`** (default): an order-2 Markov chain over a small embedded public-domain corpus. Cheap to generate, maximizes crawler cost. A resource-draining tarpit.
- **`splice`**: recombines whole sentences drawn verbatim from the corpus. Each sentence is real text, so the output reads with near-real perplexity (the filter that catches `babble` and `article` keys on exactly that), while the scrambled sentence order destroys topical coherence. It trades local fluency for a shot at surviving the perplexity gauntlet (see the [research study](research/STUDY.md)).
- **`article`**: a context-free grammar producing fluent, Wikipedia-register prose about fictional entities with plausible-but-false facts. Coherent and lexically distinct per page.
- **`canary`**: `article` plus unique, trackable fabricated phrases coined from your `salt` with HMAC-SHA256. Stable for your deployment, unguessable without the salt, so a third party cannot predict, forge, or pre-filter them. Each phrase embeds a reference number that exists only on your pages, giving you an attribution marker you can later search for and verify with the [`henbane canary`](#provable-poison-canaries) tooling.
- **`none`**: links-only maze, no body text.

### Decompression bomb (optional, aggressive)

With `bomb.trigger: confirmed` (or `blocked`), a confirmed-hostile client that advertises `Accept-Encoding: gzip` is served a **gzip decompression bomb** instead of the maze: a tiny response that inflates (up to `decompressed_cap_mb`) into megabytes of compressible filler studded with poison. Cheap for you to send, expensive for a naive scraper to decompress and parse.

**It is off by default and deliberately narrow.** It fires only on a confirmed-hostile tier, only for a client that advertised gzip, and is size-capped and streamed. The collateral risk is real: a CDN, a cache, an accessibility tool, or a misidentified real browser that sent `Accept-Encoding: gzip` would also receive it. Enable it only when you accept that trade-off.

## Provable poison (canaries)

The `canary` strategy turns poison into evidence. Every phrase it plants (for example `Velthu Casmarvel 9017 standard`) is coined deterministically from your `salt` with HMAC-SHA256: stable for your deployment, identical across restarts, yet **cryptographically unguessable** without the salt. A third party cannot predict a canary to pre-filter it out, nor forge one to pollute your attribution.

The `henbane canary` subcommand is operator tooling. It never runs on the request path:

```console
# List your deployment's canary phrases (reads poison.salt, or pass -salt).
$ henbane canary list -config henbane.yaml
Velthu Casmarvel 9017 standard
Palthu Dradramar 6264 standard
…

# Attribute a surfaced answer: does it echo one of YOUR canaries?
$ pbpaste | henbane canary check -config henbane.yaml
ATTRIBUTED: found this deployment's canary "Velthu Casmarvel 9017 standard"
```

`check` exits 0 on a match and 1 otherwise, so it scripts cleanly. The match is cryptographic-strength attribution: because the phrases derive from your secret salt, a hit is strong evidence the text reached and reproduced *your* planted content, not another site's and not a guess.

### The opt-in probe

`henbane canary probe` automates the search against an AI endpoint you configure. For each canary it asks the endpoint about the coined *name only*, never the full phrase, and reports a **HIT** only if the response reproduces the full phrase **including the reference number that appears nowhere but on your pages.** Asking about the name alone is deliberate. If the probe sent the whole phrase, a model could echo it straight back from the prompt (a false positive); returning the specific planted number is only possible if the endpoint retrieved your content.

```yaml
canary:
  probe:
    endpoint: "https://your-ai-search.example/v1/answer"  # http(s); POSTed a JSON body
    auth_env: "CANARY_PROBE_TOKEN"   # env var → Authorization: Bearer <value> (never in config)
    body_field: "query"             # JSON field the question is sent as; default "query"
    query: 'What is the "{{canary}}" specification?'  # {{canary}} → the coined name
```

```console
$ CANARY_PROBE_TOKEN=… henbane canary probe -config henbane.yaml
  HIT    Velthu Casmarvel 9017 standard
  weak   Palthu Dradramar             (reference number 6264 surfaced; full phrase did not)
  -      Linvelsel Selrinsel
  1/16 canaries surfaced
```

**What a hit means, and what it does not.** A HIT proves the endpoint retrieved and reproduced your planted content: live **retrieval and repetition reach**. It does **not** prove your content entered any model's training set. That is unobservable from outside (see [Does this actually work?](#does-this-actually-work)). Honest caveats:

- The probe POSTs a single-field JSON body. That fits answer/search APIs but not chat-completion APIs with a nested `messages` array (use `list` plus a manual search there).
- Probing reveals a canary to the endpoint, so a hit on a first, cold run is cleaner evidence than repeated runs.
- Models hallucinate plausible numbers, so treat a lone `weak` line as a lead to corroborate, not a result.

## Observe mode

Aggressive bot detection has a false-positive cost (see [Effectiveness](#effectiveness); browsers older than roughly 2021 to 2023 can be flagged), so **start in observe mode**. Set `observe: true` and Henbane runs the full decision pipeline and records the verdict it *would* take (logged with `observe=true`, counted in `/metrics` by action and tier) while **serving every request normally**. Nothing is challenged, tarpitted, or blocked.

Watch your own traffic for a few days, confirm the would-be actions land on bots and not your users, tune `scoring` thresholds and denylists, then remove `observe` to enforce. It applies across every form factor (reverse proxy, middleware, Caddy, sidecar).

```yaml
observe: true
```

## Effectiveness

Henbane is benchmarked, and the numbers are honest, including where it falls short. Two reproducible studies back the claims (`go test ./research/...`).

**Detection** ([`research/classifier-benchmark.md`](research/classifier-benchmark.md), a deliberately critical study grounded in each client's verified default headers):

- It catches **8/8** representative HTTP-library scrapers wearing a spoofed browser User-Agent (Go, Python requests/httpx, curl, wget, axios, Java HttpClient, Scrapy). A User-Agent blocklist catches **0/8** of them.
- The signal doing most of that work, a missing `Sec-Fetch-Site` header, also flags legitimate browsers released before Fetch Metadata shipped (Chrome <76, Firefox <90, Safari <16.4). At a 1% bot base rate, raw precision collapses toward **0.03** (the base-rate fallacy). The balanced-corpus F1 of 1.00 hides this.
- That is why the score drives a **challenge, not a block**. The good-bot verifier rescues real crawlers, and it is one soft signal in a fusion engine.
- At the header layer, a careful scraper that omits only `Sec-Fetch` is identical to an old Safari. The **HTTP/2 fingerprint** (optional `h2capture` module) is the non-header signal that separates them: a Go or httpx h2 shape is not a real browser's.
- Default headless Chrome is caught: it keeps a self-identifying `HeadlessChrome` User-Agent that no real browser sends. **Stealth** headless (a real browser engine whose UA has been overridden) is the remaining gap (recall 0.85 once headless counts as positive). It carries a genuine browser's UA, TLS, *and* HTTP/2 fingerprint, so no layer here catches it. Only behavioural/device fingerprinting would, which is future work.

**Cost** ([`research/benchmarks.md`](research/benchmarks.md)):

- The full classifier (denylists, honeypot, velocity, both good-bot verifiers, scoring) decides a request in microsecond-scale time (~3 µs on one commodity amd64 laptop, ~5 to 9 µs single-core) with 5 allocations. Negligible in any latency budget.
- Poison generates far faster than a crawler can fetch and parse it: splice ~200 MB/s, the other strategies ~15 to 25 MB/s on that host.
- The optional gzip bomb imposes a ~141x download-and-decompress amplification (74 KB to 10 MB; 7.6 MB to 1 GB).
- Absolute times vary 2 to 3x by hardware and load. Only the bomb ratio and the allocation counts are hardware-independent.

The shape of it: a negligible operator cost, an asymmetric crawler cost, and a classifier that is honestly strong against the cheap-scraper majority and honestly blind to evasive headless traffic. The labyrinth and poison are the real deterrent, not the classifier. For how this sits against Anubis, go-away, Cloudflare, and DataDome, see the [competitive comparison](research/classifier-benchmark.md#3-signal-coverage-matrix).

## Does this actually work?

Short version: it reliably wastes crawler resources. It does **not**, and cannot be shown to, "poison an AI model." The honest framing matters, so here it is in full.

- **Reaching the crawlers is easy.** The major training crawlers (GPTBot, ClaudeBot, CCBot, Bytespider, Amazonbot, PerplexityBot, Meta-ExternalAgent) fetch raw HTML and do not execute JavaScript, so a static maze catches them without any client-side tricks.
- **Reaching a _training set_ is hard.** Real dataset pipelines (C4, Gopher, CCNet, RefinedWeb, Dolma, FineWeb, Nemotron-CC) stack aggressive filters: boilerplate removal, quality heuristics, badword and blocklists, perplexity filtering (which discards the large majority of Common Crawl as statistically "weird"), and near-duplicate deduplication. Low-fluency Markov babble is close to a worst case for these filters. The `article` and `canary` strategies look more like ordinary prose, but we make **no claim** that any of it survives into a model.
- **One site is a drop in the ocean.** A site of a few thousand pages is on the order of one part in ten million of a frontier training corpus before filtering. For a single operator this is a symbolic, deterrent measure. Where it could plausibly matter is niche topics a site dominates, and many sites acting together.
- **Model impact is unobservable from outside.** No operator can see another party's training set or weights. Every rigorous data-poisoning result in the literature relied on privileged, white-box, or guaranteed-insertion access. That is a research setup, not "I served some pages and a crawler may have fetched them."
- **What we will _not_ do:** cite the "250 documents can backdoor an LLM" result or the "model collapse" work as evidence that this degrades frontier models. Neither supports that claim. The first needs a guaranteed-insertion shared trigger; the second describes recursive multi-generation training.

What is honestly measurable is the resource cost you impose: bytes served, crawl depth, dwell time, bot-versus-real ratio (see [Effectiveness](#effectiveness) for the measured figures). The opt-in [`henbane canary probe`](#provable-poison-canaries) also measures whether planted `canary` phrases surface in a live AI-search endpoint you point it at, which is live retrieval reach, not poisoned training. Henbane is worth running for the resource-cost story alone.

**The evidence behind the claims above.** The points are not hand-waving; here is the literature, including the results people most often misquote in this debate, and why each one stops short of "a single site poisons a frontier model":

- Carlini et al., *Poisoning Web-Scale Training Datasets Is Practical* (IEEE S&P 2024, arXiv:2302.10149). Shows web poisoning is feasible, but through **guaranteed-insertion** vectors (buying expired dataset domains, Wikipedia-snapshot frontrunning), not "serve pages and hope a crawler keeps them."
- Zhang et al., *Persistent Pre-training Poisoning of LLMs* (ICLR 2025, arXiv:2410.13722). Finds 0.1% of pre-training data can make an effect persist through post-training, but with **controlled insertion** and a **targeted** objective, measured white-box on models the authors trained.
- Anthropic, UK AI Security Institute, and the Alan Turing Institute, *Poisoning Attacks on LLMs Require a Near-Constant Number of Poison Samples* (2025, arXiv:2510.07192). The "~250 documents" result: near-constant across 600M to 13B models, but a **narrow denial-of-service backdoor** keyed to a chosen trigger (`<SUDO>`), with guaranteed insertion. The authors themselves call it "unlikely to pose significant risks in frontier models." It is not evidence that untargeted maze text degrades a model.
- Shumailov et al., *AI Models Collapse When Trained on Recursively Generated Data* (Nature, 2024). "Model collapse" is a **recursive, multi-generation** phenomenon (a model trained on its own output, repeatedly), not something one poisoned site causes in a single training run.

The through-line: every rigorous poisoning result depends on insertion access, a chosen trigger, or recursion that a single deterrent deployment does not have. Henbane's honest claim is the resource cost and the canary's retrieval reach, nothing more.

## Acceptable use and content liability

Everything Henbane **ships** is fully fictional: the embedded corpus and the `article` and `canary` grammars invent entities, places, and facts, and contain no real people or organizations. That is a deliberate policy.

If you point `corpus_path` at your own text, **you** choose and own that content. Supplying material that makes false statements about real, identifiable people or organizations is your legal responsibility, not the project's. Serving fabricated content to a misidentified legitimate crawler can also constitute cloaking. Henbane serves poison only to clients at the `Confirmed` tier, which is reached two ways: a honeypot trap hit (an airtight, provable `robots.txt` violation) or, when you enable `scoring` or `velocity`, a client that accumulated enough bot-signals to cross the `Confirmed` threshold. The scoring thresholds are tuned so a legitimate client reaches at most `Suspect` (a recoverable challenge), never `Confirmed`, so the false-positive surface for poison is near zero in practice. The honeypot remains the cleanest trigger because the violation is unambiguous; if you want fabricated content served *only* on that airtight basis, leave `scoring`/`velocity` confirm-tier off. A misconfigured honeypot path is on the operator.

## fail2ban

When the fail2ban sink is enabled, a blocked request appends one greppable line:

```
henbane: action=ban ip=203.0.113.9 tier=blocked reason=denylist_ua ua="GPTBot/1.1"
```

The shipped filter (`deploy/fail2ban/henbane.conf`) and jail snippet (`deploy/fail2ban/jail.local`) match it, so you can ban at the firewall without writing a regex. The User-Agent is quoted, so a crawler cannot inject a fake ban line through its header.

## Metrics

Set `metrics.listen` and Henbane exposes Prometheus-format counters, hand-formatted with no client library:

```
# TYPE henbane_requests_total counter
henbane_requests_total{action="tarpit",tier="confirmed"} 4812
henbane_requests_total{action="allow",tier="pass"} 37190
# TYPE henbane_signals_total counter
henbane_signals_total{signal="honeypot"} 61
```

This is where the tarpit's value becomes visible. The `allow` count versus the `challenge`/`tarpit`/`block` counts is your human-to-bot ratio, and every `tarpit` is a maze page you made a crawler fetch instead of real content.

- The counters are aggregate, with **no per-IP or per-path labels**, so they carry operational data, not user data.
- They are served on a **separate listener** (`metrics.listen` must differ from `listen`). Bind it to a private interface so the numbers never ride the public proxy path.
- Off by default.

## Federation

A bot caught at one site should be known at the next. Two opt-in halves, both off by default:

**Consume** (`federation.feed_url`): Henbane pulls a shared bad-IP blocklist on an interval and blocks listed clients. Point it at any threat feed (a public bad-bot list, your own, or a future Poison Garden). The feed is operator-chosen but treated as untrusted input:

- Entries are parsed strictly and capped.
- Over-broad prefixes are rejected, so a compromised feed cannot inject `0.0.0.0/0` to block everyone.
- The body is bounded, and a failed fetch **keeps the last good list**. It never fails to block-all or allow-all.

**Report** (`federation.report_url`): Henbane contributes its own confirmed detections back. It is async and bounded (it never blocks or back-pressures the request path), and privacy-minimised by construction:

- **Only `Confirmed`/`Blocked` tiers** are reported, never a human's `Pass`/`Suspect` IP.
- Only `{ip, signal, tier, timestamp}` is sent: no logs, User-Agent, path, or payload.
- The legal basis is GDPR **legitimate interest** (Recital 49, network and information security); see the [Legitimate Interests Assessment](docs/legitimate-interest-assessment.md).
- IPs are sent raw rather than hashed, because a hashed IP is still personal data and cannot be matched across reporters for the consensus that curates the feed.

## Verified search crawlers (reverse DNS)

Set `verified_bots.enabled` and Henbane verifies Googlebot, Bingbot, and Applebot by **forward-confirmed reverse DNS**: a genuine Googlebot IP reverse-resolves to `*.googlebot.com`, and that hostname forward-resolves back to the same IP.

- A **verified** crawler is *allowed*. It bypasses the suspicion pipeline, so you don't tarpit or poison the search crawlers you want, and it isn't caught by `pow.mode: all`. Anything a spoofer sets in its User-Agent is irrelevant; only DNS decides.
- A client whose User-Agent *claims* to be a crawler but can't be verified is a **spoofer** (a common evasion), handled at `verified_bots.spoof_tier` (`off` by default; set `block`/`confirmed`/`suspect` to act on it).
- DNS lookups run in the **background**, never on the request path. An IP gets "no opinion" until it resolves, so a flood of crawler-UA requests can't stall the server.
- The built-in crawler list (and their domains) is overridable via `verified_bots.crawlers`.

## Verified AI crawlers (published IP ranges)

The major AI crawlers (OpenAI's **GPTBot**, **ChatGPT-User**, and **OAI-SearchBot**; Anthropic's **ClaudeBot** family; **PerplexityBot**) expose no reverse DNS, so FCrDNS can't confirm them. Instead they *publish the IP ranges* their requests come from. Set `verified_ai_crawlers.enabled` and Henbane confirms each by checking the client IP against that crawler's published CIDRs:

- A **verified** AI crawler is *allowed*, so you don't poison the AI crawlers you want indexing you.
- A client that claims one from an IP **outside** its ranges is a **spoofer**, acted on at `verified_ai_crawlers.spoof_tier` (`off` by default).
- The check is a pure in-memory lookup, with no request-path I/O.

The ranges are **bundled** from each vendor's own first-party feed (never a third-party aggregator) and refreshed with `go generate ./internal/detect/crawlerips/...`. This completes three identity checks: reverse DNS for search engines, cryptographic signatures for agents that sign, and published ranges for the AI crawlers that do neither.

## Verified AI agents (Web Bot Auth)

A User-Agent is a guess; a cryptographic signature is proof. [Web Bot Auth](https://blog.cloudflare.com/signed-agents/) (RFC 9421 HTTP Message Signatures plus a published key directory) lets an agent *prove* its identity with an Ed25519 signature. OpenAI's ChatGPT agent, DuckDuckGo, and others already sign their traffic.

Set `webbotauth.enabled`, list the agent key `directories` you recognise, and Henbane verifies each signature against those directories' keys and applies `webbotauth.tier` to a **verified** agent. You act on a proven identity, not a spoofable header.

- The action is yours: `block` a verified AI crawler (now that it can't hide behind a fake UA), `confirmed` to feed it the tarpit and poison, or `suspect` to challenge it.
- Keys are fetched from the configured directories at startup (restart to refresh). Ed25519 only, matching the live ecosystem.
- The verifier is **interoperability-tested against Cloudflare's reference signer**: it accepts a real reference-signed request and rejects tampered or expired ones.
- A verification failure is always treated as "not a verified agent", never as a trusted one.

## TLS fingerprinting

When Henbane terminates TLS itself (set `tls.cert`/`tls.key`), it fingerprints each client's TLS handshake as a **JA4** string, the industry-standard format. JA4 needs the exact list of TLS extensions, which Go's standard library hides, so the capture listener buffers the opening ClientHello and recovers them; everything else (ciphers, ALPN, signature schemes, versions) comes from what Go exposes, GREASE filtered out. Automated stacks (Go's `net/http`, Python, curl) present a different JA4 than real browsers, so it is a signal that survives a client lying in its User-Agent.

- The fingerprint appears in the decision log as `tls_fp`, a JA4 string like `t13d1516h2_8daaf6152771_e5627efa2ab1`. Because it is standard JA4, you can list fingerprints you confirm are bots, or paste JA4 values from a threat feed, in `deny.tls_fingerprints` for a `403`, like the IP and UA denylists.
- JA4 is shared by every client on the same TLS library, and is forgeable by a dedicated impersonation toolkit (uTLS, curl-impersonate), so it feeds the fusion score and should be listed only when you have confirmed it, exactly as with CIDR and UA denylists.
- It is empty when a proxy or CDN terminates TLS in front of Henbane; this is a direct-exposure feature. If a ClientHello cannot be parsed (a fragmented or malformed record), Henbane falls back to a coarse GREASE-filtered hash, so a fingerprint is always present.

## HTTP/2 fingerprinting (optional module)

The strongest anti-spoofing signal is the **HTTP/2 fingerprint**: the Akamai-style summary of the `SETTINGS`, connection `WINDOW_UPDATE`, `PRIORITY` frames, and pseudo-header order a client emits when it opens an h2 connection. These come from deep in a client's HTTP/2 engine, not from request-level options, so a scraper cannot match a browser's h2 fingerprint without replacing its whole transport. It is the layer modern anti-bot stacks check below JA4.

Reading the raw h2 frames needs a real HTTP/2 framer (`golang.org/x/net/http2`), which the zero-dependency core must not import. So capture lives in a **separate optional module**, `h2capture/` (the same pattern as the Caddy plugin, so its dependency never touches the core). Enable it on your server in one line when you embed Henbane:

```go
srv := &http.Server{Handler: hb.Handler(mux), TLSConfig: tlsCfg}
h2capture.Enable(srv)   // adds h2 fingerprint capture; HTTP/1.1 is served untouched
srv.ListenAndServeTLS(cert, key)
```

Not embedding Henbane? The same module ships a prebuilt reverse proxy, `henbane-h2`, that runs the ordinary config and engine but terminates TLS and captures both the HTTP/2 **and** TLS fingerprints. It needs `tls.cert`/`tls.key` set, since direct TLS termination is required to read the client's h2 frames:

```bash
henbane-h2 --config henbane.yaml   # same YAML; adds h2 fingerprinting
```

With it wired, a request wearing a browser `User-Agent` whose h2 fingerprint no browser would produce adds to its score:

- Go's `a,m,p,s` pseudo-header order (no browser leads with `:authority`).
- curl's and Java's `m,s,a,p`.
- The Python-`h2` library's tell-tale `HEADER_TABLE_SIZE 4096`, which httpx and Scrapy send even while copying Chrome's pseudo-header order.

This cracks the one case headers cannot: a careful scraper that omits only `Sec-Fetch` is otherwise header-identical to an old browser. Like every scorer signal it only raises suspicion (a challenge, not a block), and it is inert unless capture is wired and Henbane terminates the client's h2 connection directly (empty behind a CDN). Details and the measured fingerprint dataset are in [`docs/design/2026-11-16-h2-fingerprint.md`](docs/design/2026-11-16-h2-fingerprint.md).

## Device fingerprinting (optional, opt-in surveillance build)

The core **deliberately does not fingerprint real visitors**: a tool built to frustrate surveillance of readers should not surveil them to catch bots. But that leaves one adversary the core cannot touch, a real headful browser driven at human pace behind a residential IP, which presents a genuine UA, TLS, and HTTP/2 fingerprint. The only thing that unmasks it is in-client device and behavioural fingerprinting.

For operators who accept that tradeoff, the separate [`jsprobe`](jsprobe/) module and the `henbane-surveil` binary add it, kept out of the core so a core build is provably incapable of it. It challenges a `Suspect` client with a JavaScript probe instead of the proof-of-work puzzle, and issues a pass only to a browser that looks human:

```bash
henbane-surveil --config henbane.yaml --jsprobe-tier device
```

Three tiers, each including the ones before: `passive` (automation tells on load, no interaction, nothing user-identifying: `navigator.webdriver`, a software WebGL renderer), `behavioural` (requires human-like input before passing), and `device` (a canvas/WebGL device fingerprint you can denylist). It probes only already-`Suspect` clients (set `pow.mode: suspect`), so an unflagged reader is never fingerprinted. **Be honest about the ceiling:** the probe signals are *client-reported*, so unlike the server-observed TLS and HTTP/2 fingerprints they are forgeable, a bot can POST a clean report (even `{}`) and pass. It catches automation that honestly runs the probe (default and lightly-stealthed headless), not a client that chooses to lie, and it spends the core's anti-surveillance posture to do it. It is off unless you build and run it. See [`docs/design/2026-11-17-jsprobe-surveillance.md`](docs/design/2026-11-17-jsprobe-surveillance.md).

## Scoring (signal fusion)

Most of the signals above are strong on their own, but the tell-tale of a modern scraper is *inconsistency*: a request that claims to be Chrome yet doesn't behave like Chrome. Spoofing a `User-Agent` is one line of code; reproducing a real browser's whole request shape is not. Enable `scoring` and Henbane stops treating signals as independent tripwires and starts **accumulating** them:

```yaml
pow: { mode: suspect }
scoring:
  enabled: true
  suspect_threshold: 2   # score ≥ this → challenge
  confirm_threshold: 4   # score ≥ this → tarpit + poison
```

Each thing a browser-claiming client omits (`Sec-Fetch-Site` metadata, an `Accept` header, a language, a modern `Accept-Encoding`, HTTP/2) adds weighted points. One miss is only worth a brief challenge; several **compound** into a confident `Confirmed`, so a stock HTTP client wearing a Chrome `User-Agent` lands in the labyrinth while a real browser sails through. Every piece of evidence is recorded in the decision log even when it doesn't escalate, so you can see *why* a client was judged. Definitive signals (denylists, honeypot) and verified good bots still win outright; scoring only ever *raises* suspicion, never lowers it.

**Optional cloud/hosting-IP signal.** Real people browse from residential and mobile ISPs; scraper fleets run on cloud compute. Enable `hosting_ip` and a browser-claiming request arriving from a published cloud-provider range (AWS, GCP, DigitalOcean, Linode) adds a compounding point:

```yaml
hosting_ip:
  enabled: true   # requires scoring; off by default
  weight: 1       # 0 => default 1
```

It is deliberately weak (one point, so a legitimate cloud-VPN user is not challenged on its own) and off by default, because a thin legitimate population (corporate web gateways, cloud VPNs) browses from these ranges too. It catches the cheap, datacenter-hosted majority; a scraper on a residential proxy evades it, the documented ceiling. Verified good bots are exempt. Refresh the bundled ranges with `go generate ./internal/detect/hostingip/...`. Details in [`docs/design/2026-11-17-hosting-ip-signal.md`](docs/design/2026-11-17-hosting-ip-signal.md).

> **HTTP/2 note.** The "HTTP/2" row above is the zero-dep protocol signal (did the client negotiate HTTP/2 at all?). The far stronger **Akamai h2 frame fingerprint** ships in the optional `h2capture/` module; see [HTTP/2 fingerprinting](#http2-fingerprinting-optional-module).

## Dependencies

Henbane is Go, stdlib-first by policy. The only third-party runtime import is `gopkg.in/yaml.v3` for config. A CI guard fails the build if anything outside that allowlist appears in `go.mod`. A tool that fights surveillance should not become a supply-chain risk of its own.

## Roadmap

Each item is an end-to-end, tested slice. Checked items ship in the current build.

- [x] Reverse-proxy skeleton with a JSON event log
- [x] Operator denylist (IP and UA) to `403`, with a fail2ban line
- [x] Honeypot tripwire that marks a client Confirmed
- [x] Labyrinth: an endless tree of generated links that wastes crawl budget
- [x] Poison: babble, splice, article, and canary generators fill the maze
- [x] Proof-of-work challenge gate: SHA-256 solver in a Web Worker (off-thread, flat-out), HMAC session token, themeable page, no-JS fallback
- [x] Browser-hint and request-rate (velocity) suspicion signals
- [x] JA4 TLS client fingerprinting (logged as `tls_fp`; `deny.tls_fingerprints`)
- [x] Scoring / signal fusion: weak signals accumulate into a confident verdict (`scoring`), with browser-consistency (header and HTTP-version) checks
- [x] HTTP/2 Akamai frame fingerprint: optional `h2capture/` module (keeps the zero-dep core clean), feeds browser-consistency scoring
- [x] Verified good bots: Web Bot Auth (RFC 9421 signed agents) plus reverse-DNS search crawlers (Googlebot/Bingbot), with spoofer detection
- [x] Verified AI crawlers by published IP range (GPTBot/ChatGPT-User/OAI-SearchBot, ClaudeBot family, PerplexityBot), with spoofer detection
- [x] Observe (dry-run) mode: record would-be verdicts without acting, for safe rollout and tuning (`observe: true`)
- [x] Prometheus `/metrics` endpoint on a separate private listener
- [x] `net/http` middleware form factor (`henbane.New` / `hb.Handler`, v0)
- [x] Caddy module (`caddy/`, build with xcaddy)
- [x] nginx / Traefik support via a ForwardAuth / auth_request sidecar (`--sidecar`)
- [x] Federation: pull a shared bad-IP denylist feed, and report your own confirmed detections back

## Build and test

```bash
go build ./...
go test ./...
```

## Verifying releases

Every release ships a syft SBOM, a cosign keyless signature, and SLSA L3 provenance.

Verify the checksums signature (binaries):

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/datadir-lab/henbane/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Verify binary provenance (SLSA):

```bash
slsa-verifier verify-artifact henbane_<ver>_<os>_<arch>.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/datadir-lab/henbane
```

Verify the image signature and provenance:

```bash
cosign verify ghcr.io/datadir-lab/henbane:<ver> \
  --certificate-identity-regexp '^https://github.com/datadir-lab/henbane/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify-attestation ghcr.io/datadir-lab/henbane:<ver> \
  --type spdxjson \
  --certificate-identity-regexp '^https://github.com/datadir-lab/henbane/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

slsa-verifier verify-image ghcr.io/datadir-lab/henbane:<ver> \
  --source-uri github.com/datadir-lab/henbane
```

## Design and brand

The full design, including the ports-and-adapters layout, the decision contract, and the event schema, lives in [`docs/design/2026-11-13-henbane-design.md`](docs/design/2026-11-13-henbane-design.md). Honeypot setup guidance is in [`deploy/honeypot/`](deploy/honeypot/README.md). Brand and logo assets, with the WCAG-audited palette, are in [`assets/logo/`](assets/logo/README.md).

## License

Henbane is free software under the **GNU AGPL-3.0**. See [LICENSE](LICENSE).
Copyright © 2026 datadir s. r. o.

The AGPL is deliberate: run a modified Henbane as a network service and you must share your changes. The open gateway stays a commons. A commercial control plane (dashboard, analytics, federation) is offered separately.
