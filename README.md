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
  <img alt="Go 1.26+" src="https://img.shields.io/badge/go-1.26%2B-2f5233">
  <img alt="Dependencies: stdlib + yaml" src="https://img.shields.io/badge/deps-stdlib%20%2B%20yaml-2f5233">
  <img alt="Status: early development" src="https://img.shields.io/badge/status-early%20development-8fae63">
</p>

---

Scrapers that train AI models now hit small sites thousands of times an hour. They ignore `robots.txt`, run up the hosting bill, and copy content wholesale. Henbane sits in front of your site as a reverse proxy, identifies hostile automated crawlers, and depending on how confident it is either bans them or detains them in an endless maze of generated pages seeded with poison text.

The design point is restraint. Tools that make every visitor solve a proof-of-work puzzle also punish people on no-JS browsers, screen readers, and old devices. Henbane acts only on traffic that proves itself hostile, so a real reader passes through without noticing it is there.

> **Status: early, under active development.** Built and tested today: the reverse proxy, IP and User-Agent denylists, a honeypot trap detector, the labyrinth maze, three poison generators, and a proof-of-work challenge gate. Prometheus metrics and the middleware and Caddy form factors are planned, not yet built. Zero third-party runtime dependencies (standard library only, plus `gopkg.in/yaml.v3` for config). Not production ready.

## How it works

Every request is classified into a tier, and the tier picks an action.

| Tier | Trigger | Action | Response |
|---|---|---|---|
| `Pass` | normal traffic | Allow | proxied to your upstream |
| `Suspect` | spoofed browser UA (`pow.mode: suspect`), or `pow.mode: all` | **Challenge** | a proof-of-work interstitial, then passed through |
| `Confirmed` | tripped a honeypot trap | **Tarpit** | `200`, a labyrinth maze page with poison text, no ban |
| `Blocked` | on a denylist (IP or UA) | **Block** | `403`, plus a fail2ban ban line if configured |

The split is deliberate. A denylisted actor is banished (403 and fail2ban). A honeypot-confirmed crawler is detained instead: the aim is to keep it crawling the maze and spending its own budget, so banning it would be counterproductive. If `robots.serve` is on, Henbane publishes a `/robots.txt` that `Disallow`s the honeypot trap: well-behaved crawlers avoid it, so any client that fetches it is provably ignoring `robots.txt` — and gets confirmed as a bad bot.

A proof-of-work tier challenges suspicious clients — or everyone, with `pow.mode: all`. The browser solves a small puzzle once, is remembered by an anonymous session cookie, and passes through; a crawler reading a million pages pays it a million times. It is off by default.

A request-velocity signal classifies any client IP that exceeds `velocity.requests` within `velocity.window`. The counter is keyed on the resolved client IP and hard-bounded in memory. Because it is a weaker signal than a trap hit — shared NAT, CDNs, and asset-heavy pages all inflate a single IP's rate — the response is the operator's choice: `tier: suspect` makes a fast client pay the proof-of-work toll (recoverable for a real browser), while `tier: confirmed` trips it straight into the tarpit. Note the counter sees *every* request including subresources, so tune `requests` above a heavy human session or keep static assets off the proxied path. Off by default.

## Quick start

```bash
git clone https://github.com/datadir-lab/henbane
cd henbane
go build -o henbane ./cmd/henbane

# proxy a local app on :8081, listening on :8080
./henbane --upstream http://127.0.0.1:8081
```

Flags: `--upstream` (required), `--listen` (default `:8080`), `--config`. Flag values override the config file. The binary is static (`CGO_ENABLED=0`); a distroless `Dockerfile` is included.

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
[latest release](https://github.com/datadir-lab/henbane/releases/latest), then verify it (below).

## Embed in your Go app

Henbane is also an embeddable `net/http` middleware — the same engine the CLI runs, wrapping your own handlers instead of a reverse-proxy upstream:

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
// r.Use(hb.Handler)                        // chi / alice — Handler is func(http.Handler) http.Handler
adminMux.Handle("/metrics", hb.MetricsHandler())
```

Allowed requests fall through to your handler; suspect/confirmed/blocked requests are challenged, tarpitted, or blocked first. Build **one** `*Henbane` and reuse it across routes — it holds the shared protection state. If you configure [federation](#federation), call `hb.Start(ctx)` once with a context tied to your server's lifetime to activate its background tasks (feed refresh + reporting); cancelling the context stops them. The package is **v0/experimental** (the API may change before a tagged 1.0).

### Caddy plugin

Henbane is also a [Caddy v2](https://caddyserver.com) HTTP handler module, in its own Go module (`caddy/`) so Caddy's large dependency tree never touches the zero-dependency core. Build it into Caddy with [xcaddy](https://github.com/caddyserver/xcaddy):

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

Requests Henbane allows continue down the handler chain (to `reverse_proxy` here); the rest are challenged, tarpitted, or blocked first. With no config file the directive is passive.

### nginx / Traefik (ForwardAuth sidecar)

If you already run **nginx** or **Traefik**, you don't need to replace it. Run Henbane as an **auth sidecar**: your front proxy asks Henbane about each request, Henbane runs the full decision pipeline, and answers `204` to let the request through or a non-`2xx` deny carrying the challenge page / maze / `403`.

```bash
henbane --sidecar --config /etc/henbane.yaml   # same YAML; no upstream
```

Henbane reconstructs the original request from the forwarded headers (`X-Forwarded-Uri`/`X-Original-URI`, `X-Forwarded-Method`, `X-Forwarded-Host`, `X-Forwarded-For`), so the classifier sees the real path, method, host, and client IP. **Bind the sidecar to your internal network** — only the front proxy should reach it, since those headers are trusted. Set `trusted_proxies` to your front proxy so the client IP is taken from `X-Forwarded-For`.

**Traefik** forwards a non-`2xx` auth response straight to the client, so the challenge and maze render directly:

```yaml
http:
  middlewares:
    henbane:
      forwardAuth:
        address: "http://henbane:8080/auth"
        authResponseHeaders: ["X-Henbane-Action"]
```

**nginx** `auth_request` reads only the status, so the deny *body* is surfaced with an `error_page` recipe. Full, copy-pasteable configs for both — including routing the proof-of-work verify path so the challenge can be solved — are in [`docs/deploy/sidecar.md`](docs/deploy/sidecar.md).

## Configuration

Zero-config works: a single `--upstream` passes all traffic through. For anything more, point `--config` at a YAML file. Every key below is one henbane reads today.

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
  tls_fingerprints:       # coarse TLS fingerprints (see logs; requires tls.cert/key)
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

velocity:
  enabled: false                 # rate-based detector; off by default
  requests: 600                  # max requests per window per IP before firing
  window: "1m"                   # the fixed counting window
  tier: "suspect"                # suspect (PoW toll, needs pow) | confirmed (tarpit)
  max_tracked: 100000            # hard cap on tracked IPs (memory bound)

metrics:
  listen: ""                     # e.g. "127.0.0.1:9090"; empty = disabled.
                                 # Served on a SEPARATE, private listener — never
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
  tier: "block"                  # suspect | confirmed | block — action for a verified agent
  directories:                   # agent key directories (https) to trust
    - "https://chatgpt.com"

verified_bots:
  enabled: false                 # allow reverse-DNS-verified search crawlers (Googlebot, Bingbot)
  spoof_tier: "off"              # off | suspect | confirmed | block — action for a UA-spoofer

sinks:
  fail2ban:
    enabled: true
    path: /var/log/henbane/ban.log
```

## Poison strategies

The maze's pages are filled by a pluggable `Poisoner`, selected by config:

- **`babble`** (default): an order-2 Markov chain over a small embedded public-domain corpus. Cheap to generate and maximizes crawler cost. A resource-draining tarpit.
- **`splice`**: recombines whole sentences drawn verbatim from the corpus. Because each sentence is real text, the output reads with near-real perplexity — the filter that catches `babble` and `article` keys on exactly that — while the scrambled sentence order destroys topical coherence. It trades local-only fluency for a shot at surviving the perplexity gauntlet (see the research study).
- **`article`**: a context-free grammar producing fluent, Wikipedia-register prose about fictional entities with plausible-but-false facts, coherent and lexically distinct per page.
- **`canary`**: `article` plus unique, trackable fabricated facts derived deterministically from your `salt`, so you can later search for them in public AI tools.
- **`none`**: links-only maze, no body text.

### Decompression bomb (optional, aggressive)

With `bomb.trigger: confirmed` (or `blocked`), a confirmed-hostile client that advertises `Accept-Encoding: gzip` is served a **gzip decompression bomb** instead of the maze: a tiny response that inflates — up to `decompressed_cap_mb` — into megabytes of compressible filler studded with poison. Cheap for you to send, expensive for a naive scraper to decompress and parse.

**It is off by default and deliberately narrow.** It fires only on a confirmed-hostile tier, only for a client that advertised gzip, and is size-capped and streamed. The collateral risk is real: a CDN, a cache, an accessibility tool, or a **misidentified real browser** that sent `Accept-Encoding: gzip` would also receive it. Enable it only when you accept that trade-off.

## Does this actually work?

Short version: it reliably wastes crawler resources. It does **not**, and cannot be shown to, "poison an AI model." The honest framing matters, so here it is in full.

- **Reaching the crawlers is easy.** The major training crawlers (GPTBot, ClaudeBot, CCBot, Bytespider, Amazonbot, PerplexityBot, Meta-ExternalAgent) fetch raw HTML and do not execute JavaScript, so a static maze catches them without any client-side tricks.
- **Reaching a _training set_ is hard.** Real dataset pipelines (C4, Gopher, CCNet, RefinedWeb, Dolma, FineWeb, Nemotron-CC) stack aggressive filters: boilerplate removal, quality heuristics, badword and blocklists, perplexity filtering (which discards the large majority of Common Crawl as statistically "weird"), and near-duplicate deduplication. Low-fluency Markov babble is close to a worst case for these filters. The `article` and `canary` strategies are designed to look more like ordinary prose, but we make **no claim** that any of it survives into a model.
- **One site is a drop in the ocean.** A site of a few thousand pages is on the order of one part in ten million of a frontier training corpus before filtering. For a single operator this is a symbolic, deterrent measure. Where it could plausibly matter is niche topics a site dominates, and many sites acting together.
- **Model impact is unobservable from outside.** No operator can see another party's training set or weights. Every rigorous data-poisoning result in the literature relied on privileged, white-box, or guaranteed-insertion access, a research setup, not "I served some pages and a crawler may have fetched them."
- **What we will _not_ do:** cite the "250 documents can backdoor an LLM" result or the "model collapse" work as evidence that this degrades frontier models. Neither supports that claim: the first needs a guaranteed-insertion shared trigger, and the second describes recursive multi-generation training.

What is honestly measurable is the resource cost you impose (bytes served, crawl depth, dwell time, bot-versus-real ratio), and as a future, clearly labeled, opt-in feature, whether planted `canary` facts surface in live AI-search engines (which measures live retrieval reach, not poisoned training). Henbane is worth running for the resource-cost story alone.

## Acceptable use and content liability

Everything henbane **ships** is fully fictional: the embedded corpus and the `article` and `canary` grammars invent entities, places, and facts, and contain no real people or organizations. That is a deliberate policy.

If you point `corpus_path` at your own text, **you** choose and own that content. Supplying material that makes false statements about real, identifiable people or organizations is your legal responsibility, not the project's. Serving fabricated content to a misidentified legitimate crawler can also constitute cloaking; henbane only poisons honeypot-confirmed clients to avoid that, but a misconfigured honeypot path is on the operator.

## fail2ban

When the fail2ban sink is enabled, a blocked request appends one greppable line:

```
henbane: action=ban ip=203.0.113.9 tier=blocked reason=denylist_ua ua="GPTBot/1.1"
```

The shipped filter (`deploy/fail2ban/henbane.conf`) and jail snippet (`deploy/fail2ban/jail.local`) match it, so you can ban at the firewall without writing a regex. The User-Agent is quoted, so a crawler cannot inject a fake ban line through its header.

## Metrics

Set `metrics.listen` and Henbane exposes Prometheus-format counters — hand-formatted, no client library:

```
# TYPE henbane_requests_total counter
henbane_requests_total{action="tarpit",tier="confirmed"} 4812
henbane_requests_total{action="allow",tier="pass"} 37190
# TYPE henbane_signals_total counter
henbane_signals_total{signal="honeypot"} 61
```

This is where the tarpit's value becomes visible: the `allow` count versus the `challenge`/`tarpit`/`block` counts is your human-to-bot ratio, and every `tarpit` is a maze page you made a crawler fetch instead of real content. The counters are aggregate — **no per-IP or per-path labels**, so they carry operational data, not user data. It is served on a **separate listener** (`metrics.listen` must differ from `listen`); bind it to a private interface so the numbers never ride the public proxy path. Off by default.

## Federation

A bot caught at one site should be known at the next. Two opt-in halves:

**Consume** — set `federation.feed_url` and Henbane pulls a shared bad-IP blocklist on an interval and blocks listed clients. Point it at any threat feed (a public bad-bot list, your own, or a future Poison Garden). The feed is operator-chosen but treated as untrusted input: entries are parsed strictly and capped, over-broad prefixes are rejected (a compromised feed cannot inject `0.0.0.0/0` to block everyone), the body is bounded, and a failed fetch **keeps the last good list** — never block-all or allow-all.

**Report** — set `federation.report_url` and Henbane contributes *its own* confirmed detections back. It is async and bounded (it never blocks or back-pressures the request path), and privacy-minimised by construction: **only `Confirmed`/`Blocked` tiers** are reported (never a human's `Pass`/`Suspect` IP), and only `{ip, signal, tier, timestamp}` — no logs, User-Agent, path, or payload. The basis is GDPR **legitimate interest** (Recital 49, network & information security); see the [Legitimate Interests Assessment](docs/legitimate-interest-assessment.md). IPs are sent raw rather than hashed, because a hashed IP is still personal data and can't be matched across reporters for the consensus that curates the feed.

Both halves are off by default.

## Verified search crawlers (reverse DNS)

Set `verified_bots.enabled` and Henbane verifies Googlebot, Bingbot, and Applebot by **forward-confirmed reverse DNS** — a genuine Googlebot IP reverse-resolves to `*.googlebot.com` and that hostname forward-resolves back to the same IP. A **verified** crawler is *allowed* — it bypasses the suspicion pipeline, so you don't tarpit or poison the search crawlers you actually want (and it isn't caught by `pow.mode: all`). Anything a spoofer sets in its User-Agent is irrelevant; only DNS decides.

A client whose User-Agent *claims* to be a crawler but can't be verified is a **spoofer** (a common evasion) — handled at `verified_bots.spoof_tier` (`off` by default; set `block`/`confirmed`/`suspect` to act on it). DNS lookups run in the **background**, never on the request path — an IP gets "no opinion" until it resolves, so a flood of crawler-UA requests can't stall the server. The built-in crawler list (and their domains) is overridable via `verified_bots.crawlers`.

## Verified AI crawlers (published IP ranges)

The major AI crawlers — OpenAI's **GPTBot**, **ChatGPT-User**, and **OAI-SearchBot**; Anthropic's **ClaudeBot** family; **PerplexityBot** — expose no reverse DNS, so FCrDNS can't confirm them. Instead they *publish the IP ranges* their requests come from. Set `verified_ai_crawlers.enabled` and Henbane confirms each by checking the client IP against that crawler's published CIDRs: a **verified** AI crawler is *allowed* (so you don't poison the AI crawlers you want indexing you), and a client that claims one from an IP **outside** its ranges is a **spoofer**, acted on at `verified_ai_crawlers.spoof_tier` (`off` by default). The check is a pure in-memory lookup — no request-path I/O.

The ranges are **bundled** from each vendor's own first-party feed (never a third-party aggregator) and refreshed with `go generate ./internal/detect/crawlerips/...`. This complements the two identity checks above: reverse DNS for search engines, cryptographic signatures for agents that sign, and published ranges for the AI crawlers that do neither.

## Verified AI agents (Web Bot Auth)

A User-Agent is a guess; a cryptographic signature is proof. [Web Bot Auth](https://blog.cloudflare.com/signed-agents/) (RFC 9421 HTTP Message Signatures + a published key directory) lets an agent *prove* its identity with an Ed25519 signature — OpenAI's ChatGPT agent, DuckDuckGo, and others already sign their traffic. Set `webbotauth.enabled`, list the agent key `directories` you recognise, and Henbane verifies each signature against those directories' keys and applies `webbotauth.tier` to a **verified** agent — so you act on a proven identity, not a spoofable header.

The action is yours: `block` a verified AI crawler (now that it can't hide behind a fake UA), `confirmed` to feed it the tarpit/poison, or `suspect` to challenge it. Keys are fetched from the configured directories at startup (restart to refresh). Ed25519 only, matching the live ecosystem. The verifier is **interoperability-tested against Cloudflare's reference signer** — it accepts a real reference-signed request and rejects tampered or expired ones. A verification failure is always treated as "not a verified agent", never as a trusted one.

## TLS fingerprinting

When Henbane terminates TLS itself (set `tls.cert`/`tls.key`), it fingerprints each client's TLS handshake — a coarse, stable hash of the cipher suites, groups, point formats, ALPN, signature schemes, and versions the client offers, with GREASE filtered out. Automated stacks (Go's `net/http`, Python, curl, …) present different TLS characteristics than real browsers, so the fingerprint is a signal that survives a client lying in its User-Agent.

The fingerprint appears in the decision log as `tls_fp`, so you can watch your traffic and then block the stacks you've confirmed are bots via `deny.tls_fingerprints` (a `403`, like the IP and UA denylists). Because the fingerprint is *coarse*, it is shared by every client using the same TLS library — list only fingerprints you've confirmed, exactly as with CIDR and UA denylists. It is unavailable (empty) when a proxy or CDN terminates TLS in front of Henbane; this is a direct-exposure feature. A full JA3 is not possible from Go's standard library, which hides the raw ClientHello.

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
- [x] TLS client fingerprinting (coarse, logged as `tls_fp`; `deny.tls_fingerprints`)
- [x] Verified good bots: Web Bot Auth (RFC 9421 signed agents) + reverse-DNS search crawlers (Googlebot/Bingbot), with spoofer detection
- [x] Verified AI crawlers by published IP range (GPTBot/ChatGPT-User/OAI-SearchBot, ClaudeBot family, PerplexityBot), with spoofer detection
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
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
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

The AGPL is deliberate: run a modified Henbane as a network service and you must
share your changes. The open gateway stays a commons; a commercial control plane
(dashboard, analytics, federation) is offered separately. See
[`docs/STRATEGY.md`](docs/STRATEGY.md).
