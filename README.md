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

## Configuration

Zero-config works: a single `--upstream` passes all traffic through. For anything more, point `--config` at a YAML file. Every key below is one henbane reads today.

```yaml
# henbane.yaml
listen: ":8080"
upstream: "http://127.0.0.1:8081"

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

honeypot:
  enabled: true
  path: "/.well-known/hb-trap"   # link this invisibly from your pages
  flag_ttl: "1h"
  max_flagged: 100000

labyrinth:
  links_per_page: 15

poison:
  strategy: babble               # babble | article | canary | none
  paragraphs_per_page: 3         # clamped to [0, 20]
  corpus_path: ""                # optional BYO corpus for babble
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

sinks:
  fail2ban:
    enabled: true
    path: /var/log/henbane/ban.log
```

## Poison strategies

The maze's pages are filled by a pluggable `Poisoner`, selected by config:

- **`babble`** (default): an order-2 Markov chain over a small embedded public-domain corpus. Cheap to generate and maximizes crawler cost. A resource-draining tarpit.
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

## Dependencies

Henbane is Go, stdlib-first by policy. The only third-party runtime import is `gopkg.in/yaml.v3` for config. A CI guard fails the build if anything outside that allowlist appears in `go.mod`. A tool that fights surveillance should not become a supply-chain risk of its own.

## Roadmap

Each item is an end-to-end, tested slice. Checked items ship in the current build.

- [x] Reverse-proxy skeleton with a JSON event log
- [x] Operator denylist (IP and UA) to `403`, with a fail2ban line
- [x] Honeypot tripwire that marks a client Confirmed
- [x] Labyrinth: an endless tree of generated links that wastes crawl budget
- [x] Poison: babble, article, and canary generators fill the maze
- [x] Proof-of-work challenge gate: JS solver, HMAC session token, themeable page (WASM solver + no-JS fallback still to come)
- [ ] Bundled AI-crawler IP ranges, plus a verified-good-bot check
- [ ] Rate-based suspicion
- [ ] Prometheus `/metrics` sink
- [ ] `net/http` middleware form factor
- [ ] Caddy module, with nginx and Traefik via a ForwardAuth sidecar
- [ ] Federated reporter seam for a shared crawler denylist

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
