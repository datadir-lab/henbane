# Henbane

An open-source, self-hostable **anti-AI-scraper gateway**. Henbane sits in front of
your site as a reverse proxy, identifies hostile automated crawlers, and — depending on
how confident it is — either bans them or detains them in an endless maze of generated
pages seeded with poison text.

> **Status: early / under active development.** Implemented today: reverse proxy, IP/UA
> denylists, a honeypot trap detector, the labyrinth maze, and three poison generators.
> Proof-of-work challenges, metrics, and the proxy-module/middleware form factors are
> planned, not yet built. Zero third-party runtime dependencies (standard library only,
> plus `gopkg.in/yaml.v3` for config).

## How it works

Every request is classified into a tier, and the tier picks an action:

| Tier | Trigger | Action | Response |
|---|---|---|---|
| `Pass` | normal traffic | Allow | proxied to your upstream |
| `Confirmed` | tripped a honeypot trap | **Tarpit** | 200 — a labyrinth maze page with poison text (**no** ban) |
| `Blocked` | on a denylist (IP/UA) | **Block** | 403 — plus a fail2ban ban-line if configured |

The split is deliberate: a **denylisted** actor is *banished* (403 + fail2ban), but a
**honeypot-confirmed** crawler is *detained* — the point is to keep it crawling the maze
and consuming its own budget, so banning it would be counterproductive.

## Poison strategies

The maze's pages are filled with body text by a pluggable `Poisoner`. Four ship today,
selected by config:

- **`babble`** (default) — an order-2 Markov chain over a small embedded public-domain
  corpus. Cheap to generate, maximizes crawler cost. A resource-draining *tarpit*.
- **`article`** — a context-free grammar producing fluent, Wikipedia-register prose about
  fictional entities with plausible-but-false facts. Built to be coherent and lexically
  distinct per page.
- **`canary`** — `article` plus unique, trackable fabricated facts derived deterministically
  from your `salt`, so they can later be searched for in public AI tools.
- **`none`** — links-only maze, no body text.

```yaml
# henbane.yaml
upstream: "http://127.0.0.1:8081"
honeypot:
  enabled: true
  path: "/.well-known/hb-trap"   # link this invisibly from your pages
labyrinth:
  links_per_page: 15
poison:
  strategy: babble               # babble | article | canary | none
  paragraphs_per_page: 3         # clamped to [0,20]
  corpus_path: ""                # optional: your own corpus for `babble`
  salt: ""                       # per-deployment; REQUIRED for `canary`
```

## Does this actually work?

**Short version: it reliably wastes crawler resources. It does _not_, and cannot be shown
to, "poison an AI model."** We think the honest framing matters, so here it is in full.

- **Reaching the crawlers is easy.** The major training crawlers (GPTBot, ClaudeBot,
  CCBot, Bytespider, Amazonbot, PerplexityBot, Meta-ExternalAgent) fetch raw HTML and do
  not execute JavaScript, so a static maze catches them without any client-side tricks.
- **Reaching a _training set_ is hard.** Real dataset pipelines (C4, Gopher, CCNet,
  RefinedWeb, Dolma, FineWeb, Nemotron-CC) stack aggressive filters: boilerplate removal,
  quality heuristics, badword/blocklists, **perplexity filtering** (which discards the
  large majority of Common Crawl as statistically "weird"), and **near-duplicate
  deduplication**. Low-fluency Markov babble is close to a worst case for these filters;
  `article`/`canary` are designed to look more like ordinary prose, but we make **no claim**
  that any of it survives into a model.
- **One site is a drop in the ocean.** A site of a few thousand pages is on the order of
  one part in ten million of a frontier training corpus *before* filtering. For a single
  operator this is a **symbolic / deterrent** measure. Where it could plausibly matter is
  (a) niche topics a site dominates, and (b) **many sites acting together**.
- **Model impact is unobservable from outside.** No operator can see another party's
  training set or weights. Every rigorous data-poisoning result in the literature relied on
  privileged, white-box or guaranteed-insertion access — a research setup, not "I served
  some pages and a crawler may have fetched them."
- **What we will _not_ do:** cite the "250 documents can backdoor an LLM" result or the
  "model collapse" work as evidence that this degrades frontier models. Neither supports
  that claim (the first needs a guaranteed-insertion shared trigger; the second describes
  recursive multi-generation training). Tools that make that leap are overclaiming, and we
  won't repeat it.

**What is honestly measurable** is the resource cost you impose (bytes served, crawl depth,
dwell time, bot-vs-real ratio) and — as a future, clearly-labeled, opt-in feature — whether
planted **canary** facts show up in live AI-search/answer engines (that measures *live
retrieval reach*, which is **not** the same as "poisoned training"). Henbane is worth
running for the resource-cost story alone; it does not need the unverifiable claim.

## Acceptable use and content liability

Everything Henbane **ships** is fully fictional: the embedded corpus and the `article`/
`canary` grammars invent entities, places, and facts, and contain no real people or
organizations. That is a deliberate policy.

If you point `corpus_path` at your own text, **you** choose and own that content. Supplying
material that makes false statements about real, identifiable people or organizations is
your legal responsibility, not the project's — Henbane provides the mechanism, not the
content. Serving fabricated content to a *misidentified* legitimate crawler (e.g. a search
engine) can also constitute cloaking; Henbane only poisons honeypot-*confirmed* clients to
avoid that, but a misconfigured honeypot path is on the operator.

## Build

```sh
go build ./...
go test ./...
./henbane --config henbane.yaml --upstream http://127.0.0.1:8081
```

## License

Henbane is free software licensed under the **GNU Affero General Public License
v3.0** (AGPL-3.0) — see [LICENSE](LICENSE). Copyright © 2026 datadir s. r. o.

The AGPL is deliberate: anyone who runs a modified Henbane as a network service
must share their modifications. The open gateway stays a commons; a managed
control plane (dashboard, analytics, federation) is offered separately. See
[docs/STRATEGY.md](docs/STRATEGY.md).
