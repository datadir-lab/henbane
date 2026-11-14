# Henbane Slice 4 — Poison (Design Addendum)

- **Status:** Approved for planning
- **Date:** 2026-11-14
- **Builds on:** main design §6.2, Slice 3 (labyrinth maze generator + `Confirmed → Tarpit`).

## Goal

Fill the maze's pages with **poison body text** via a pluggable `Poisoner` port, and
ship **three strategies** spanning cheap-tarpit → filter-surviving-poison →
measurable-reach-poison. Poison inherits the existing gate: it only renders inside the
`Confirmed → Tarpit` maze, so a correctly-classified search crawler is never poisoned
(this is what keeps us clear of search-engine *cloaking*).

Everything shipped stays **honest**: no model-impact claims anywhere. The reproducible
filter-survival benchmark and its README graphs are **Slice 4b** (separate follow-on).

## Research grounding (why this shape)

Four research sweeps (archived in `scratchpad/research-*.md`) converged on:
- **Static HTML is enough** — GPTBot, ClaudeBot, PerplexityBot, CCBot, Bytespider,
  Amazonbot, Meta-ExternalAgent fetch raw HTML and never run JS. The existing maze
  already targets them.
- **The dataset filter gauntlet is the binding constraint.** C4 / Gopher / CCNet /
  RefinedWeb / Dolma / FineWeb-Edu / Nemotron-CC stack boilerplate-extraction →
  heuristics → badword/punctuation → **KenLM perplexity (discards ~84% of Common
  Crawl)** → **MinHash dedup** → LLM-judge classifiers. None check factual *correctness*.
  So: gibberish/Markov is an excellent **tarpit** but a weak **poison**; text that
  actually reaches a corpus must be fluent, Wikipedia-register, topically coherent,
  **lexically distinct per page** (dedup), profanity-free, and carry a **semantic**
  payload (plausible-but-false facts), not exact-string injection.
- **Honest effectiveness:** for a single generic site this is symbolic/deterrent
  (~1 part in 10⁷ of a frontier corpus before filtering). Materiality needs niche
  topical dominance or **federation** across many sites.
- **Measurement:** training-corpus/weight impact is **unobservable** from outside.
  Only two things are honestly measurable: resource cost imposed, and (later, opt-in)
  **live-AI-search canary reach**. We must never relabel either as "poisoned training".

## Fabrication-target policy (A / B / C)

- **The mechanism supports A, B, and C.** The **project ships only (A) fully-fictional**
  content (invented entities/places/dates). **(B)** real-category/invented-specifics and
  **(C)** targeted real-entity content are reachable **only via an operator-supplied
  `corpus_path`** — a custom text corpus the `babble` Markov generator draws from (custom
  `article`/`canary` templates are a future BYO path). Whoever loads B/C content owns the
  liability; Henbane ships no targeted falsehoods about real people or organizations. This
  is documented in an acceptable-use note (the "we make the tool, not the ammunition" posture).

## In scope

- `internal/ports`: new `Poisoner` port (first-class, like `Detector`/`Sink`).
- `internal/generate/poison/{babble,article,canary}` — three poisoners + a `none` no-op.
- `internal/generate/labyrinth`: compose poison paragraphs into the page
  (`New` gains a `Poisoner` + paragraph count).
- `internal/config`: a `poison:` block (`strategy`, `paragraphs_per_page`,
  `corpus_path`, `salt`) + validation.
- `cmd/henbane`: select/build the poisoner from config (incl. BYO corpus read).
- Arch purity extended to the new `poison/*` packages.
- README "Does this actually work?" section (prose only — honest, correctly cited).

## Out of scope (deferred)

- **Filter-survival benchmark harness + README graphs** → Slice 4b.
- **Canary live-probe** (querying public AI endpoints) → measurement slice. Canary here
  only *generates* reconstructible canaries and exposes them.
- **`Event.PoisonBytes` wiring / per-bot canary↔scraper mapping** → metrics slice
  (the struct field already exists; it stays 0 this slice).
- Interleaving poison density by crawler, adaptive length, `ActionPoison` as a distinct
  verdict (poison lives *inside* `Tarpit` for now).

## The `Poisoner` port (`internal/ports`)

```go
// Poisoner produces deterministic plain-text poison paragraphs for a maze page.
// Plain text ONLY: the maze template escapes it, so a Poisoner can never emit raw
// HTML (zero injection surface). Implementations must be deterministic for a given
// seed, concurrency-safe, and bounded in CPU and output size.
type Poisoner interface {
    Name() string
    Paragraphs(seed int64, n int) []string // n already clamped by the caller
}
```

- Lives in `ports` beside `Detector`/`Sink` — it is a core extensibility axis
  ("users can write their own logic"). `ports` stays pure; `labyrinth` may import it.
- **Determinism:** `seed` is the maze's existing per-URL `fnv64a(path)`. Each poisoner
  mixes in its own **per-deployment salt** so two installs with the same corpus aren't
  byte-identical (fingerprint resistance) and so canaries are deployment-unique.
- **Concurrency-safe:** like the maze, each call builds its own `rand.New(rand.NewSource(…))`
  — no shared mutable rng.

## The three poisoners (`internal/generate/poison/*`, one subpackage each)

Each is a pure leaf (stdlib + `go:embed` only; may import `ports`; added to arch purity).

- **`babble`** — order-2 word-level Markov over a `go:embed`ed **public-domain** corpus
  (operator `corpus_path` overrides the embedded default). Cheap, high crawler-cost,
  low filter-survival. *Tarpit-grade; option A.* `babble.New(corpus []byte, salt string)`
  (`corpus == nil` ⇒ embedded default).
- **`article`** — a context-free grammar → Wikipedia-register sentences with slot-filled
  **fictional** entities/facts. Large combinatorial space ⇒ lexically distinct per page
  (dedup-resistant); coherent, lower-perplexity, profanity-free; semantic payload.
  *Filter-surviving; option A.* `article.New(salt string)`.
- **`canary`** — `article` generation plus a dedicated fabricated-fact vocabulary derived
  **deterministically from the salt**, so a later probe slice regenerates the exact canary
  strings and searches public AI endpoints for them — **no generation-time state/IO**
  (stays pure). `canary.New(salt string)`; also exposes `Canaries() []string` (the
  reconstructible set) for the future probe.
- **`none`** — `poison.None{}` returning `nil` paragraphs (today's links-only maze).

The A/B/C seam is `babble`'s `corpus_path`: shipped content is fictional-only; an operator
supplies B/C content as a custom Markov corpus. `article`/`canary` ship fictional grammar
and ignore `corpus_path` this slice.

## Page composition (`internal/generate/labyrinth`)

```go
func New(links int, poisoner ports.Poisoner, paragraphs int) *Generator
```

`WritePage` renders: `<h1>{{Title}}</h1>` → **N poison `<p>` paragraphs** (main content)
→ `<ul>` of `rel="nofollow"` child links. Prose-block-then-link-list mimics real
main-content/nav structure (helps clear trafilatura boilerplate extraction). `paragraphs`
is clamped to **[0, 20]**; each poisoner also caps paragraph length — total page size
stays bounded (poison must never DoS *us*). Poisoner is always non-nil (cmd wires `none`
when disabled). Template still `html/template` (every paragraph auto-escaped).

## Config (`internal/config`)

```yaml
poison:
  strategy: babble          # babble | article | canary | none ; "" => babble
  paragraphs_per_page: 3    # 0 => default 3 ; clamped [0,20]
  corpus_path: ""           # optional BYO corpus for babble (Markov source); ignored by article/canary
  salt: ""                  # per-deployment; REQUIRED (non-empty) for canary
```

`Config` gains `Poison struct { Strategy string; ParagraphsPerPage int; CorpusPath, Salt string }`.
Validation in `Parse`:
- `strategy ∈ {"", babble, article, canary, none}` (else error); `"" ⇒ babble`.
- `paragraphs_per_page >= 0`.
- **`strategy == canary` ⇒ `salt != ""`** (hard error — a saltless canary is guessable
  and non-unique, defeating the feature; fail-safe per zero-trust).
- `corpus_path`, if set, is read by `cmd` at startup and passed to `babble`; an unreadable
  file is a fatal config error (fail-closed). It is ignored by `article`/`canary`.

**Default strategy is `babble`** — poison is on by default when the maze triggers, but
only the safe, fictional, cheap tier. `article`/`canary` are deliberate opt-ins.

## Wiring (`cmd/henbane`)

Add a small selector in `newHandler`: map `cfg.Poison.Strategy` → a concrete
`ports.Poisoner` (reading `corpus_path` bytes for babble/article/canary; passing
`cfg.Poison.Salt`). `none`/empty → `poison.None{}`. Build
`labyrinth.New(cfg.Labyrinth.LinksPerPage, poisoner, cfg.Poison.ParagraphsPerPage)`.
The selector stays in `cmd` so the poison packages never import `config`.

## Zero-trust safety invariants

- Poison renders **only on `Confirmed → Tarpit`** (search crawlers, if classified right,
  never see it — no cloaking).
- **Plain-text-only** from poisoners ⇒ `html/template` escapes everything (no injection).
- **Hard caps:** `paragraphs_per_page` clamped [0,20]; per-paragraph length cap in each
  poisoner; links already ≤100 — total page bounded, generation O(size).
- **Deterministic, concurrency-safe, bounded-CPU** per URL; no global rng.
- **No attacker input** ever enters the corpus or the generated text (only `fnv(path)`
  seeds the rng; the path is never reflected into poison prose).
- **Shipped content fictional-only (A);** B/C are operator-supplied and operator-owned.
- Saltless `canary` is a hard config error.

## README (this slice — prose, graphs in 4b)

An honest **"Does this actually work?"** section: the filter-gauntlet reality; "symbolic
for a single site, materially amplified only by federation"; **zero model-impact claims**;
and an explicit note that cites the literature *correctly* — calling out the common
anti-pattern of citing the Anthropic 250-document backdoor and "model collapse" papers as
if they proved one-shot web-poisoning (they do not). Plus the A/B/C acceptable-use /
liability note and BYO-corpus guidance.

## Testing (TDD)

- **`babble`:** determinism (same seed → identical paragraphs); generated words ∈ corpus
  vocabulary; different seeds differ; different salts differ; `n` paragraphs returned and
  length-capped; `corpus == nil` uses the embedded default.
- **`article`:** deterministic per seed; sentences are grammatical (start/terminal
  punctuation, ≥N words); **cross-seed lexical distinctness** (dedup resistance) over many
  pages; profanity-free (badword list absent); contains only fictional entities.
- **`canary`:** output contains canary strings **reconstructible from the salt**;
  `Canaries()` matches what appears in output; same salt → same set; different salt →
  different set.
- **`none`:** returns `nil`/empty; maze renders links-only (Slice-3 behavior preserved).
- **`labyrinth`:** paragraphs appear in the page as escaped `<p>`; special chars in poison
  text stay escaped; `paragraphs` clamps [0,20]; link structure unchanged; determinism
  preserved; poison text sits before the link list.
- **`config`:** strategy whitelist; `"" ⇒ babble`; `paragraphs_per_page < 0` rejected;
  `canary` without `salt` rejected; valid blocks round-trip.
- **`cmd` integration:** a honeypot-flagged client gets a **200 maze with poison
  paragraphs**; strategy switch selects the right poisoner; `none` → links-only;
  unreadable `corpus_path` → fatal startup error; denylisted client still 403; allowed
  client still proxies.

## Arch / deps impact

- **No new third-party module** (stdlib + `go:embed` only; allowlist unchanged).
- Arch purity adds `internal/generate/poison/{babble,article,canary}` and
  `internal/generate/poison` (must not import net/http*, adapters, config, clientip;
  may import `ports`). `labyrinth` now imports `ports` — still pure, still a valid target.
```
