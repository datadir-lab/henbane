# Henbane Slice 3: Labyrinth (Design Addendum)

- **Status:** Approved for planning
- **Date:** 2026-11-14
- **Builds on:** main design §6.2, Slice 2 (detector pipeline + honeypot/flagstore).

## Goal

Serve `Confirmed` (honeypot-flagged) clients an **infinite maze of generated links**
(HTTP 200) instead of a 403, to waste their crawl budget. Slice 3 builds the maze
*structure*; Slice 4 fills pages with Markov poison text.

## In scope
- `internal/generate/labyrinth`: a deterministic, unbounded maze-page generator (stdlib).
- `core.actionForTier`: `Confirmed → Tarpit` (was Block interim).
- Proxy `ActionTarpit` case → serve a maze page via an injected writer.
- Config `labyrinth.links_per_page` (default 15).
- Arch purity extended to `internal/generate/labyrinth`.

## Out of scope (deferred)
- Markov / plausible-but-wrong **poison text** (Slice 4). Slice-3 pages are links only.
- A configurable tier→action map (Confirmed→Tarpit is the fixed default this slice).
- Rate-limiting / adaptive maze depth.

## Disposition philosophy (confirmed)
- **Denylist → Block → 403 + fail2ban line**: banish a known-bad actor (firewall ban).
- **Honeypot-confirmed → Tarpit → maze (200), NO fail2ban**: *detain* them; the point is to
  keep them crawling the maze (and poison them in Slice 4). Banning would make them leave.
- The fail2ban sink keeps firing only on `Action == Block`, so tarpitted clients get no ban
  line. **No fail2ban change needed.**

## The maze generator (`internal/generate/labyrinth`)

Stdlib-only (`hash/fnv`, `html/template`, `io`, `math/rand`, `strconv`, `strings`).

```go
func New(links int) *Generator                         // clamps links to [1,100], default 15 for <1
func (g *Generator) WritePage(w io.Writer, path string) error
```

- **Deterministic per path:** `seed = fnv64a(path)`; a per-call `rand.New(rand.NewSource(seed))`
  (no global state → concurrency-safe) generates the page. Same path → identical bytes (stable
  re-crawl); different paths → different pages.
- **Unbounded:** each page emits `links` child `<a href>`s to distinct child paths derived from
  the parent path + random segments, so following any link yields a fresh page forever.
- **Bounded cost:** `links` clamped ≤100; page is small, generation is O(links), cheaper to
  serve than for the crawler to fetch. Output via `html/template` (auto-escaped). Links carry
  `rel="nofollow"`.
- Pure leaf: takes `io.Writer` + `path`; imports no `ports`, no transport. Added to the arch
  purity targets.

## Engine (`internal/core`)

`actionForTier`: `Pass→Allow`, `Confirmed→Tarpit`, else (`Suspect` interim, `Blocked`) →`Block`.
The emitted `Event.Tier` stays accurate; only Confirmed's action changes. Engine signature
unchanged (no caller ripple from this change).

## Proxy adapter

Add `case ports.ActionTarpit:` → set `Content-Type: text/html; charset=utf-8` and
`mazeWriter.WritePage(w, r.URL.Path)` (first write ⇒ 200). The proxy defines a small
`MazeWriter` interface (`WritePage(io.Writer, string) error`) and takes it in `New`;
`labyrinth.Generator` satisfies it structurally (keeps proxy decoupled from the generator and
testable with a fake). The fail-closed `default` still covers Challenge/Poison. The generator
is always wired (cheap, stateless) so `Tarpit` can never hit a nil writer.

## Config

```yaml
labyrinth:
  links_per_page: 15   # clamped to [1,100]; 0/absent => default 15
```
`config.Config` gains `Labyrinth struct { LinksPerPage int }`. Validation: `LinksPerPage >= 0`
(0 = default). No TTL/path needed.

## Wiring (`cmd/henbane`)

Build `labyrinth.New(cfg.Labyrinth.LinksPerPage)`; pass it to `proxy.New`. Nothing else
changes in detector assembly: the honeypot already produces `Confirmed`, which now maps to
Tarpit and routes every flagged-client request into the maze.

## Testing (TDD)
- `labyrinth`: determinism (same path → identical bytes); different paths differ; exactly N
  links present; child hrefs are under the parent path; output parses as HTML / has no unescaped
  injection; `links<1` clamps to 15, `>100` clamps to 100.
- `core`: `Confirmed → Tarpit`; `Blocked → Block`; `Pass → Allow`.
- `proxy`: a fake engine returning `ActionTarpit` → 200, `text/html`, body from the maze writer,
  upstream NOT hit; `ActionBlock` still 403; `ActionAllow` still proxies.
- `cmd` integration: a honeypot-flagged client now receives a **200 maze page** (HTML with
  links) instead of 403; a denylisted client still gets 403; allowed client still proxies.

## Arch / deps impact
- No new third-party module (stdlib only; allowlist unchanged).
- Arch purity test adds `internal/generate/labyrinth` (must not import net/http*, adapters,
  config, clientip).
