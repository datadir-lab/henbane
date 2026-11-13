# Henbane — Design Document

- **Status:** Draft for review
- **Date:** 2026-11-13
- **Project dir:** `D:\dev\hacktivism\poison\henbane`
- **Collective/network brand:** The Poison Garden

---

## 1. Summary

**Henbane** is a self-hostable, configurable gateway that defends websites against
abusive AI scrapers. It combines three defensive *postures* — a **proof-of-work (PoW)
challenge**, a **labyrinth** (infinite maze of links), and **poison** (Markov/garbage
content that corrupts scraped datasets) — behind a **tiered classifier** that decides,
per request, who gets let through untouched and who gets escalated.

The same engine ships in three *form factors*: a **standalone reverse proxy**, an
**embeddable `net/http` middleware library**, and a **proxy plugin** (native Caddy
module; nginx/Traefik via sidecar + ForwardAuth). Every decision emits a structured
**Event** consumed by pluggable **sinks** (logs, fail2ban, Prometheus metrics, and —
later — a dashboard and the federated *Poison Garden* feed).

It is written in **Go**, with a **near-zero third-party dependency** policy (stdlib
only, save a short vetted allowlist).

## 2. Goals / Non-Goals

### Goals
- Protect a site's real content and infrastructure from abusive AI crawlers.
- **Minimize collateral damage to humans** — the explicit wedge against challenge-everyone
  tools like Anubis. Default behavior lets real humans through untouched.
- One engine, three form factors, consistent behavior across all.
- Themeable challenge/trap pages (custom HTML, image, branding).
- First-class observability: structured logs, fail2ban integration, Prometheus metrics.
- Tiny, auditable supply chain (stdlib-first).
- A clean seam toward a future federated defense network ("The Poison Garden").

### Non-Goals (v1)
- A hosted/SaaS offering. Henbane is self-hosted.
- A built-in dashboard UI (v2 — the data path is designed now).
- The Poison Garden federated feed itself (v2 — only the sink interface + disabled stub now).
- ML-based detection (v1 uses deterministic signals).
- Being a general-purpose WAF. Scope is AI-scraper defense.
- Offensive use (injecting poison into third-party pipelines). Henbane only acts on
  traffic to the operator's own site.

## 3. Positioning

- **robots.txt** is unenforceable; abusive crawlers ignore it. Henbane acts, it doesn't ask.
- **Anubis** (PoW for everyone) stops the load but taxes humans (no-JS, screen readers,
  old devices). Henbane keeps PoW as *one tier*, not the default for all traffic.
- **Nepenthes / Iocaine** (tarpits) and **Cloudflare AI Labyrinth** prove the trap+poison
  posture. Henbane makes it self-hostable, configurable, and targeted.
- Henbane's differentiator is the **tiered classifier**: only escalate what looks hostile.

## 4. Core Concepts

### 4.1 Postures (actions)
- **Challenge** — serve a PoW challenge; must be solved before reaching real content.
- **Tarpit (labyrinth)** — serve an endless tree of generated links; waste crawl budget.
- **Poison** — fill trap pages with plausible Markov/garbage text to corrupt datasets.
- **Block** — 403 / connection drop.
- **Allow** — serve real content, untouched.

### 4.2 Tiers (targeting model — option "C", tiered + configurable)

| Tier | Who lands here | Default action |
|---|---|---|
| **Pass** | Looks human / allow-listed good bot (e.g. Googlebot verified) | Allow |
| **Suspect** | Weak bot signals (unknown UA, elevated rate, odd headers) | Challenge (PoW) |
| **Confirmed** | Known AI-crawler ASN/UA, or tripped a honeypot link | Tarpit + Poison |
| **Blocked** | Operator denylist / repeat offender | Block |

The tier→action mapping is **configurable**. An operator under heavy load can slide the
baseline up (e.g. treat all unknown clients as Suspect → "challenge everyone" mode).

## 5. Architecture

### 5.1 Hexagonal (ports & adapters)

```
internal/
  core/        # domain: classifier, tier/policy engine, verdict — NO transport imports
  ports/       # interfaces: RequestView, Sink, ContentStore, Clock, StateStore
  generate/    # content generators: challenge page, labyrinth, poison (Markov)
  pow/         # hashcash-style issue/verify; wasm client build
  config/      # YAML + env + defaults + hot reload
  adapters/
    proxy/        # standalone reverse proxy (+ ForwardAuth/auth_request mode)
    middleware/   # net/http middleware
    sink/         # log(slog) · fail2ban · prometheus · reporter(v2 stub)
cmd/henbane/   # wiring, flags, signals

# separate, optional Go module (isolated deps):
caddy/         # native Caddy module importing caddyserver/caddy
```

**Invariant (enforced by architecture tests):** `core` and `ports` import nothing from
`adapters`, `config`, or any transport package. Adapters depend inward only, never on
each other. `generate` and `pow` depend only on stdlib + `ports`.

### 5.2 The decision contract

```go
// ports — transport-agnostic, read-only view of a request
type RequestView interface {
    IP() netip.Addr
    UserAgent() string
    Method() string
    Path() string
    Header(name string) string
}

type Action int // Allow | Challenge | Tarpit | Poison | Block
type Tier   int // Pass | Suspect | Confirmed | Blocked

type Verdict struct {
    Action    Action
    Tier      Tier
    Reasons   []Signal      // which signals fired
    Directive *Directive    // optional: what the adapter must emit (page, headers, status)
}

type Event struct {
    Time        time.Time
    IP          netip.Addr
    ASN         string
    UserAgent   string
    Path        string
    Action      Action
    Tier        Tier
    Signals     []Signal
    PoWMillis   int64
    PoisonBytes int64
}

type Sink interface { Emit(Event) }   // never returns an error that blocks the request path

type Engine interface {
    Decide(ctx context.Context, r RequestView) (Verdict, []Event)
}
```

The adapter's only job: build a `RequestView`, call `Decide`, apply the `Directive`
(pass through to upstream, emit challenge page, stream labyrinth/poison, or block),
and fan the returned `Event`s to the configured sinks.

## 6. Components

### 6.1 Classifier / policy engine (`core`)
Deterministic signal evaluation producing a `Tier`, then a configurable mapping to an
`Action`. v1 signals:
- **UA allowlist / denylist** — explicit good/bad user agents.
- **Verified good bots** — optional reverse-DNS/forward-confirmed check for Googlebot etc. (stdlib `net`).
- **Known AI-crawler ranges** — bundled, updatable list of published crawler **CIDRs** (OpenAI, Anthropic, Google-Extended, etc.), matched via `net/netip`.
- **Honeypot tripwire** — hidden links (meta-hidden from legit indexers, CSS-hidden from humans); any client fetching one is **Confirmed**.
- **Rate** — per-IP token-bucket (hand-rolled, stdlib) raising Suspect on bursts.

Signals compose into the highest applicable tier. All thresholds/lists are config-driven.

### 6.2 Content generators (`generate`)
- **Challenge page** — `html/template`, fully themeable (see §8.3).
- **Labyrinth** — deterministic infinite link tree, seeded per-path so it's stable but unbounded; `robots`/`nofollow`-safe so legit indexers that *do* honor directives are not harmed, and configurably excluded from verified good bots.
- **Poison** — Markov-chain text generator (stdlib only) producing plausible prose to fill labyrinth pages. Seed corpora are operator-configurable; a default neutral corpus ships. `PoisonBytes` is metered per response.

### 6.3 Proof of work (`pow`)
- Hashcash-style challenge (`crypto/sha256`); difficulty configurable; HashX/argon profiles are post-v1.
- **Token issue/verify** via `crypto/hmac` + `crypto/rand` — signed, expiring cookie proving a solved challenge, so humans solve at most once per session.
- **Client solver** compiled from Go to WASM (`GOOS=js GOARCH=wasm`, `syscall/js`) — no Rust, no third-party.
- **Accessibility:** a configurable non-JS fallback path (e.g. a slower server-verified alternative or allow-with-logging) so the tool degrades instead of hard-blocking no-JS clients. This is a deliberate improvement over Anubis.

### 6.4 Sinks (`adapters/sink`)
- **log** — `log/slog`; JSON or human-readable renderer of `Event`.
- **fail2ban** — stable, greppable line + shipped `filter.d/henbane.conf` and a jail snippet. Henbane also keeps its own denylist for the Block verdict, so firewall banning is optional.
- **prometheus** — `/metrics` in text exposition format, hand-formatted (no `client_golang`).
- **reporter (v2 stub)** — interface present, disabled; later pushes Confirmed fingerprints to The Poison Garden.
- Sinks are non-blocking and must never fail the request path.

### 6.5 Adapters
- **Standalone proxy** — `net/http/httputil.ReverseProxy`; also runs in **ForwardAuth/`auth_request` mode** so nginx and Traefik can delegate decisions to it as a sidecar.
- **Middleware** — `net/http` middleware wrapping any `http.Handler`; same core.
- **Caddy module** — native Caddy plugin in the **isolated `caddy/` module**; the only place third-party (Caddy) imports are allowed.

## 7. Dependency Policy

- **Target: stdlib only** for the core/standalone/middleware module.
- **Allowlist** (the CI guard fails on anything *not* here):
  - `gopkg.in/yaml.v3` — config parsing.
  - `golang.org/x/crypto/acme/autocert` — optional, off-by-default auto-HTTPS.
- The **Caddy module** is a *separate* Go module; its (unavoidable) Caddy dependencies are
  out of scope for the core allowlist.
- Rationale: a tool that fights surveillance must not itself be a supply-chain liability.
  Zero deps shrinks the attack surface to ~"the Go toolchain + Docker base image."

## 8. Configuration & Dev UX

### 8.1 Principles
- **Zero-config happy path:** `henbane --upstream http://localhost:8080` works with sane
  tiered defaults.
- One `henbane.yaml` for everything; **env-var overrides**; **hot reload on SIGHUP**.
- `henbane init` scaffolds a commented config.
- Single static binary + slim Docker image.

### 8.2 Example `henbane.yaml`
```yaml
listen: ":443"
upstream: "http://localhost:8080"

tls:
  mode: byo            # byo | autocert | off
  cert: /etc/henbane/cert.pem
  key:  /etc/henbane/key.pem
  # autocert:
  #   domains: ["example.com"]
  #   email: "admin@example.com"

policy:
  default_tier: pass          # raise to "suspect" for challenge-everyone mode
  tiers:
    suspect:   challenge
    confirmed: [tarpit, poison]
    blocked:   block

signals:
  ua_allow:  ["Googlebot", "bingbot"]
  ua_deny:   ["GPTBot", "CCBot", "ClaudeBot"]
  verify_good_bots: true
  crawler_cidrs: "/etc/henbane/crawlers.txt"   # bundled default, updatable
  honeypot: { enabled: true, path_prefix: "/.well-known/hb-trap/" }
  rate:     { enabled: true, rps: 8, burst: 20 }

pow:
  difficulty: 4
  session_ttl: 24h
  nojs_fallback: allow-logged   # allow-logged | slow-verify | block

theme:
  dir: /etc/henbane/theme        # overrides default; challenge.html + assets

sinks:
  log:        { format: json }
  fail2ban:   { enabled: true, path: /var/log/henbane/ban.log }
  prometheus: { enabled: true, path: /metrics }
```

### 8.3 Theming
A theme is a directory containing `challenge.html` (plus referenced assets). Template
variables: difficulty, estimated solve time, operator branding, custom image, copy.
A default theme ships embedded (`embed.FS`). Operators override by pointing `theme.dir`
at their own.

## 9. Observability

### 9.1 Event schema
See §5.2 `Event`. One `decide()` → zero or more Events → all configured sinks.

### 9.2 fail2ban line (stable contract)
```
henbane: action=ban ip=203.0.113.9 tier=confirmed reason=honeypot ua="GPTBot/1.1"
```
Shipped `filter.d/henbane.conf` matches this; a jail snippet is provided.

### 9.3 Metrics (`/metrics`)
`requests_total{action,tier}`, `pow_issued_total`, `pow_solved_total`,
`pow_failed_total`, `tarpit_entries_total`, `poison_bytes_total`,
`unique_bot_ips`, `decide_duration_seconds`.

## 10. Engineering Practices

### 10.1 TDD
Each slice starts with a failing **acceptance test** (`httptest` server → real HTTP
request → assert response *and* emitted Event), then unit tests drive the classifier and
generators. Core `Decide` is table-test friendly. Run under `test-driven development`.

### 10.2 Architecture tests
A stdlib test shells `go list -deps -json` and asserts `core`/`ports` have no transport
or adapter imports. (No third-party `go-arch-lint`.) `go vet` + `depguard`-style rules
optional via dev tooling.

### 10.3 Lefthook
```yaml
pre-commit:
  parallel: true
  commands:
    fmt:     { glob: "*.go", run: "gofmt -w {staged_files}", stage_fixed: true }
    vet:     { run: "go vet ./..." }
    arch:    { run: "go test ./internal/arch/..." }
    unit:    { run: "go test -short ./..." }
pre-push:
  commands:
    test:    { run: "go test -race -cover ./..." }
    vuln:    { run: "govulncheck ./..." }
    build:   { run: "go build ./..." }
commit-msg:
  commands:
    conventional: { run: "conform enforce --commit-msg-file {1}" }
```

### 10.4 Conventional commits
`conform` (single Go binary) enforces Conventional Commits in the `commit-msg` hook and
in CI. Enables automated changelog/semver later.

### 10.5 CI (GitHub Actions) + heavy vuln scanning
- Build matrix, `gofmt -l` check, `go vet`, `go test -race -cover`, architecture test.
- **Dependency-allowlist guard**: fail if `go.mod require` contains a module not on the allowlist (§7).
- Vuln scanning: `govulncheck` (official), **CodeQL** (SAST), **Trivy** (image + fs),
  **Dependabot** (Go version + Actions), **OpenSSF Scorecard**.
- Supply-chain: **SBOM** (syft) + **SLSA provenance** + **cosign** signing on release.
- `conform` commit check on PRs.
- Linting lane: purist = `gofmt` + `go vet` + `govulncheck`; `staticcheck` optional (dev tool).

## 11. Security & Ethics
- **Defensive only.** Henbane acts on traffic to the operator's own site; it does not
  attack third-party systems.
- **Collateral-damage minimization** is a design goal: humans pass by default; PoW has a
  configurable no-JS fallback; labyrinth/poison apply only to the Confirmed tier.
- **Legal:** operators serve their own content and traps on their own infrastructure —
  the clean side of the line. Docs will state scope and caution against misuse.

## 12. The Poison Garden (future, v2)
A federated feed where Henbane nodes contribute Confirmed bot fingerprints and consume a
shared denylist — giving small sites network-scale detection without a central CDN. v1
plants the seam only: the **reporter sink interface** exists and ships disabled. Sibling
modules may later take other poison-plant names (Belladonna, Mandrake, Hemlock).

## 13. MVP Scope — Vertical Slices
Each slice is end-to-end, TDD'd, and shippable. MVP may be declared done at any slice ≥8.

| # | Slice | Proves |
|---|---|---|
| 0 | Walking skeleton: standalone proxy passes all traffic, emits `allow` Event → JSON log; arch tests + lefthook + CI wired; `git init` | the full pipe + engineering harness |
| 1 | Operator denylist → `block` (403) + fail2ban line | first verdict + fail2ban output |
| 2 | Honeypot tripwire → `confirmed` tier | first classifier signal |
| 3 | Labyrinth action for confirmed clients | content-generator port |
| 4 | Poison (Markov) fills the maze | dataset-corruption posture |
| 5 | PoW challenge + themeable page + WASM solver + token verify + no-JS fallback | the PoW tier |
| 6 | Bundled AI-crawler CIDR list (updatable) + verified-good-bot check | richer classification |
| 7 | Rate-based suspicion | behavioral signal |
| 8 | Prometheus `/metrics` sink + shipped fail2ban filter/jail | observability hardening |
| 9 | `net/http` middleware adapter | core is transport-agnostic |
| 10 | Caddy module (isolated) + sidecar/ForwardAuth docs for nginx/Traefik | all three form factors |
| 11 | Poison Garden reporter sink interface + disabled stub | federation seam, no debt |

Slices 0–8 = a complete standalone gateway (all three postures + observability).
9–11 complete the form factors and plant the federation seam.

## 14. Open Questions / Future Work
- Markov quality vs. cost; alternative poison strategies (templated plausible-but-wrong facts).
- Adaptive PoW difficulty under load.
- Canary/attribution to detect *which* crawler consumed poison.
- Dashboard store (stdlib ring buffer vs. accepting a pure-Go embedded DB in v2).
- Non-Go middleware (Python/Node) via the sidecar.

## 15. Proposed Directory Layout
```
henbane/
  cmd/henbane/
  internal/{core,ports,generate,pow,config,adapters/{proxy,middleware,sink},arch}
  caddy/                      # separate module
  themes/default/             # embedded default theme
  configs/crawlers.txt        # bundled crawler CIDR list
  deploy/{fail2ban/,docker/,systemd/}
  docs/design/
  .github/workflows/
  lefthook.yml
  .conform.yaml
  go.mod
```
