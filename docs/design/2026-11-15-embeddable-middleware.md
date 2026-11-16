# Embeddable middleware

## Goal

Ship Henbane as a Go library a developer can drop into their own `net/http`
server. This is the second of the three form factors (standalone proxy, embeddable
middleware, Caddy/nginx plugin). Adoption is the strategy's moat: more sites
running Henbane means more imposed crawler cost and the only path to poison
mattering at scale.

## API (researched against the ecosystem)

The Go middleware consensus (`justinas/alice`, `go-chi`, and especially
`unrolled/secure`, the closest analog, a security middleware) is:

- The wrapper type is `func(http.Handler) http.Handler`.
- Construct a configured instance with `New(opts)`, then expose a `.Handler(next)`
  **method** that *is* that wrapper. Features off by default. On a violation the
  middleware handles the response instead of calling `next`.
- Config via a struct when it is file/YAML-backed and large (Henbane's `Config`);
  functional options for the few runtime knobs (logger, extra sinks).

So the public `github.com/datadir-lab/henbane` package is:

```go
type Config = config.Config                 // re-exported; zero value is passive

func New(cfg Config, opts ...Option) (*Henbane, error)
func (h *Henbane) Handler(next http.Handler) http.Handler   // chi/alice/net-http
func (h *Henbane) MetricsHandler() http.Handler

func WithLogger(*slog.Logger) Option        // silent by default
func WithFail2banLog(io.Writer) Option
```

One `*Henbane` holds the shared, stateful protection pieces (PoW gate, flag
stores, rate counters, metrics), so callers build it once and reuse it. Marked
**v0/experimental** so we are not semver-locked while the surface settles.

The `Config` alias exposes the struct but not its internal nested field types, so
external callers set nested fields by assignment (`cfg.Honeypot.Enabled = true`)
rather than composite literals. Acceptable for v0; a hand-tailored public config
is a later option if the ergonomics warrant it.

## Internal refactor (no behavior change)

The two form factors must run the *same* decision logic. Duplicating security
dispatch would be a drift hazard. So:

1. **Shared gate.** The proxy's `ServeHTTP` body moved into `serve(w, r, origin)`,
   where `origin` is the handler for an *allowed* request. `New(upstream,…)` is
   unchanged (origin = the reverse proxy); a new `NewGate(…)` + `Wrap(next)`
   supply the origin per call (origin = the host handler). Existing proxy tests
   are untouched.
2. **Shared assembly.** The config→components wiring (detectors, engine, maze,
   PoW, bomb) moved from `package main` into `internal/assembly`, imported by both
   the CLI and the library. The CLI (`cmd/henbane`) is now a thin user of it.
3. **Shared validation.** `config.Validate(cfg)` was extracted from `Parse` so the
   library rejects the same bad config as the CLI (minus CLI-only checks:
   `upstream` required, `metrics.listen != listen`).

The public package is a facade over internal packages (allowed within the module);
nothing new is exported beyond the four functions above.

## Scope / non-goals

- No framework-specific adapters beyond the universal `func(http.Handler)
  http.Handler` (which already covers chi, alice, and net/http). Gin/echo users
  wrap with their framework's bridge, as with any such middleware.
- No public, hand-tailored config type yet (the alias suffices for v0).
- The Caddy/nginx form factor remains future work.
