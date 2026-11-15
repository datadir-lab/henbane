// Package henbane is the embeddable form of the Henbane anti-AI-scraper gateway.
// It wraps any http.Handler with the same classifier, proof-of-work gate,
// labyrinth, poison, and decompression-bomb machinery the standalone proxy runs:
// requests it allows fall through to your handler; suspect, confirmed, and
// blocked requests are challenged, tarpitted, or blocked before your code runs.
//
//	hb, err := henbane.New(cfg, henbane.WithLogger(log))
//	if err != nil { ... }
//	mux.Handle("/", hb.Handler(app))        // net/http
//	r.Use(hb.Handler)                        // chi / alice (func(http.Handler) http.Handler)
//	adminMux.Handle("/metrics", hb.MetricsHandler())
//
// STABILITY: this package is v0 and EXPERIMENTAL — its API may change before a
// tagged 1.0. The internal engine it drives is the same one the CLI ships.
package henbane

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/datadir-lab/henbane/internal/adapters/metrics"
	"github.com/datadir-lab/henbane/internal/adapters/proxy"
	"github.com/datadir-lab/henbane/internal/adapters/sink"
	"github.com/datadir-lab/henbane/internal/assembly"
	"github.com/datadir-lab/henbane/internal/config"
	"github.com/datadir-lab/henbane/internal/ports"
)

// Config is the Henbane configuration. Build it directly (it is a plain struct)
// or load YAML into it with your own loader; the zero value is a usable, fully
// passive configuration (every posture is off by default).
type Config = config.Config

// Henbane is a configured protection instance. Build one with New, then wrap
// your handlers with Handler. A single Henbane is safe for concurrent use and
// holds the shared protection state (PoW gate, flag stores, rate counters), so
// create ONE and reuse it across all routes rather than one per route.
type Henbane struct {
	gate       *proxy.Handler
	metrics    *metrics.Registry
	background []func(context.Context)
	startOnce  sync.Once
}

type options struct {
	logger    *slog.Logger
	fail2banW io.Writer
}

// Option configures a Henbane instance.
type Option func(*options)

// WithLogger routes Henbane's decision events to l. Without it, events are not
// logged (the Prometheus counters from MetricsHandler still record every one).
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithFail2banLog adds a fail2ban ban-line sink writing to w (typically an open
// log file that fail2ban tails). The caller owns w's lifecycle.
func WithFail2banLog(w io.Writer) Option {
	return func(o *options) { o.fail2banW = w }
}

// LoadConfig reads and validates a Henbane YAML config file — the same file the
// standalone binary reads. An empty path returns the default (passive) config.
// Use it to configure New from a file instead of building Config in code.
func LoadConfig(path string) (Config, error) {
	cfg, err := config.LoadFile(path)
	if err != nil {
		return Config{}, err
	}
	if err := config.Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// New builds a Henbane from cfg. It validates cfg and assembles the detectors,
// engine, maze, PoW gate, and bomb, returning an error for any invalid config
// (unknown poison strategy, bad CIDR, suspect velocity without a PoW gate, …).
func New(cfg Config, opts ...Option) (*Henbane, error) {
	o := options{logger: slog.New(slog.NewTextHandler(io.Discard, nil))} // silent by default
	for _, opt := range opts {
		opt(&o)
	}
	if err := config.Validate(cfg); err != nil {
		return nil, err
	}
	fed, err := assembly.Federation(cfg, o.logger)
	if err != nil {
		return nil, err
	}
	comps, err := assembly.Build(cfg, fed.Detectors...)
	if err != nil {
		return nil, err
	}
	reg := metrics.New()
	sinks := []ports.Sink{sink.NewSlogSink(o.logger), reg}
	if o.fail2banW != nil {
		sinks = append(sinks, sink.NewFail2banSink(o.fail2banW))
	}
	sinks = append(sinks, fed.Sinks...)
	gate := proxy.NewGate(comps.Engine, sinks, o.logger, comps.Resolver, comps.Maze, comps.PoW, comps.Bomb)
	return &Henbane{gate: gate, metrics: reg, background: fed.Background}, nil
}

// Start activates Henbane's background tasks — the federation feed refresher and
// the reporter flusher — under ctx. Call it once, with a context tied to your
// server's lifetime; cancelling the context stops the tasks (and flushes any
// pending reports). It is optional and idempotent: without it Henbane still
// classifies every request, but federation (if configured) stays passive. If no
// federation is configured, Start does nothing.
func (h *Henbane) Start(ctx context.Context) {
	h.startOnce.Do(func() {
		for _, task := range h.background {
			go task(ctx)
		}
	})
}

// Handler wraps next with Henbane's protection. Its type is
// func(http.Handler) http.Handler, so it drops straight into chi's Use, alice,
// or any router that consumes that shape; with net/http pass your handler
// directly: hb.Handler(mux).
func (h *Henbane) Handler(next http.Handler) http.Handler {
	return h.gate.Wrap(next)
}

// MetricsHandler serves Henbane's Prometheus counters. Mount it on a private
// endpoint — it carries aggregate operational data (no per-user labels), but it
// still should not be exposed on the same public surface as your application.
func (h *Henbane) MetricsHandler() http.Handler {
	return h.metrics.Handler()
}
