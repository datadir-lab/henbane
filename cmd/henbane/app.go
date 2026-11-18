package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/datadir-lab/henbane/internal/adapters/authz"
	"github.com/datadir-lab/henbane/internal/adapters/metrics"
	"github.com/datadir-lab/henbane/internal/adapters/proxy"
	"github.com/datadir-lab/henbane/internal/adapters/sink"
	"github.com/datadir-lab/henbane/internal/assembly"
	"github.com/datadir-lab/henbane/internal/config"
	"github.com/datadir-lab/henbane/internal/ports"
)

// newHandler wires config into the shared components, sinks, and proxy adapter.
// If fail2banW is non-nil a fail2ban sink writing to it is added; the caller
// owns that writer's lifecycle. If metricsReg is non-nil it is added as a sink;
// the caller serves its Handler on the separate metrics listener. It also returns
// any background tasks (e.g. the federation feed refresher) the caller must run.
func newHandler(cfg config.Config, logger *slog.Logger, fail2banW io.Writer, metricsReg *metrics.Registry) (http.Handler, []func(context.Context), error) {
	// Federation consumer + reporter (each optional) plus their background tasks.
	fed, err := assembly.Federation(cfg, logger)
	if err != nil {
		return nil, nil, err
	}

	extra := fed.Detectors
	if wba := assembly.WebBotAuth(cfg, logger); wba != nil {
		extra = append(extra, wba)
	}

	comps, err := assembly.Build(cfg, extra...)
	if err != nil {
		return nil, nil, err
	}

	sinks := []ports.Sink{sink.NewSlogSink(logger)}
	if fail2banW != nil {
		sinks = append(sinks, sink.NewFail2banSink(fail2banW))
	}
	if metricsReg != nil {
		sinks = append(sinks, metricsReg)
	}
	sinks = append(sinks, fed.Sinks...)

	handler, err := buildServeHandler(cfg, comps, sinks, logger)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Robots.Serve {
		handler = withRobots(buildRobots(cfg), handler)
	}
	return handler, fed.Background, nil
}

// buildServeHandler selects the form factor: a ForwardAuth/auth_request sidecar
// for an existing nginx/Traefik front proxy (no upstream), or the standalone
// reverse proxy. Both run the same decision pipeline; only the "allowed" action
// differs — 204 for the front proxy to proceed, vs. proxying to upstream.
func buildServeHandler(cfg config.Config, comps assembly.Components, sinks []ports.Sink, logger *slog.Logger) (http.Handler, error) {
	if cfg.Sidecar.Enabled {
		gate := proxy.NewGate(comps.Engine, sinks, logger, comps.Resolver, comps.Maze, comps.PoW, comps.Bomb).
			WithObserve(cfg.Observe)
		allow := gate.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		return authz.New(allow, comps.PoW.VerifyPath), nil
	}
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream %q: %w", cfg.Upstream, err)
	}
	if upstream.Scheme == "" || upstream.Host == "" {
		return nil, fmt.Errorf("invalid upstream %q: missing scheme or host", cfg.Upstream)
	}
	return proxy.New(upstream, comps.Engine, sinks, logger, comps.Resolver, comps.Maze, comps.PoW, comps.Bomb).
		WithObserve(cfg.Observe), nil
}

// buildRobots renders the robots.txt body: Disallow the honeypot trap (so
// well-behaved crawlers avoid it, and any client that fetches it is provably
// ignoring robots.txt) plus any operator-configured paths.
func buildRobots(cfg config.Config) string {
	var b strings.Builder
	b.WriteString("User-agent: *\n")
	if u := cfg.Robots.AIUsage; u != nil {
		writeAIUsage(&b, u)
	}
	if cfg.Honeypot.Enabled && cfg.Honeypot.Path != "" {
		b.WriteString("Disallow: " + cfg.Honeypot.Path + "\n")
	}
	for _, p := range cfg.Robots.Disallow {
		b.WriteString("Disallow: " + p + "\n")
	}
	return b.String()
}

// writeAIUsage emits the operator's AI-usage preferences in both the Cloudflare
// Content-signal syntax (search=yes, ai-train=no) and the IETF AIPREF Content-Usage
// syntax (train-ai=n, y/n values). The two are independent ecosystems, so emitting both
// reaches the widest set of crawlers. Unset preferences are omitted from both.
func writeAIUsage(b *strings.Builder, u *config.AIUsage) {
	var cf []string
	if u.Search != nil {
		cf = append(cf, "search="+yesNo(*u.Search))
	}
	if u.AIInput != nil {
		cf = append(cf, "ai-input="+yesNo(*u.AIInput))
	}
	if u.Train != nil {
		cf = append(cf, "ai-train="+yesNo(*u.Train))
	}
	if len(cf) > 0 {
		b.WriteString("Content-signal: " + strings.Join(cf, ", ") + "\n")
	}
	// AIPREF's vocabulary covers training and search (not a live-input token), one line each.
	if u.Train != nil {
		b.WriteString("Content-Usage: train-ai=" + yN(*u.Train) + "\n")
	}
	if u.Search != nil {
		b.WriteString("Content-Usage: search=" + yN(*u.Search) + "\n")
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func yN(b bool) string {
	if b {
		return "y"
	}
	return "n"
}

// withRobots serves body at /robots.txt and delegates everything else to next.
func withRobots(body string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, body)
			return
		}
		next.ServeHTTP(w, r)
	})
}
