package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

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
// the caller serves its Handler on the separate metrics listener.
func newHandler(cfg config.Config, logger *slog.Logger, fail2banW io.Writer, metricsReg *metrics.Registry) (http.Handler, error) {
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream %q: %w", cfg.Upstream, err)
	}
	if upstream.Scheme == "" || upstream.Host == "" {
		return nil, fmt.Errorf("invalid upstream %q: missing scheme or host", cfg.Upstream)
	}

	comps, err := assembly.Build(cfg)
	if err != nil {
		return nil, err
	}

	sinks := []ports.Sink{sink.NewSlogSink(logger)}
	if fail2banW != nil {
		sinks = append(sinks, sink.NewFail2banSink(fail2banW))
	}
	if metricsReg != nil {
		sinks = append(sinks, metricsReg)
	}

	var handler http.Handler = proxy.New(upstream, comps.Engine, sinks, logger, comps.Resolver, comps.Maze, comps.PoW, comps.Bomb)
	if cfg.Robots.Serve {
		handler = withRobots(buildRobots(cfg), handler)
	}
	return handler, nil
}

// buildRobots renders the robots.txt body: Disallow the honeypot trap (so
// well-behaved crawlers avoid it, and any client that fetches it is provably
// ignoring robots.txt) plus any operator-configured paths.
func buildRobots(cfg config.Config) string {
	var b strings.Builder
	b.WriteString("User-agent: *\n")
	if cfg.Honeypot.Enabled && cfg.Honeypot.Path != "" {
		b.WriteString("Disallow: " + cfg.Honeypot.Path + "\n")
	}
	for _, p := range cfg.Robots.Disallow {
		b.WriteString("Disallow: " + p + "\n")
	}
	return b.String()
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
