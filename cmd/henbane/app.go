package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/henbane-sh/henbane/internal/adapters/proxy"
	"github.com/henbane-sh/henbane/internal/adapters/sink"
	"github.com/henbane-sh/henbane/internal/clientip"
	"github.com/henbane-sh/henbane/internal/config"
	"github.com/henbane-sh/henbane/internal/core"
	"github.com/henbane-sh/henbane/internal/detect/denylist"
	"github.com/henbane-sh/henbane/internal/ports"
)

// newHandler wires config into the resolver, engine, sinks, and proxy adapter.
// If fail2banW is non-nil a fail2ban sink writing to it is added; the caller
// owns that writer's lifecycle (opening and closing it).
func newHandler(cfg config.Config, logger *slog.Logger, fail2banW io.Writer) (http.Handler, error) {
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream %q: %w", cfg.Upstream, err)
	}
	if upstream.Scheme == "" || upstream.Host == "" {
		return nil, fmt.Errorf("invalid upstream %q: missing scheme or host", cfg.Upstream)
	}

	trusted, err := cfg.TrustedPrefixes()
	if err != nil {
		return nil, err
	}
	denyCIDRs, err := cfg.DenyPrefixes()
	if err != nil {
		return nil, err
	}

	var detectors []ports.Detector
	if len(denyCIDRs) > 0 {
		detectors = append(detectors, denylist.NewIP(denyCIDRs))
	}
	if len(cfg.Deny.UserAgents) > 0 {
		detectors = append(detectors, denylist.NewUA(cfg.Deny.UserAgents))
	}

	engine := core.NewEngine(detectors...)
	resolver := clientip.NewResolver(trusted)

	sinks := []ports.Sink{sink.NewSlogSink(logger)}
	if fail2banW != nil {
		sinks = append(sinks, sink.NewFail2banSink(fail2banW))
	}

	return proxy.New(upstream, engine, sinks, logger, resolver), nil
}
