package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"

	"github.com/henbane-sh/henbane/internal/adapters/proxy"
	"github.com/henbane-sh/henbane/internal/adapters/sink"
	"github.com/henbane-sh/henbane/internal/clientip"
	"github.com/henbane-sh/henbane/internal/config"
	"github.com/henbane-sh/henbane/internal/core"
	"github.com/henbane-sh/henbane/internal/ports"
)

// newHandler wires config into the resolver, engine, sinks, and proxy adapter.
func newHandler(cfg config.Config, logger *slog.Logger) (http.Handler, error) {
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

	engine := core.NewEngine(core.Policy{
		DenyCIDRs:      denyCIDRs,
		DenyUserAgents: cfg.Deny.UserAgents,
	})
	resolver := clientip.NewResolver(trusted)

	sinks := []ports.Sink{sink.NewSlogSink(logger)}
	if cfg.Sinks.Fail2ban.Enabled {
		f, err := os.OpenFile(cfg.Sinks.Fail2ban.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open fail2ban log %q: %w", cfg.Sinks.Fail2ban.Path, err)
		}
		sinks = append(sinks, sink.NewFail2banSink(f))
	}

	return proxy.New(upstream, engine, sinks, logger, resolver), nil
}
