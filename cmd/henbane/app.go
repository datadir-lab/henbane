package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/henbane-sh/henbane/internal/adapters/proxy"
	"github.com/henbane-sh/henbane/internal/adapters/sink"
	"github.com/henbane-sh/henbane/internal/config"
	"github.com/henbane-sh/henbane/internal/core"
	"github.com/henbane-sh/henbane/internal/ports"
)

// newHandler wires config into the engine, sinks, and proxy adapter.
func newHandler(cfg config.Config, logger *slog.Logger) (http.Handler, error) {
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		return nil, fmt.Errorf("invalid upstream %q", cfg.Upstream)
	}
	engine := core.NewEngine()
	sinks := []ports.Sink{sink.NewSlogSink(logger)}
	return proxy.New(upstream, engine, sinks), nil
}
