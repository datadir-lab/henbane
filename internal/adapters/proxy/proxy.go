// Package proxy is the standalone reverse-proxy adapter.
package proxy

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"

	"github.com/henbane-sh/henbane/internal/ports"
)

// requestView adapts *http.Request to ports.RequestView.
type requestView struct{ r *http.Request }

func (v requestView) IP() netip.Addr {
	host, _, err := net.SplitHostPort(v.r.RemoteAddr)
	if err != nil {
		host = v.r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}
func (v requestView) UserAgent() string         { return v.r.UserAgent() }
func (v requestView) Method() string            { return v.r.Method }
func (v requestView) Path() string              { return v.r.URL.Path }
func (v requestView) Header(name string) string { return v.r.Header.Get(name) }

// Handler is the reverse-proxy HTTP handler fronting an upstream.
type Handler struct {
	engine ports.Engine
	sinks  []ports.Sink
	logger *slog.Logger
	rp     *httputil.ReverseProxy
}

// New builds a Handler proxying to upstream, consulting engine and fanning
// events to sinks. Upstream transport errors are routed through logger
// (structured) instead of the stdlib default logger. logger must be non-nil.
func New(upstream *url.URL, engine ports.Engine, sinks []ports.Sink, logger *slog.Logger) *Handler {
	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.ErrorLog = slog.NewLogLogger(logger.Handler(), slog.LevelError)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("upstream proxy error", "err", err, "path", r.URL.Path)
		w.WriteHeader(http.StatusBadGateway)
	}
	return &Handler{
		engine: engine,
		sinks:  sinks,
		logger: logger,
		rp:     rp,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	verdict, events := h.engine.Decide(r.Context(), requestView{r: r})
	for _, e := range events {
		for _, s := range h.sinks {
			s.Emit(e)
		}
	}
	switch verdict.Action {
	case ports.ActionAllow:
		h.rp.ServeHTTP(w, r)
	default:
		// Fail closed. Only ActionAllow proxies to the upstream. Later slices
		// add explicit cases for challenge/tarpit/poison/block; until an action
		// has a handler, it must NOT silently pass traffic through — a bug that
		// left the engine returning a non-allow verdict here would otherwise
		// fail *open*. Respond 500 rather than serve the upstream.
		h.logger.Error("unhandled verdict action; failing closed",
			"action", verdict.Action.String(),
			"tier", verdict.Tier.String(),
			"path", r.URL.Path)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

var _ http.Handler = (*Handler)(nil)
