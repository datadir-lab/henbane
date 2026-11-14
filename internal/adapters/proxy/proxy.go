// Package proxy is the standalone reverse-proxy adapter.
package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"

	"github.com/henbane-sh/henbane/internal/clientip"
	"github.com/henbane-sh/henbane/internal/ports"
)

// MazeWriter writes a labyrinth page for a request path.
type MazeWriter interface {
	WritePage(w io.Writer, path string) error
}

// requestView adapts *http.Request to ports.RequestView, resolving the client
// IP through the trusted-proxy resolver.
type requestView struct {
	r        *http.Request
	resolver *clientip.Resolver
}

func (v requestView) IP() netip.Addr {
	return v.resolver.ClientIP(v.r.RemoteAddr, v.r.Header.Values("X-Forwarded-For"))
}
func (v requestView) UserAgent() string         { return v.r.UserAgent() }
func (v requestView) Method() string            { return v.r.Method }
func (v requestView) Path() string              { return v.r.URL.Path }
func (v requestView) Header(name string) string { return v.r.Header.Get(name) }

// Handler is the reverse-proxy HTTP handler fronting an upstream.
type Handler struct {
	engine   ports.Engine
	sinks    []ports.Sink
	logger   *slog.Logger
	resolver *clientip.Resolver
	maze     MazeWriter
	rp       *httputil.ReverseProxy
}

// New builds a Handler proxying to upstream, consulting engine and fanning
// events to sinks. resolver determines the client IP; logger must be non-nil.
// maze serves the labyrinth page on a tarpit verdict.
func New(upstream *url.URL, engine ports.Engine, sinks []ports.Sink, logger *slog.Logger, resolver *clientip.Resolver, maze MazeWriter) *Handler {
	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.ErrorLog = slog.NewLogLogger(logger.Handler(), slog.LevelError)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("upstream proxy error", "err", err, "path", r.URL.Path)
		w.WriteHeader(http.StatusBadGateway)
	}
	return &Handler{engine: engine, sinks: sinks, logger: logger, resolver: resolver, maze: maze, rp: rp}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	verdict, events := h.engine.Decide(r.Context(), requestView{r: r, resolver: h.resolver})
	for _, e := range events {
		for _, s := range h.sinks {
			s.Emit(e)
		}
	}
	switch verdict.Action {
	case ports.ActionAllow:
		h.rp.ServeHTTP(w, r)
	case ports.ActionBlock:
		http.Error(w, "forbidden", http.StatusForbidden)
	case ports.ActionTarpit:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.maze.WritePage(w, r.URL.Path); err != nil {
			h.logger.Error("labyrinth write failed", "err", err, "path", r.URL.Path)
		}
	default:
		// Fail closed: actions without a handler yet (challenge/poison,
		// added in later slices) must NOT pass traffic through.
		h.logger.Error("unhandled verdict action; failing closed",
			"action", verdict.Action.String(),
			"tier", verdict.Tier.String(),
			"path", r.URL.Path)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

var _ http.Handler = (*Handler)(nil)
