// Package proxy is the standalone reverse-proxy adapter.
package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"

	"github.com/datadir-lab/henbane/internal/clientip"
	"github.com/datadir-lab/henbane/internal/ports"
)

// MazeWriter writes a labyrinth page for a request path.
type MazeWriter interface {
	WritePage(w io.Writer, path string) error
}

// Challenger gates requests behind proof-of-work. A nil Challenger disables PoW.
type Challenger interface {
	HasValidToken(r *http.Request, ip netip.Addr) bool
	ServeChallenge(w http.ResponseWriter, r *http.Request, ip netip.Addr)
	Verify(w http.ResponseWriter, r *http.Request, ip netip.Addr)
}

// PoW configures the proof-of-work gate. A nil Challenger disables it.
type PoW struct {
	Challenger   Challenger
	VerifyPath   string
	ChallengeAll bool // "challenge everyone": every un-authed request is challenged
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
	pow      PoW
	rp       *httputil.ReverseProxy
}

// New builds a Handler proxying to upstream, consulting engine and fanning
// events to sinks. resolver determines the client IP; logger must be non-nil.
// maze serves the labyrinth page on a tarpit verdict; pow (if its Challenger is
// non-nil) gates requests behind proof-of-work.
func New(upstream *url.URL, engine ports.Engine, sinks []ports.Sink, logger *slog.Logger, resolver *clientip.Resolver, maze MazeWriter, pow PoW) *Handler {
	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.ErrorLog = slog.NewLogLogger(logger.Handler(), slog.LevelError)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("upstream proxy error", "err", err, "path", r.URL.Path)
		w.WriteHeader(http.StatusBadGateway)
	}
	return &Handler{engine: engine, sinks: sinks, logger: logger, resolver: resolver, maze: maze, pow: pow, rp: rp}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := h.resolver.ClientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"))

	// The verify endpoint is PoW machinery, handled before any engine logic.
	if h.pow.Challenger != nil && r.URL.Path == h.pow.VerifyPath {
		h.pow.Challenger.Verify(w, r, ip)
		return
	}

	verdict, events := h.engine.Decide(r.Context(), requestView{r: r, resolver: h.resolver})
	for _, e := range events {
		for _, s := range h.sinks {
			s.Emit(e)
		}
	}

	// Proof-of-work layers over the verdict: a solved token clears a challenge,
	// and "challenge everyone" mode turns an otherwise-allowed, un-authed request
	// into a challenge. Block/Tarpit (confirmed-hostile) are never reinterpreted.
	action := verdict.Action
	if h.pow.Challenger != nil {
		authed := h.pow.Challenger.HasValidToken(r, ip)
		switch {
		case authed && action == ports.ActionChallenge:
			action = ports.ActionAllow
		case !authed && action == ports.ActionAllow && h.pow.ChallengeAll:
			action = ports.ActionChallenge
		}
	}

	switch action {
	case ports.ActionAllow:
		h.rp.ServeHTTP(w, r)
	case ports.ActionChallenge:
		if h.pow.Challenger == nil {
			h.failClosed(w, r, verdict) // Challenge with no configured gate
			return
		}
		h.pow.Challenger.ServeChallenge(w, r, ip)
	case ports.ActionBlock:
		http.Error(w, "forbidden", http.StatusForbidden)
	case ports.ActionTarpit:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.maze.WritePage(w, r.URL.Path); err != nil {
			h.logger.Error("labyrinth write failed", "err", err, "path", r.URL.Path)
		}
	default:
		h.failClosed(w, r, verdict)
	}
}

// failClosed refuses traffic for any action without a handler, rather than
// passing it through to the upstream.
func (h *Handler) failClosed(w http.ResponseWriter, r *http.Request, v ports.Verdict) {
	h.logger.Error("unhandled verdict action; failing closed",
		"action", v.Action.String(), "tier", v.Tier.String(), "path", r.URL.Path)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

var _ http.Handler = (*Handler)(nil)
