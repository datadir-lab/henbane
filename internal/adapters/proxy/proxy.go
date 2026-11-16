// Package proxy is the standalone reverse-proxy adapter.
package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"

	"github.com/datadir-lab/henbane/h2fp"
	"github.com/datadir-lab/henbane/internal/clientip"
	"github.com/datadir-lab/henbane/internal/ports"
	"github.com/datadir-lab/henbane/tlsfp"
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

// BombWriter streams a gzip decompression bomb for a request path.
type BombWriter interface {
	WriteGzip(w io.Writer, path string) error
}

// Bomb configures the decompression-bomb response. A nil Writer disables it. It
// fires only for a client that advertised Accept-Encoding: gzip, and only on the
// opted-in tier(s); otherwise the normal maze/403 is served.
type Bomb struct {
	Writer      BombWriter
	OnConfirmed bool // replace the Tarpit maze with a bomb
	OnBlocked   bool // replace the 403 with a bomb
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

// TLSFingerprint implements ports.TLSFingerprinter: the client's coarse TLS
// fingerprint, captured during the handshake when Henbane terminates TLS (""
// otherwise).
func (v requestView) TLSFingerprint() string { return tlsfp.FromContext(v.r.Context()) }

// H2Fingerprint implements ports.H2Fingerprinter: the client's Akamai-style HTTP/2
// fingerprint, captured by the optional h2capture module when Henbane terminates
// the client's HTTP/2 connection ("" otherwise — plain HTTP/1.1, behind a proxy,
// or without the capture module wired).
func (v requestView) H2Fingerprint() string { return h2fp.FromContext(v.r.Context()) }

// Host exposes the request authority (for RFC 9421 @authority); the Web Bot Auth
// detector reads it through an optional interface.
func (v requestView) Host() string { return v.r.Host }

// HTTPMajorVersion implements ports.ProtocolViewer: the client connection's HTTP
// major version (1 or 2). Consistency scoring uses it to flag a client that
// claims a modern browser but speaks HTTP/1.1. It reflects the hop into Henbane,
// so it is only meaningful when Henbane terminates the client connection.
func (v requestView) HTTPMajorVersion() int { return v.r.ProtoMajor }

// Handler runs the decision pipeline and dispatches each verdict. An allowed
// request is served by origin — the upstream reverse proxy for the standalone
// form factor, or (via Wrap) the host application for the middleware form
// factor. All other verdicts are challenged, tarpitted, or blocked here.
type Handler struct {
	engine   ports.Engine
	sinks    []ports.Sink
	logger   *slog.Logger
	resolver *clientip.Resolver
	maze     MazeWriter
	pow      PoW
	bomb     Bomb
	origin   http.Handler
	observe  bool
}

// WithObserve enables observe (dry-run) mode: the full decision pipeline runs and
// the verdict it WOULD take is recorded on each Event (with Observed=true), but no
// request is challenged, tarpitted, or blocked — every request is served normally.
// It lets an operator measure impact on real traffic before enforcing. Returns the
// handler for chaining.
func (h *Handler) WithObserve(observe bool) *Handler {
	h.observe = observe
	return h
}

// New builds a Handler proxying to upstream, consulting engine and fanning events
// to sinks. resolver determines the client IP; logger must be non-nil. maze serves
// the labyrinth on a tarpit verdict; pow gates requests behind proof-of-work; bomb
// (if its Writer is non-nil) replaces the opted-in tier's response with a gzip bomb.
func New(upstream *url.URL, engine ports.Engine, sinks []ports.Sink, logger *slog.Logger, resolver *clientip.Resolver, maze MazeWriter, pow PoW, bomb Bomb) *Handler {
	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.ErrorLog = slog.NewLogLogger(logger.Handler(), slog.LevelError)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("upstream proxy error", "err", err, "path", r.URL.Path)
		w.WriteHeader(http.StatusBadGateway)
	}
	return &Handler{engine: engine, sinks: sinks, logger: logger, resolver: resolver, maze: maze, pow: pow, bomb: bomb, origin: rp}
}

// NewGate builds a Handler with no fixed origin, meant to be used through Wrap:
// each Wrap call supplies the "allowed" handler (the host application). It is the
// embeddable-middleware form factor of New — same decision pipeline, but an
// allowed request falls through to the wrapped handler instead of a reverse
// proxy. The returned Handler's ServeHTTP responds 404 (there is no upstream);
// callers are expected to use Wrap, not mount it directly.
func NewGate(engine ports.Engine, sinks []ports.Sink, logger *slog.Logger, resolver *clientip.Resolver, maze MazeWriter, pow PoW, bomb Bomb) *Handler {
	return &Handler{engine: engine, sinks: sinks, logger: logger, resolver: resolver, maze: maze, pow: pow, bomb: bomb,
		origin: http.HandlerFunc(http.NotFound)}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, h.origin)
}

// Wrap returns middleware that runs the full decision pipeline and, for an
// allowed request, delegates to next. Every Handler returned by Wrap shares this
// Handler's engine, PoW gate, flag stores, and sinks, so protection state is
// consistent across all wrapped routes.
func (h *Handler) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.serve(w, r, next)
	})
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request, origin http.Handler) {
	ip := h.resolver.ClientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"))

	// The verify endpoint is PoW machinery, handled before any engine logic.
	if h.pow.Challenger != nil && r.URL.Path == h.pow.VerifyPath {
		h.pow.Challenger.Verify(w, r, ip)
		return
	}

	verdict, events := h.engine.Decide(r.Context(), requestView{r: r, resolver: h.resolver})

	// Proof-of-work layers over the verdict: a solved token clears a challenge,
	// and "challenge everyone" mode turns an otherwise-allowed, un-authed request
	// into a challenge. Block/Tarpit (confirmed-hostile) are never reinterpreted.
	action := verdict.Action
	if h.pow.Challenger != nil {
		authed := h.pow.Challenger.HasValidToken(r, ip)
		switch {
		case authed && action == ports.ActionChallenge:
			action = ports.ActionAllow
		case !authed && action == ports.ActionAllow && h.pow.ChallengeAll && !verdict.Allowlisted:
			action = ports.ActionChallenge
		}
	}

	// Emit the SERVED action (after PoW layering), so logs and metrics record what
	// the client actually got — not the pre-layering classifier verdict. In observe
	// mode Action is the action that WOULD have been taken (Observed=true), but the
	// request is still served normally below.
	for i := range events {
		events[i].Action = action
		events[i].Observed = h.observe
		for _, s := range h.sinks {
			s.Emit(events[i])
		}
	}

	if h.observe {
		// Observe (dry-run): record the would-be verdict above, but act on nothing.
		origin.ServeHTTP(w, r)
		return
	}

	switch action {
	case ports.ActionAllow:
		origin.ServeHTTP(w, r)
	case ports.ActionChallenge:
		if h.pow.Challenger == nil {
			h.failClosed(w, r, verdict) // Challenge with no configured gate
			return
		}
		h.pow.Challenger.ServeChallenge(w, r, ip)
	case ports.ActionBlock:
		if h.serveBombIf(w, r, h.bomb.OnBlocked) {
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	case ports.ActionTarpit:
		if h.serveBombIf(w, r, h.bomb.OnConfirmed) {
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.maze.WritePage(w, r.URL.Path); err != nil {
			h.logger.Error("labyrinth write failed", "err", err, "path", r.URL.Path)
		}
	default:
		h.failClosed(w, r, verdict)
	}
}

// serveBombIf streams the decompression bomb when it is enabled, opted in for this
// tier (triggered), and the client advertised gzip. It reports whether it handled
// the response.
func (h *Handler) serveBombIf(w http.ResponseWriter, r *http.Request, triggered bool) bool {
	if h.bomb.Writer == nil || !triggered || !acceptsGzip(r) {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Encoding", "gzip")
	if err := h.bomb.Writer.WriteGzip(w, r.URL.Path); err != nil {
		h.logger.Error("bomb write failed", "err", err, "path", r.URL.Path)
	}
	return true
}

func acceptsGzip(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
}

// failClosed refuses traffic for any action without a handler, rather than passing
// it through to the upstream.
func (h *Handler) failClosed(w http.ResponseWriter, r *http.Request, v ports.Verdict) {
	h.logger.Error("unhandled verdict action; failing closed",
		"action", v.Action.String(), "tier", v.Tier.String(), "path", r.URL.Path)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

var _ http.Handler = (*Handler)(nil)
