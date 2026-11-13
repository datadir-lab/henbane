// Package proxy is the standalone reverse-proxy adapter.
package proxy

import (
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
	rp     *httputil.ReverseProxy
}

// New builds a Handler proxying to upstream, consulting engine and fanning
// events to sinks.
func New(upstream *url.URL, engine ports.Engine, sinks []ports.Sink) *Handler {
	return &Handler{
		engine: engine,
		sinks:  sinks,
		rp:     httputil.NewSingleHostReverseProxy(upstream),
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
		// Slice 0 implements only ActionAllow; other actions arrive in later slices.
		h.rp.ServeHTTP(w, r)
	}
}

var _ http.Handler = (*Handler)(nil)
