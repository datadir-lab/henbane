// Package authz adapts Henbane's decision gate into a ForwardAuth / auth_request
// endpoint, so Henbane can protect an existing nginx or Traefik front proxy
// instead of running as a reverse proxy.
//
// The front proxy sends each inbound request to Henbane's auth endpoint. Henbane
// reconstructs the original request from the forwarded headers (the auth
// subrequest's own path/method are the endpoint's, not the client's), runs the
// full decision pipeline, and answers:
//
//   - 204 No Content — allow; the front proxy serves the real backend.
//   - a non-2xx deny carrying the challenge page / maze / 403 as its body.
//
// Traefik forwards a non-2xx auth response (status + body) straight to the
// client, so the challenge and maze render directly. nginx's auth_request reads
// only the status, so for nginx the body is surfaced with an `error_page` recipe
// (see the deployment docs). The PoW session cookie round-trips through either
// front proxy on subsequent requests, so the challenge flow works end to end
// once the verify path is routed to Henbane.
package authz

import (
	"net/http"
	"net/url"
	"strings"
)

// New wraps a decision gate as a ForwardAuth/auth_request handler. gate must
// answer 204 for an allowed request and render the challenge/maze/403 otherwise
// (i.e. proxy.Handler.Wrap with a 204 "allowed" handler). verifyPath, when
// non-empty, is the PoW solution endpoint: it is passed through unchanged so its
// response (which sets the session cookie) is not rewritten into a deny.
func New(gate http.Handler, verifyPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reconstruct(r)
		if verifyPath != "" && r.URL.Path == verifyPath {
			gate.ServeHTTP(w, r)
			return
		}
		gate.ServeHTTP(&authWriter{ResponseWriter: w, denyStatus: http.StatusForbidden}, r)
	})
}

// reconstruct rewrites the auth subrequest in place to reflect the original
// client request, using the headers nginx and Traefik forward. The auth endpoint
// must only be reachable by the trusted front proxy (bind it to the internal
// network); these headers are otherwise attacker-controlled, so parsing is
// strict and failures leave the subrequest's own values untouched.
func reconstruct(r *http.Request) {
	if raw := firstHeader(r, "X-Forwarded-Uri", "X-Original-Uri", "X-Original-Url"); raw != "" {
		if u, err := url.ParseRequestURI(raw); err == nil {
			r.URL.Path = u.Path
			r.URL.RawQuery = u.RawQuery
		}
	}
	if m := sanitizeMethod(firstHeader(r, "X-Forwarded-Method", "X-Original-Method")); m != "" {
		r.Method = m
	}
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		r.Host = h
	}
}

func firstHeader(r *http.Request, names ...string) string {
	for _, n := range names {
		if v := r.Header.Get(n); v != "" {
			return v
		}
	}
	return ""
}

// sanitizeMethod accepts only a short, all-letter HTTP method token, so a
// forwarded header can't inject arbitrary bytes into the decision or the logs.
// Anything else returns "" (the subrequest's own method is kept).
func sanitizeMethod(m string) string {
	if m == "" || len(m) > 16 {
		return ""
	}
	for i := 0; i < len(m); i++ {
		if c := m[i]; (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return ""
		}
	}
	return strings.ToUpper(m)
}

// authWriter adapts gate responses to ForwardAuth/auth_request semantics. The
// gate writes 204 only for an allowed request; any other 2xx it writes (a 200
// challenge page or maze) must become a non-2xx deny, or the front proxy would
// read it as a grant and forward to the real backend. The body is preserved so
// Traefik can return the challenge/maze to the client. Non-2xx statuses (the 403
// block) pass through unchanged.
type authWriter struct {
	http.ResponseWriter
	denyStatus  int
	wroteHeader bool
}

func (aw *authWriter) WriteHeader(code int) {
	if aw.wroteHeader {
		return
	}
	aw.wroteHeader = true
	if code >= 200 && code < 300 && code != http.StatusNoContent {
		code = aw.denyStatus
	}
	aw.ResponseWriter.WriteHeader(code)
}

func (aw *authWriter) Write(b []byte) (int, error) {
	if !aw.wroteHeader {
		aw.WriteHeader(http.StatusOK)
	}
	return aw.ResponseWriter.Write(b)
}

var _ http.ResponseWriter = (*authWriter)(nil)
