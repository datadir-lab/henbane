package authz

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const verifyPath = "/.henbane/verify"

// fakeGate stands in for proxy.Handler.Wrap(204): it answers 204 for an allowed
// request, a 200 HTML maze for a tarpit, a 403 for a block, and a 200 cookie for
// the verify endpoint — so the adapter's status/path handling can be checked
// without building a full engine. It records the request it saw.
func fakeGate(seen *http.Request) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = *r
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusNoContent) // allow
		case "/trap":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, "<html>maze</html>") // defaults to 200
		case "/bad":
			http.Error(w, "forbidden", http.StatusForbidden) // block
		case verifyPath:
			http.SetCookie(w, &http.Cookie{Name: "hb", Value: "token"})
			_, _ = io.WriteString(w, "verified") // 200 + cookie
		default:
			http.NotFound(w, r)
		}
	})
}

func authReq(fwdURI string) *http.Request {
	r := httptest.NewRequest("GET", "/auth", nil) // the auth endpoint's own path
	if fwdURI != "" {
		r.Header.Set("X-Forwarded-Uri", fwdURI)
	}
	return r
}

func TestAllowReturns204(t *testing.T) {
	var seen http.Request
	h := New(fakeGate(&seen), verifyPath)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq("/ok"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("allow status = %d, want 204", w.Code)
	}
	if seen.URL.Path != "/ok" {
		t.Errorf("gate saw path %q, want the reconstructed /ok", seen.URL.Path)
	}
}

func TestTarpitBodyBecomesNon2xxDeny(t *testing.T) {
	var seen http.Request
	h := New(fakeGate(&seen), verifyPath)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq("/trap"))
	// A 200 maze would read as "allow" to the front proxy; it must become a deny.
	if w.Code != http.StatusForbidden {
		t.Fatalf("tarpit status = %d, want 403 (remapped from 200)", w.Code)
	}
	if w.Body.String() != "<html>maze</html>" {
		t.Errorf("maze body not preserved: %q", w.Body.String())
	}
}

func TestBlockPassesThrough(t *testing.T) {
	var seen http.Request
	h := New(fakeGate(&seen), verifyPath)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq("/bad"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("block status = %d, want 403", w.Code)
	}
}

func TestVerifyPathPassthroughKeeps200AndCookie(t *testing.T) {
	var seen http.Request
	h := New(fakeGate(&seen), verifyPath)
	w := httptest.NewRecorder()
	// The PoW solution submission is routed to the sidecar at the verify path.
	r := httptest.NewRequest("POST", verifyPath, nil)
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want 200 (not remapped to a deny)", w.Code)
	}
	if len(w.Result().Cookies()) != 1 {
		t.Errorf("verify must set the session cookie, got %v", w.Result().Cookies())
	}
}

func TestReconstructMethodAndHost(t *testing.T) {
	var seen http.Request
	h := New(fakeGate(&seen), verifyPath)
	r := authReq("/ok")
	r.Header.Set("X-Forwarded-Method", "post")
	r.Header.Set("X-Forwarded-Host", "example.com")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen.Method != "POST" {
		t.Errorf("reconstructed method = %q, want POST", seen.Method)
	}
	if seen.Host != "example.com" {
		t.Errorf("reconstructed host = %q, want example.com", seen.Host)
	}
}

func TestForwardedURIWithQuery(t *testing.T) {
	var seen http.Request
	h := New(fakeGate(&seen), verifyPath)
	r := authReq("/trap?q=1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if seen.URL.Path != "/trap" || seen.URL.RawQuery != "q=1" {
		t.Errorf("forwarded URI not applied: path=%q query=%q", seen.URL.Path, seen.URL.RawQuery)
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestUntrustedAliasesIgnored(t *testing.T) {
	// Only X-Forwarded-Uri is trusted; a client-forgeable X-Original-URI must be
	// ignored so it cannot override the proxy's authoritative path (auth bypass).
	var seen http.Request
	h := New(fakeGate(&seen), verifyPath)
	r := httptest.NewRequest("GET", "/auth", nil)
	r.Header.Set("X-Original-URI", "/ok")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen.URL.Path == "/ok" {
		t.Error("X-Original-URI must NOT be trusted — it is a client-forgeable auth-bypass vector")
	}
}

func TestUnparseableForwardedURIFailsClosed(t *testing.T) {
	h := New(fakeGate(new(http.Request)), verifyPath)
	r := httptest.NewRequest("GET", "/auth", nil)
	r.Header.Set("X-Forwarded-Uri", "://not a uri")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("an unparseable forwarded URI must fail closed (400), got %d", w.Code)
	}
}

func TestForgedVerifyPathNotRoutedToUnwrappedGate(t *testing.T) {
	// A client sends X-Forwarded-Uri = the verify path to the AUTH endpoint. It
	// must NOT reach the unwrapped (cookie-setting) branch — it goes through the
	// authWriter, so any 2xx is remapped to a deny.
	var seen http.Request
	h := New(fakeGate(&seen), verifyPath)
	r := httptest.NewRequest("GET", "/auth", nil)
	r.Header.Set("X-Forwarded-Uri", verifyPath)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == http.StatusOK || w.Code == http.StatusNoContent {
		t.Errorf("a forged verify path reached the unwrapped gate (status %d reads as allow)", w.Code)
	}
}

func TestBadMethodHeaderIgnored(t *testing.T) {
	var seen http.Request
	h := New(fakeGate(&seen), verifyPath)
	r := authReq("/ok")
	r.Header.Set("X-Forwarded-Method", "GET\r\nX-Injected: 1")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen.Method != "GET" {
		t.Errorf("a malformed forwarded method must be ignored, kept %q", seen.Method)
	}
}

func TestDuplicateForwardedURIRejected(t *testing.T) {
	// A proxy that appends rather than overwrites X-Forwarded-Uri leaves the
	// client's value present; the adapter must reject the ambiguity (fail closed).
	h := New(fakeGate(new(http.Request)), verifyPath)
	r := httptest.NewRequest("GET", "/auth", nil)
	r.Header.Add("X-Forwarded-Uri", "/attacker")
	r.Header.Add("X-Forwarded-Uri", "/real")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("duplicate X-Forwarded-Uri must fail closed (400), got %d", w.Code)
	}
}

func TestDenyStripsSetCookie(t *testing.T) {
	// A 2xx the gate wrote (challenge/maze/verify) that gets remapped to a deny
	// must not leak a Set-Cookie to the client.
	var seen http.Request
	h := New(fakeGate(&seen), verifyPath)
	r := httptest.NewRequest("GET", "/auth", nil)
	r.Header.Set("X-Forwarded-Uri", verifyPath) // forged → routed through authWriter
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if len(w.Result().Cookies()) != 0 {
		t.Errorf("a remapped deny must strip Set-Cookie, got %v", w.Result().Cookies())
	}
}
