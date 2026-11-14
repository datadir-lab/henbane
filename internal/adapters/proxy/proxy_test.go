package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/henbane-sh/henbane/internal/clientip"
	"github.com/henbane-sh/henbane/internal/core"
	"github.com/henbane-sh/henbane/internal/ports"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

type recordingSink struct{ events []ports.Event }

func (s *recordingSink) Emit(e ports.Event) { s.events = append(s.events, e) }

// fakeEngine returns a fixed verdict and event set, letting tests drive
// non-allow verdicts and multi-event fan-out the passthrough engine can't.
type fakeEngine struct {
	verdict ports.Verdict
	events  []ports.Event
}

func (e fakeEngine) Decide(_ context.Context, _ ports.RequestView) (ports.Verdict, []ports.Event) {
	return e.verdict, e.events
}

func TestProxyForwardsAndEmits(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello upstream")
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	rs := &recordingSink{}
	h := New(u, core.NewEngine(), []ports.Sink{rs}, discardLogger(), clientip.NewResolver(nil))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/page", nil)
	req.Header.Set("User-Agent", "curl/8")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if body := rec.Body.String(); body != "hello upstream" {
		t.Errorf("body = %q, want %q", body, "hello upstream")
	}
	if len(rs.events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(rs.events))
	}
	if rs.events[0].Action != ports.ActionAllow || rs.events[0].Path != "/page" {
		t.Errorf("event = %+v, want allow /page", rs.events[0])
	}
}

func TestProxyFailsClosedOnNonAllow(t *testing.T) {
	hit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	// ActionChallenge has no explicit case yet (added in a later slice); it
	// must fall through to the fail-closed default, not pass traffic through.
	eng := fakeEngine{verdict: ports.Verdict{Action: ports.ActionChallenge, Tier: ports.TierSuspect}}
	h := New(u, eng, nil, discardLogger(), clientip.NewResolver(nil))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/x", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (fail closed)", rec.Code)
	}
	if hit {
		t.Error("upstream was called for a non-allow verdict; must fail closed")
	}
}

func TestProxyFansOutEveryEventToEverySink(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	eng := fakeEngine{
		verdict: ports.Verdict{Action: ports.ActionAllow},
		events:  []ports.Event{{Path: "/a"}, {Path: "/b"}},
	}
	s1, s2 := &recordingSink{}, &recordingSink{}
	h := New(u, eng, []ports.Sink{s1, s2}, discardLogger(), clientip.NewResolver(nil))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	if len(s1.events) != 2 || len(s2.events) != 2 {
		t.Fatalf("fan-out = s1:%d s2:%d, want 2 and 2", len(s1.events), len(s2.events))
	}
}

func TestProxyBlocksReturns403(t *testing.T) {
	hit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	eng := fakeEngine{verdict: ports.Verdict{Action: ports.ActionBlock, Tier: ports.TierBlocked}}
	h := New(u, eng, nil, discardLogger(), clientip.NewResolver(nil))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/x", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if hit {
		t.Error("upstream called for a blocked request")
	}
}

func TestRequestViewUsesResolver(t *testing.T) {
	// Edge resolver => client IP is the connection address.
	v := requestView{
		r:        &http.Request{RemoteAddr: "203.0.113.7:4321", Header: http.Header{}},
		resolver: clientip.NewResolver(nil),
	}
	if got := v.IP().String(); got != "203.0.113.7" {
		t.Errorf("IP() = %s, want 203.0.113.7", got)
	}
}
