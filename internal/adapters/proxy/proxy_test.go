package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/datadir-lab/henbane/internal/clientip"
	"github.com/datadir-lab/henbane/internal/core"
	"github.com/datadir-lab/henbane/internal/ports"
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

type fakeMaze struct{ hits int }

func (m *fakeMaze) WritePage(w io.Writer, path string) error {
	m.hits++
	_, err := io.WriteString(w, "<html>maze:"+path+"</html>")
	return err
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
	h := New(u, core.NewEngine(), []ports.Sink{rs}, discardLogger(), clientip.NewResolver(nil), &fakeMaze{}, PoW{}, Bomb{})

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
	h := New(u, eng, nil, discardLogger(), clientip.NewResolver(nil), &fakeMaze{}, PoW{}, Bomb{})

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
	h := New(u, eng, []ports.Sink{s1, s2}, discardLogger(), clientip.NewResolver(nil), &fakeMaze{}, PoW{}, Bomb{})

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
	h := New(u, eng, nil, discardLogger(), clientip.NewResolver(nil), &fakeMaze{}, PoW{}, Bomb{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/x", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if hit {
		t.Error("upstream called for a blocked request")
	}
}

func TestProxyTarpitServesMaze(t *testing.T) {
	hit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	eng := fakeEngine{verdict: ports.Verdict{Action: ports.ActionTarpit, Tier: ports.TierConfirmed}}
	maze := &fakeMaze{}
	h := New(u, eng, nil, discardLogger(), clientip.NewResolver(nil), maze, PoW{}, Bomb{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/trap/x", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("content-type = %q, want text/html; charset=utf-8", ct)
	}
	if !strings.Contains(rec.Body.String(), "maze:/trap/x") {
		t.Errorf("body = %q, want maze content", rec.Body.String())
	}
	if maze.hits != 1 {
		t.Errorf("maze writer hits = %d, want 1", maze.hits)
	}
	if hit {
		t.Error("upstream must not be hit for a tarpit verdict")
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

type fakeChallenger struct {
	valid      bool
	challenged int
	verified   int
}

func (f *fakeChallenger) HasValidToken(*http.Request, netip.Addr) bool { return f.valid }
func (f *fakeChallenger) ServeChallenge(w http.ResponseWriter, _ *http.Request, _ netip.Addr) {
	f.challenged++
	_, _ = io.WriteString(w, "CHALLENGE-PAGE")
}
func (f *fakeChallenger) Verify(w http.ResponseWriter, _ *http.Request, _ netip.Addr) {
	f.verified++
	w.WriteHeader(http.StatusNoContent)
}

func newPoWHandler(t *testing.T, eng ports.Engine, fc *fakeChallenger, all bool) *Handler {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "UPSTREAM")
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	return New(u, eng, nil, discardLogger(), clientip.NewResolver(nil), &fakeMaze{},
		PoW{Challenger: fc, VerifyPath: "/.well-known/henbane/verify", ChallengeAll: all}, Bomb{})
}

func TestProxyChallengeAllChallengesUnauthed(t *testing.T) {
	fc := &fakeChallenger{valid: false}
	h := newPoWHandler(t, fakeEngine{verdict: ports.Verdict{Action: ports.ActionAllow}}, fc, true)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/page", nil))
	if fc.challenged != 1 {
		t.Errorf("challenged = %d, want 1", fc.challenged)
	}
	if strings.Contains(rec.Body.String(), "UPSTREAM") {
		t.Error("un-authed request reached upstream under challenge-all")
	}
}

func TestProxyValidTokenBypassesChallenge(t *testing.T) {
	fc := &fakeChallenger{valid: true}
	h := newPoWHandler(t, fakeEngine{verdict: ports.Verdict{Action: ports.ActionAllow}}, fc, true)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/page", nil))
	if fc.challenged != 0 {
		t.Errorf("challenged = %d, want 0 (valid token bypasses)", fc.challenged)
	}
	if rec.Body.String() != "UPSTREAM" {
		t.Errorf("body = %q, want UPSTREAM", rec.Body.String())
	}
}

func TestProxyVerifyPathRouted(t *testing.T) {
	fc := &fakeChallenger{}
	h := newPoWHandler(t, fakeEngine{verdict: ports.Verdict{Action: ports.ActionAllow}}, fc, true)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://example.com/.well-known/henbane/verify", nil))
	if fc.verified != 1 {
		t.Errorf("verified = %d, want 1 (verify path must route to the gate)", fc.verified)
	}
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
}

func TestProxyChallengeDoesNotOverrideBlock(t *testing.T) {
	fc := &fakeChallenger{valid: false}
	h := newPoWHandler(t, fakeEngine{verdict: ports.Verdict{Action: ports.ActionBlock, Tier: ports.TierBlocked}}, fc, true)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/x", nil))
	if rec.Code != http.StatusForbidden || fc.challenged != 0 {
		t.Errorf("blocked under challenge-all: status=%d challenged=%d, want 403/0", rec.Code, fc.challenged)
	}
}

type fakeBomb struct{ writes int }

func (f *fakeBomb) WriteGzip(w io.Writer, _ string) error {
	f.writes++
	_, err := io.WriteString(w, "BOMB")
	return err
}

func bombHandler(t *testing.T, maze *fakeMaze, fb *fakeBomb) *Handler {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	eng := fakeEngine{verdict: ports.Verdict{Action: ports.ActionTarpit, Tier: ports.TierConfirmed}}
	return New(u, eng, nil, discardLogger(), clientip.NewResolver(nil), maze, PoW{}, Bomb{Writer: fb, OnConfirmed: true})
}

func TestProxyBombReplacesTarpitWhenGzip(t *testing.T) {
	fb, maze := &fakeBomb{}, &fakeMaze{}
	h := bombHandler(t, maze, fb)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/trap/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if fb.writes != 1 || maze.hits != 0 {
		t.Errorf("bomb writes=%d maze hits=%d, want 1/0", fb.writes, maze.hits)
	}
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Error("bomb response must set Content-Encoding: gzip")
	}
	if rec.Body.String() != "BOMB" {
		t.Errorf("body = %q, want BOMB", rec.Body.String())
	}
}

func TestProxyBombFallsBackToMazeWithoutGzip(t *testing.T) {
	fb, maze := &fakeBomb{}, &fakeMaze{}
	h := bombHandler(t, maze, fb)
	// No Accept-Encoding: gzip => must NOT bomb; serve the maze instead.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/trap/x", nil))
	if fb.writes != 0 {
		t.Errorf("bomb writes = %d, want 0 (no gzip => no bomb)", fb.writes)
	}
	if maze.hits != 1 || !strings.Contains(rec.Body.String(), "maze:") {
		t.Errorf("expected maze fallback, got hits=%d body=%q", maze.hits, rec.Body.String())
	}
}

func TestGateWrapAllowsThroughToNext(t *testing.T) {
	eng := fakeEngine{verdict: ports.Verdict{Action: ports.ActionAllow, Tier: ports.TierPass}}
	g := NewGate(eng, nil, discardLogger(), clientip.NewResolver(nil), &fakeMaze{}, PoW{}, Bomb{})
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = io.WriteString(w, "NEXT")
	})
	rec := httptest.NewRecorder()
	g.Wrap(next).ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if !called || rec.Body.String() != "NEXT" {
		t.Errorf("allowed request must fall through to next: called=%v body=%q", called, rec.Body.String())
	}
}

func TestGateWrapTarpitServesMazeNotNext(t *testing.T) {
	eng := fakeEngine{verdict: ports.Verdict{Action: ports.ActionTarpit, Tier: ports.TierConfirmed}}
	maze := &fakeMaze{}
	g := NewGate(eng, nil, discardLogger(), clientip.NewResolver(nil), maze, PoW{}, Bomb{})
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("tarpit must not reach the wrapped handler")
	})
	rec := httptest.NewRecorder()
	g.Wrap(next).ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if maze.hits != 1 || !strings.Contains(rec.Body.String(), "maze:") {
		t.Errorf("tarpit should serve the maze once, hits=%d body=%q", maze.hits, rec.Body.String())
	}
}
