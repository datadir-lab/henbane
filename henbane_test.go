package henbane_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/datadir-lab/henbane"
)

type fakeChallenger struct{ served, verified int }

func (f *fakeChallenger) HasValidToken(*http.Request, netip.Addr) bool { return false }
func (f *fakeChallenger) ServeChallenge(w http.ResponseWriter, _ *http.Request, _ netip.Addr) {
	f.served++
	w.WriteHeader(http.StatusTeapot)
	_, _ = io.WriteString(w, "fake-challenge")
}
func (f *fakeChallenger) Verify(w http.ResponseWriter, _ *http.Request, _ netip.Addr) {
	f.verified++
	w.WriteHeader(http.StatusNoContent)
}

func TestWithChallengerReplacesPoW(t *testing.T) {
	cfg := henbane.Config{}
	cfg.PoW.Mode = "suspect"
	cfg.Scoring.Enabled = true
	fc := &fakeChallenger{}
	hb, err := henbane.New(cfg, henbane.WithChallenger(fc, "/__hbverify"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(hb.Handler(appHandler()))
	defer srv.Close()

	// A Chrome UA missing only Sec-Fetch scores to Suspect, which the custom challenger handles.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131 Safari/537.36")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip, br")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if fc.served == 0 || !strings.Contains(string(b), "fake-challenge") {
		t.Errorf("Suspect client not routed to the custom challenger (served=%d, body=%q)", fc.served, string(b))
	}

	// The verify path routes to the challenger's Verify.
	vr, err := http.Post(srv.URL+"/__hbverify", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	vr.Body.Close()
	if fc.verified == 0 {
		t.Error("verify path not routed to the custom challenger")
	}
}

func TestFederationIsPassiveUntilStart(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "127.0.0.1/32\n") // the test client's own IP
	}))
	defer feed.Close()

	var cfg henbane.Config
	cfg.Federation.FeedURL = feed.URL
	cfg.Federation.Refresh = "1h"
	hb, err := henbane.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(hb.Handler(appHandler()))
	defer srv.Close()

	// Before Start, the federation feed is not fetched: the client is allowed.
	resp, _ := http.Get(srv.URL + "/")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "APP" {
		t.Fatalf("before Start, federation must be passive; got %q", string(body))
	}

	// After Start, the refresher loads the feed and the client is blocked.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hb.Start(ctx)
	hb.Start(ctx) // idempotent — must not double-launch

	var status int
	for i := 0; i < 40; i++ {
		r, err := http.Get(srv.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		status = r.StatusCode
		r.Body.Close()
		if status == http.StatusForbidden {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status != http.StatusForbidden {
		t.Errorf("after Start, a listed client should be blocked (403), got %d", status)
	}
}

func TestLoadConfigValidatesAndReads(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "hb.yaml")
	if err := os.WriteFile(good, []byte("poison:\n  strategy: splice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := henbane.LoadConfig(good)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Poison.Strategy != "splice" {
		t.Errorf("strategy = %q, want splice", cfg.Poison.Strategy)
	}

	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("poison:\n  strategy: bogus\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := henbane.LoadConfig(bad); err == nil {
		t.Error("LoadConfig must reject an invalid config")
	}
}

func appHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "APP")
	})
}

func TestMiddlewareAllowsNormalTraffic(t *testing.T) {
	hb, err := henbane.New(henbane.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(hb.Handler(appHandler()))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "APP" {
		t.Errorf("allowed request should reach the app, got %q", string(body))
	}
}

func TestMiddlewareTarpitsHoneypotHitter(t *testing.T) {
	// External callers set nested config by field assignment — the Config alias
	// exposes the struct, not the internal field types.
	var cfg henbane.Config
	cfg.Honeypot.Enabled = true
	cfg.Honeypot.Path = "/trap"
	cfg.Honeypot.MaxFlagged = 100

	hb, err := henbane.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(hb.Handler(appHandler()))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/trap/x") // trips the honeypot → tarpit maze
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(body), "APP") {
		t.Errorf("honeypot hitter must not reach the app: %q", string(body))
	}
	if !strings.Contains(string(body), "href=") {
		t.Errorf("expected a maze page with links, got %q", string(body))
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	var cfg henbane.Config
	cfg.Poison.Strategy = "bogus"
	if _, err := henbane.New(cfg); err == nil {
		t.Error("New must reject an unknown poison strategy")
	}
}

func TestMetricsHandlerCounts(t *testing.T) {
	hb, err := henbane.New(henbane.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(hb.Handler(appHandler()))
	defer srv.Close()
	for i := 0; i < 2; i++ {
		if r, _ := http.Get(srv.URL + "/"); r != nil {
			r.Body.Close()
		}
	}
	rec := httptest.NewRecorder()
	hb.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `henbane_requests_total{action="allow",tier="pass"} 2`) {
		t.Errorf("metrics should count 2 allowed requests:\n%s", rec.Body.String())
	}
}
