package henbane_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/datadir-lab/henbane"
)

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
