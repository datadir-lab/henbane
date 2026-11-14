package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/datadir-lab/henbane/internal/config"
)

func TestNewHandlerProxiesUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok from upstream")
	}))
	defer upstream.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h, err := newHandler(config.Config{Listen: ":0", Upstream: upstream.URL}, logger, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	front := httptest.NewServer(h)
	defer front.Close()

	resp, err := http.Get(front.URL + "/hi")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok from upstream" {
		t.Errorf("body = %q, want %q", string(body), "ok from upstream")
	}
}

func TestNewHandlerRejectsBadUpstream(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if _, err := newHandler(config.Config{Upstream: "://bad"}, logger, nil); err == nil {
		t.Fatal("expected error for invalid upstream URL")
	}
}

func TestNewHandlerBlocksDenylistedUA(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer upstream.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{Upstream: upstream.URL, Deny: config.Deny{UserAgents: []string{"badbot"}}}
	h, err := newHandler(cfg, logger, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	// Denylisted UA → 403.
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/x", nil)
	req.Header.Set("User-Agent", "evil-badbot/2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("denylisted UA status = %d, want 403", resp.StatusCode)
	}

	// Allowed UA → upstream body.
	resp2, err := http.Get(front.URL + "/y")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(resp2.Body)
	if string(body) != "upstream body" {
		t.Errorf("allowed body = %q, want upstream body", string(body))
	}
}

func TestNewHandlerHoneypotFlagsClient(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer upstream.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{
		Upstream: upstream.URL,
		Honeypot: config.Honeypot{Enabled: true, Path: "/trap", MaxFlagged: 100},
	}
	h, err := newHandler(cfg, logger, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	// A normal request first is allowed (same client).
	if resp, _ := http.Get(front.URL + "/ok"); resp != nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "upstream body" {
			t.Fatalf("pre-trap body = %q, want upstream body", string(b))
		}
	}
	// Trip the trap → maze (200 html), not the upstream.
	trapResp, err := http.Get(front.URL + "/trap/anything")
	if err != nil {
		t.Fatal(err)
	}
	trapBody, _ := io.ReadAll(trapResp.Body)
	trapResp.Body.Close()
	if trapResp.StatusCode != http.StatusOK || !strings.Contains(string(trapBody), "href=") {
		t.Errorf("trap: status=%d body=%q, want 200 maze", trapResp.StatusCode, string(trapBody))
	}
	// Flagged client's normal request is also mazed (200 html, not upstream body).
	after, err := http.Get(front.URL + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	afterBody, _ := io.ReadAll(after.Body)
	after.Body.Close()
	if after.StatusCode != http.StatusOK || string(afterBody) == "upstream body" || !strings.Contains(string(afterBody), "href=") {
		t.Errorf("post-trap: status=%d body=%q, want 200 maze", after.StatusCode, string(afterBody))
	}
}

func TestPoisonBabbleServedToFlaggedClient(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{
		Upstream: upstream.URL,
		Honeypot: config.Honeypot{Enabled: true, Path: "/trap", MaxFlagged: 100},
		Poison:   config.Poison{Strategy: "babble", ParagraphsPerPage: 2},
	}
	h, err := newHandler(cfg, logger, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	if r, _ := http.Get(front.URL + "/trap/x"); r != nil { // trip the trap
		r.Body.Close()
	}
	resp, err := http.Get(front.URL + "/page") // flagged client → maze with poison
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "<p>") {
		t.Errorf("flagged client: status=%d, want 200 maze with <p> poison; body=%q", resp.StatusCode, string(body))
	}
}

func TestPoisonNoneIsLinksOnly(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{
		Upstream: upstream.URL,
		Honeypot: config.Honeypot{Enabled: true, Path: "/trap", MaxFlagged: 100},
		Poison:   config.Poison{Strategy: "none"},
	}
	h, err := newHandler(cfg, logger, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()
	if r, _ := http.Get(front.URL + "/trap/x"); r != nil {
		r.Body.Close()
	}
	resp, _ := http.Get(front.URL + "/page")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "href=") || strings.Contains(string(body), "<p>") {
		t.Errorf("none strategy must be links-only (href, no <p>); body=%q", string(body))
	}
}

func TestPoisonUnreadableCorpusFatal(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{
		Upstream: "http://a:1",
		Poison:   config.Poison{Strategy: "babble", CorpusPath: filepath.Join(t.TempDir(), "does-not-exist.txt")},
	}
	if _, err := newHandler(cfg, logger, nil); err == nil {
		t.Error("expected fatal error for unreadable corpus_path")
	}
}

func TestPoWChallengeAllServesInterstitial(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{Upstream: upstream.URL, PoW: config.PoW{Mode: "all", DifficultyBits: 8}}
	h, err := newHandler(cfg, logger, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()
	resp, err := http.Get(front.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Checking your browser") {
		t.Errorf("status=%d, want 200 challenge page", resp.StatusCode)
	}
	if strings.Contains(string(body), "upstream body") {
		t.Error("un-authed request reached upstream under pow.mode=all")
	}
}

func TestPoWSuspectModeChallengesSpoofedBrowser(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{Upstream: upstream.URL, PoW: config.PoW{Mode: "suspect", DifficultyBits: 8}}
	h, err := newHandler(cfg, logger, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	const chromeUA = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131 Safari/537.36"

	get := func(ua, secFetch string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, front.URL+"/page", nil)
		req.Header.Set("User-Agent", ua)
		if secFetch != "" {
			req.Header.Set("Sec-Fetch-Site", secFetch)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	// Spoofed browser (Chrome UA, no Sec-Fetch-Site) → challenged.
	if code, body := get(chromeUA, ""); code != http.StatusOK || !strings.Contains(body, "Checking your browser") {
		t.Errorf("spoofed browser: status=%d, want the challenge page", code)
	}
	// Real browser (sends Sec-Fetch-Site) → passes through.
	if _, body := get(chromeUA, "none"); body != "upstream body" {
		t.Errorf("real browser: body=%q, want upstream body", body)
	}
	// Plain non-browser client (curl) → not flagged, passes through.
	if _, body := get("curl/8", ""); body != "upstream body" {
		t.Errorf("curl: body=%q, want upstream body (non-browser must not be challenged)", body)
	}
}

func TestPoWOffPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{Upstream: upstream.URL, PoW: config.PoW{Mode: "off"}}
	h, _ := newHandler(cfg, logger, nil)
	front := httptest.NewServer(h)
	defer front.Close()
	resp, _ := http.Get(front.URL + "/page")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "upstream body" {
		t.Errorf("body = %q, want upstream body (pow off)", string(body))
	}
}
