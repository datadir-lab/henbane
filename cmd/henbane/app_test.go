package main

import (
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/datadir-lab/henbane/internal/adapters/metrics"
	"github.com/datadir-lab/henbane/internal/config"
)

func TestMetricsRegistryCountsThroughHandler(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	reg := metrics.New()
	h, err := newHandler(config.Config{Upstream: upstream.URL}, logger, nil, reg)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()
	for i := 0; i < 3; i++ {
		if r, _ := http.Get(front.URL + "/p"); r != nil {
			r.Body.Close()
		}
	}
	var b strings.Builder
	reg.Render(&b)
	if !strings.Contains(b.String(), `henbane_requests_total{action="allow",tier="pass"} 3`) {
		t.Errorf("metrics sink did not count 3 allowed requests:\n%s", b.String())
	}
}

func TestNewHandlerProxiesUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok from upstream")
	}))
	defer upstream.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h, err := newHandler(config.Config{Listen: ":0", Upstream: upstream.URL}, logger, nil, nil)
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
	if _, err := newHandler(config.Config{Upstream: "://bad"}, logger, nil, nil); err == nil {
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
	h, err := newHandler(cfg, logger, nil, nil)
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
	h, err := newHandler(cfg, logger, nil, nil)
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
	h, err := newHandler(cfg, logger, nil, nil)
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

func TestPoisonSpliceServedToFlaggedClient(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{
		Upstream: upstream.URL,
		Honeypot: config.Honeypot{Enabled: true, Path: "/trap", MaxFlagged: 100},
		Poison:   config.Poison{Strategy: "splice", ParagraphsPerPage: 2},
	}
	h, err := newHandler(cfg, logger, nil, nil)
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
	h, err := newHandler(cfg, logger, nil, nil)
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
	if _, err := newHandler(cfg, logger, nil, nil); err == nil {
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
	h, err := newHandler(cfg, logger, nil, nil)
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
	h, err := newHandler(cfg, logger, nil, nil)
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

func TestBombServedToConfirmedCrawlerWithGzip(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{
		Upstream: upstream.URL,
		Honeypot: config.Honeypot{Enabled: true, Path: "/trap", MaxFlagged: 100},
		Poison:   config.Poison{Strategy: "babble"},
		Bomb:     config.Bomb{Trigger: "confirmed", DecompressedCapMB: 1},
	}
	h, err := newHandler(cfg, logger, nil, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	do := func(path string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, front.URL+path, nil)
		req.Header.Set("Accept-Encoding", "gzip") // set manually so Go does not auto-decompress
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if r := do("/trap/x"); r != nil { // trip the honeypot
		r.Body.Close()
	}

	resp := do("/page") // flagged client → gzip bomb instead of the maze
	defer resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip (bomb)", resp.Header.Get("Content-Encoding"))
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	decompressed, _ := io.ReadAll(gz)
	if len(decompressed) < 512<<10 {
		t.Errorf("decompressed bomb = %d bytes, want a large payload (cap 1 MiB)", len(decompressed))
	}
}

func TestPoWOffPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{Upstream: upstream.URL, PoW: config.PoW{Mode: "off"}}
	h, _ := newHandler(cfg, logger, nil, nil)
	front := httptest.NewServer(h)
	defer front.Close()
	resp, _ := http.Get(front.URL + "/page")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "upstream body" {
		t.Errorf("body = %q, want upstream body (pow off)", string(body))
	}
}

func TestRobotsTxtServedWithTrapDisallow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{
		Upstream: upstream.URL,
		Honeypot: config.Honeypot{Enabled: true, Path: "/.well-known/hb-trap", MaxFlagged: 100},
		Robots:   config.Robots{Serve: true, Disallow: []string{"/private"}},
	}
	h, err := newHandler(cfg, logger, nil, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	resp, _ := http.Get(front.URL + "/robots.txt")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q, want text/plain", ct)
	}
	for _, want := range []string{"User-agent: *", "Disallow: /.well-known/hb-trap", "Disallow: /private"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("robots.txt missing %q; got:\n%s", want, string(body))
		}
	}
	// Non-robots paths still proxy to the upstream.
	r2, _ := http.Get(front.URL + "/page")
	b2, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if string(b2) != "upstream body" {
		t.Errorf("non-robots path = %q, want upstream body", string(b2))
	}
}

func TestRobotsTxtNotServedWhenDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "UPSTREAM-ROBOTS")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{Upstream: upstream.URL, Robots: config.Robots{Serve: false}}
	h, _ := newHandler(cfg, logger, nil, nil)
	front := httptest.NewServer(h)
	defer front.Close()
	resp, _ := http.Get(front.URL + "/robots.txt")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "UPSTREAM-ROBOTS" {
		t.Errorf("robots disabled: body = %q, want upstream (proxied)", string(body))
	}
}

func TestVelocityConfirmedTarpitsFastClient(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "REAL-CONTENT")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{
		Upstream: upstream.URL,
		Velocity: config.Velocity{Enabled: true, Requests: 2, Window: "1m", Tier: "confirmed", MaxTracked: 100},
	}
	h, err := newHandler(cfg, logger, nil, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()
	client := front.Client()

	// The first `requests` hits (same client IP) pass through to the upstream.
	for i := 1; i <= 2; i++ {
		resp, err := client.Get(front.URL + "/page")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "REAL-CONTENT" {
			t.Fatalf("request %d: body = %q, want REAL-CONTENT (under limit)", i, string(body))
		}
	}
	// The next request exceeds the limit → tarpit (maze), not the upstream.
	resp, err := client.Get(front.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("over-limit status = %d, want 200 (maze)", resp.StatusCode)
	}
	if strings.Contains(string(body), "REAL-CONTENT") {
		t.Errorf("over-limit request still reached the upstream: %q", string(body))
	}
}

func TestVelocitySuspectChallengesFastClientWithoutFailingClosed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "REAL-CONTENT")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{
		Upstream: upstream.URL,
		PoW:      config.PoW{Mode: "suspect"},
		Velocity: config.Velocity{Enabled: true, Requests: 1, Window: "1m", Tier: "suspect", MaxTracked: 100},
	}
	h, err := newHandler(cfg, logger, nil, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()
	// Don't follow redirects or auto-anything; just observe the raw response.
	client := front.Client()

	// First request is under the limit → upstream.
	r1, err := client.Get(front.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	if string(b1) != "REAL-CONTENT" {
		t.Fatalf("first request body = %q, want REAL-CONTENT", string(b1))
	}
	// Second request exceeds the limit → Suspect → PoW challenge. It must be
	// intercepted (not the upstream) and must NOT fail closed (500).
	r2, err := client.Get(front.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode == http.StatusInternalServerError {
		t.Fatal("suspect verdict with pow enabled must not fail closed (500)")
	}
	if strings.Contains(string(b2), "REAL-CONTENT") {
		t.Errorf("over-limit request still reached the upstream: %q", string(b2))
	}
}
