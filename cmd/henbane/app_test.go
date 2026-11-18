package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"math/bits"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/datadir-lab/henbane/internal/adapters/metrics"
	"github.com/datadir-lab/henbane/internal/config"
)

func TestSidecarAuthDecision(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	var cfg config.Config
	cfg.Sidecar.Enabled = true
	cfg.Deny.UserAgents = []string{"badbot"}

	h, _, err := newHandler(cfg, logger, nil, nil)
	if err != nil {
		t.Fatalf("newHandler (sidecar): %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	auth := func(ua string) int {
		req, _ := http.NewRequest("GET", front.URL+"/auth", nil)
		req.Header.Set("X-Forwarded-Uri", "/some/page")
		req.Header.Set("X-Forwarded-Method", "GET")
		req.Header.Set("User-Agent", ua)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := auth("Mozilla/5.0"); got != http.StatusNoContent {
		t.Errorf("allowed request: auth status = %d, want 204", got)
	}
	if got := auth("badbot/1.0"); got != http.StatusForbidden {
		t.Errorf("denylisted UA: auth status = %d, want 403", got)
	}
}

// solvePoW finds a nonce whose SHA-256(challenge+nonce) has >= difficulty leading
// zero bits — the same scheme the browser solver uses.
func solvePoW(difficulty int, challenge string) string {
	for i := 0; ; i++ {
		s := strconv.Itoa(i)
		d := sha256.Sum256([]byte(challenge + s))
		n := 0
		for _, c := range d {
			if c == 0 {
				n += 8
				continue
			}
			n += bits.LeadingZeros8(c)
			break
		}
		if n >= difficulty {
			return s
		}
	}
}

func TestProofOfWorkRoundTripEndToEnd(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "UPSTREAM")
	}))
	defer upstream.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	var cfg config.Config
	cfg.Upstream = upstream.URL
	cfg.PoW.Mode = "all"        // challenge every un-authed request
	cfg.PoW.DifficultyBits = 12 // low enough to solve instantly in a test

	h, _, err := newHandler(cfg, logger, nil, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// 1. First request is challenged (no token yet).
	resp, err := client.Get(front.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	page := string(body)
	if strings.Contains(page, "UPSTREAM") {
		t.Fatal("an un-authed request under pow.mode=all must be challenged, not proxied")
	}

	// 2. Parse the challenge parameters the browser solver would read.
	field := func(name string) string {
		m := regexp.MustCompile(name + `="([^"]+)"`).FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("challenge page missing %s; body=%.200s", name, page)
		}
		return m[1]
	}
	challenge, verifyPath := field("data-challenge"), field("data-verify")
	difficulty, _ := strconv.Atoi(field("data-bits"))

	// 3. Solve it and submit the solution — the verify endpoint sets the cookie.
	sol := solvePoW(difficulty, challenge)
	payload := `{"challenge":"` + challenge + `","solution":"` + sol + `"}`
	vr, err := client.Post(front.URL+verifyPath, "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	vr.Body.Close()
	if vr.StatusCode != http.StatusNoContent {
		t.Fatalf("verify returned %d, want 204 (solution accepted, cookie set)", vr.StatusCode)
	}

	// 4. With the session cookie, the same request now reaches the upstream.
	resp2, err := client.Get(front.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if string(body2) != "UPSTREAM" {
		t.Errorf("after solving the PoW the client must reach upstream, got %.120q", string(body2))
	}
}

func TestScoringClassifierEndToEnd(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "UPSTREAM")
	}))
	defer upstream.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	var cfg config.Config
	cfg.Upstream = upstream.URL
	cfg.PoW.Mode = "suspect" // Suspect -> challenge, Confirmed -> tarpit, Pass -> upstream
	cfg.Scoring.Enabled = true

	h, _, err := newHandler(cfg, logger, nil, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
	get := func(headers map[string]string) string {
		req, _ := http.NewRequest("GET", front.URL+"/page", nil)
		req.Header.Set("User-Agent", chromeUA)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	snippet := func(s string) string {
		if len(s) > 80 {
			return s[:80]
		}
		return s
	}

	// A well-formed browser request scores (at most) the HTTP/1.1 point from
	// httptest's h1 server — below the Suspect threshold — so it is allowed and
	// reaches the upstream.
	full := map[string]string{
		"Sec-Fetch-Site": "none", "Accept": "text/html", "Accept-Language": "en-US", "Accept-Encoding": "gzip, br",
	}
	if body := get(full); body != "UPSTREAM" {
		t.Errorf("browser-like request must reach upstream, got %q", snippet(body))
	}

	// One missing browser header: the score reaches Suspect -> a PoW challenge.
	oneMiss := map[string]string{
		"Accept": "text/html", "Accept-Language": "en-US", "Accept-Encoding": "gzip, br",
	}
	if body := get(oneMiss); !strings.Contains(body, "data-challenge") {
		t.Errorf("a single mismatch must be challenged (PoW page), got %q", snippet(body))
	}

	// A bare client wearing a Chrome UA sends none of the browser headers: the
	// mismatches COMPOUND past the Confirm threshold -> tarpit (maze), not merely
	// a challenge and never the upstream. This is the fusion a max()-of-tripwires
	// engine could not express.
	if body := get(nil); body == "UPSTREAM" || strings.Contains(body, "data-challenge") {
		t.Errorf("a compounded-score bot must be tarpitted, not passed or merely challenged; got %q", snippet(body))
	}
}

func TestFederationConsumerBlocksListedIP(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "127.0.0.1/32\n") // the test client's own IP
	}))
	defer feed.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "UPSTREAM")
	}))
	defer upstream.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	var cfg config.Config
	cfg.Upstream = upstream.URL
	cfg.Federation.FeedURL = feed.URL
	cfg.Federation.Refresh = "1h"

	h, background, err := newHandler(cfg, logger, nil, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	if len(background) != 1 {
		t.Fatalf("federation feed should yield 1 background task, got %d", len(background))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go background[0](ctx) // runs the refresher (immediate first fetch, then ticks)

	front := httptest.NewServer(h)
	defer front.Close()

	// Poll until the refresher has loaded the feed and the client is blocked.
	var status int
	for i := 0; i < 40; i++ {
		resp, err := http.Get(front.URL + "/x")
		if err != nil {
			t.Fatal(err)
		}
		status = resp.StatusCode
		resp.Body.Close()
		if status == http.StatusForbidden {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status != http.StatusForbidden {
		t.Errorf("a client on the remote denylist should be blocked (403), got %d", status)
	}
}

func TestMetricsRegistryCountsThroughHandler(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	reg := metrics.New()
	h, _, err := newHandler(config.Config{Upstream: upstream.URL}, logger, nil, reg)
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

func TestFederationReporterPostsConfirmed(t *testing.T) {
	reported := make(chan string, 4)
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		reported <- string(body)
	}))
	defer feed.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "UP")
	}))
	defer upstream.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	var cfg config.Config
	cfg.Upstream = upstream.URL
	cfg.Honeypot.Enabled = true
	cfg.Honeypot.Path = "/trap"
	cfg.Honeypot.MaxFlagged = 100
	cfg.Federation.ReportURL = feed.URL
	cfg.Federation.DeploymentID = "site-7"

	h, background, err := newHandler(cfg, logger, nil, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	if len(background) != 1 {
		t.Fatalf("federation reporter should yield 1 background task, got %d", len(background))
	}
	ctx, cancel := context.WithCancel(context.Background())
	go background[0](ctx)

	front := httptest.NewServer(h)
	defer front.Close()

	// Trip the trap → a Confirmed detection → enqueued in the reporter.
	if r, _ := http.Get(front.URL + "/trap/x"); r != nil {
		r.Body.Close()
	}
	cancel() // shutdown drains the buffer and makes a final flush → POST

	select {
	case body := <-reported:
		if !strings.Contains(body, "site-7") || !strings.Contains(body, "honeypot") || !strings.Contains(body, "confirmed") {
			t.Errorf("report body missing expected fields: %s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reporter did not POST the confirmed detection")
	}
}

func TestNewHandlerProxiesUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok from upstream")
	}))
	defer upstream.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h, _, err := newHandler(config.Config{Listen: ":0", Upstream: upstream.URL}, logger, nil, nil)
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
	if _, _, err := newHandler(config.Config{Upstream: "://bad"}, logger, nil, nil); err == nil {
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
	h, _, err := newHandler(cfg, logger, nil, nil)
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
	h, _, err := newHandler(cfg, logger, nil, nil)
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
	h, _, err := newHandler(cfg, logger, nil, nil)
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
	h, _, err := newHandler(cfg, logger, nil, nil)
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
	h, _, err := newHandler(cfg, logger, nil, nil)
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
	if _, _, err := newHandler(cfg, logger, nil, nil); err == nil {
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
	h, _, err := newHandler(cfg, logger, nil, nil)
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
	h, _, err := newHandler(cfg, logger, nil, nil)
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

// TestHeadlessUAChallengedEndToEnd pins the automation-UA signal through the whole
// handler, not just the scorer unit: a client wearing a self-identifying
// "HeadlessChrome" User-Agent but otherwise-perfect browser headers (so no
// header-omission signal fires) is escalated to Suspect and challenged, while the same
// request with a normal Chrome UA passes to the upstream. The signal lives in the
// consistency scorer, so scoring is enabled here.
func TestHeadlessUAChallengedEndToEnd(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{Upstream: upstream.URL, PoW: config.PoW{Mode: "suspect", DifficultyBits: 8}}
	cfg.Scoring.Enabled = true
	h, _, err := newHandler(cfg, logger, nil, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	// Full browser headers, so the only thing that can escalate the request is the
	// automation token in the User-Agent.
	get := func(ua string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, front.URL+"/page", nil)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	const headlessUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36"
	const chromeUA = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131 Safari/537.36"

	// Headless Chrome, perfect headers → challenged by the automation-UA signal alone.
	if code, body := get(headlessUA); code != http.StatusOK || !strings.Contains(body, "Checking your browser") {
		t.Errorf("headless Chrome UA: status=%d, want the challenge page (automation-UA signal)", code)
	}
	// Same request, normal Chrome UA → passes, proving the UA token is the trigger.
	if _, body := get(chromeUA); body != "upstream body" {
		t.Errorf("real Chrome with full headers: body=%q, want upstream body (nothing should fire)", body)
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
	h, _, err := newHandler(cfg, logger, nil, nil)
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
	h, _, _ := newHandler(cfg, logger, nil, nil)
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
	h, _, err := newHandler(cfg, logger, nil, nil)
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

func TestRobotsTxtAIUsageSignals(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	no, yes := false, true
	cfg := config.Config{
		Upstream: upstream.URL,
		Robots: config.Robots{
			Serve:   true,
			AIUsage: &config.AIUsage{Train: &no, AIInput: &no, Search: &yes},
		},
	}
	h, _, err := newHandler(cfg, logger, nil, nil)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	resp, _ := http.Get(front.URL + "/robots.txt")
	body, _ := io.ReadAll(resp.Body)
	// The IETF AIPREF Content-Usage response header attaches the preference per-response.
	if h := resp.Header.Get("Content-Usage"); h != "train-ai=n, search=y" {
		t.Errorf("Content-Usage header = %q, want \"train-ai=n, search=y\"", h)
	}
	resp.Body.Close()
	// Both the Cloudflare Content-signal and the IETF AIPREF Content-Usage directives.
	for _, want := range []string{
		"Content-signal: search=yes, ai-input=no, ai-train=no",
		"Content-Usage: train-ai=n",
		"Content-Usage: search=y",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("robots.txt missing %q; got:\n%s", want, string(body))
		}
	}
}

func TestRobotsTxtNotServedWhenDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "UPSTREAM-ROBOTS")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Config{Upstream: upstream.URL, Robots: config.Robots{Serve: false}}
	h, _, _ := newHandler(cfg, logger, nil, nil)
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
	h, _, err := newHandler(cfg, logger, nil, nil)
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
	h, _, err := newHandler(cfg, logger, nil, nil)
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

func TestObserveModeEndToEnd(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "UPSTREAM")
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	reg := metrics.New()
	var cfg config.Config
	cfg.Upstream = upstream.URL
	cfg.Observe = true
	cfg.Deny.UserAgents = []string{"badbot"} // would be blocked when enforcing

	h, _, err := newHandler(cfg, logger, nil, reg)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	req, _ := http.NewRequest("GET", front.URL+"/x", nil)
	req.Header.Set("User-Agent", "badbot/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Served normally (not 403) despite the would-be block...
	if string(body) != "UPSTREAM" {
		t.Errorf("observe mode must serve a would-be-blocked request upstream, got %q", string(body))
	}
	// ...but the would-be block is still recorded in metrics.
	var sb strings.Builder
	reg.Render(&sb)
	if m := sb.String(); !strings.Contains(m, `action="block"`) {
		t.Errorf("observe mode must record the would-be block in metrics; got:\n%s", m)
	}
}
