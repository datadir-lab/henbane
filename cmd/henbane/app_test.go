package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/henbane-sh/henbane/internal/config"
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
