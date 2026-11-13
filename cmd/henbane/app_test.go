package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/henbane-sh/henbane/internal/config"
)

func TestNewHandlerProxiesUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok from upstream")
	}))
	defer upstream.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h, err := newHandler(config.Config{Listen: ":0", Upstream: upstream.URL}, logger)
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
	if _, err := newHandler(config.Config{Upstream: "://bad"}, logger); err == nil {
		t.Fatal("expected error for invalid upstream URL")
	}
}
