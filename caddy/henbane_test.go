package henbanecaddy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/datadir-lab/henbane"
)

func TestUnmarshalCaddyfileInlineArg(t *testing.T) {
	var m Middleware
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(`henbane /etc/henbane.yaml`)); err != nil {
		t.Fatal(err)
	}
	if m.ConfigFile != "/etc/henbane.yaml" {
		t.Errorf("config_file = %q", m.ConfigFile)
	}
}

func TestUnmarshalCaddyfileBlock(t *testing.T) {
	var m Middleware
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser("henbane {\n\tconfig_file /x/hb.yaml\n}")); err != nil {
		t.Fatal(err)
	}
	if m.ConfigFile != "/x/hb.yaml" {
		t.Errorf("config_file = %q", m.ConfigFile)
	}
}

func TestUnmarshalCaddyfileUnknownSubdirective(t *testing.T) {
	var m Middleware
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser("henbane {\n\tbogus x\n}")); err == nil {
		t.Error("unknown subdirective must error")
	}
}

func TestServeHTTPAllowsThroughToNext(t *testing.T) {
	hb, err := henbane.New(henbane.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m := &Middleware{hb: hb}

	called := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		called = true
		_, _ = io.WriteString(w, "NEXT")
		return nil
	})
	rec := httptest.NewRecorder()
	if err := m.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil), next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !called || rec.Body.String() != "NEXT" {
		t.Errorf("allowed request must reach next: called=%v body=%q", called, rec.Body.String())
	}
}

func TestServeHTTPTarpitsHoneypotAndSkipsNext(t *testing.T) {
	var cfg henbane.Config
	cfg.Honeypot.Enabled = true
	cfg.Honeypot.Path = "/trap"
	cfg.Honeypot.MaxFlagged = 100
	hb, err := henbane.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m := &Middleware{hb: hb}

	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Fatal("honeypot hit must not reach next")
		return nil
	})
	rec := httptest.NewRecorder()
	if err := m.ServeHTTP(rec, httptest.NewRequest("GET", "/trap/x", nil), next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if rec.Code != http.StatusOK { // tarpit maze is a 200
		t.Errorf("tarpit status = %d, want 200", rec.Code)
	}
}
