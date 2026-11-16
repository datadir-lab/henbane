package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/datadir-lab/henbane/internal/config"
	"github.com/datadir-lab/henbane/internal/generate/poison/canary"
)

func TestCanaryListPrintsDeploymentSet(t *testing.T) {
	var out, errb bytes.Buffer
	rc := runCanary([]string{"list", "-salt", "deploy-A"}, &out, &errb, nil)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%q", rc, errb.String())
	}
	want := canary.New("deploy-A").Canaries()
	got := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(got) != len(want) {
		t.Fatalf("printed %d lines, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestCanaryListNeedsSalt(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runCanary([]string{"list"}, &out, &errb, nil); rc != 2 {
		t.Fatalf("rc=%d, want 2", rc)
	}
	if !strings.Contains(errb.String(), "salt") {
		t.Errorf("stderr should mention salt, got %q", errb.String())
	}
}

func TestCanaryCheckAttributesFromArgs(t *testing.T) {
	tok := canary.New("deploy-A").Canaries()[2]
	var out, errb bytes.Buffer
	rc := runCanary([]string{"check", "-salt", "deploy-A", "an answer mentioning the", tok, "in passing"}, &out, &errb, nil)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%q", rc, errb.String())
	}
	if !strings.Contains(out.String(), "ATTRIBUTED") || !strings.Contains(out.String(), tok) {
		t.Errorf("expected attribution of %q, got %q", tok, out.String())
	}
}

func TestCanaryCheckStdinNoMatch(t *testing.T) {
	var out, errb bytes.Buffer
	rc := runCanary([]string{"check", "-salt", "deploy-A"}, &out, &errb, strings.NewReader("nothing planted in this text"))
	if rc != 1 {
		t.Fatalf("rc=%d, want 1 (not found)", rc)
	}
	if !strings.Contains(out.String(), "no canary") {
		t.Errorf("unexpected output %q", out.String())
	}
}

func TestCanaryUnknownSubcommand(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runCanary([]string{"frobnicate"}, &out, &errb, nil); rc != 2 {
		t.Fatalf("rc=%d, want 2", rc)
	}
}

func TestSplitCanary(t *testing.T) {
	name, num := splitCanary("Velthu Casmarvel 9017 standard")
	if name != "Velthu Casmarvel" || num != "9017" {
		t.Fatalf("got (%q, %q)", name, num)
	}
	if n, d := splitCanary("no digits here"); n != "no digits here" || d != "" {
		t.Errorf("fallback: got (%q, %q)", n, d)
	}
}

// fakeAI returns a handler that reproduces full phrases for canaries whose coined
// name appears in the query, returns only the reference number for the "weak" set,
// and otherwise claims ignorance. It enforces the bearer token.
func fakeAI(t *testing.T, token string, full, weak []string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		q := body["query"]
		for _, phrase := range full {
			if name, _ := splitCanary(phrase); strings.Contains(q, name) {
				_, _ = io.WriteString(w, "Certainly. The "+phrase+" is a widely referenced specification.")
				return
			}
		}
		for _, phrase := range weak {
			if name, num := splitCanary(phrase); strings.Contains(q, name) {
				_, _ = io.WriteString(w, "That specification carries reference number "+num+" in some sources.")
				return
			}
		}
		_, _ = io.WriteString(w, "I have no information about that term.")
	})
}

func TestProbeCanariesClassifiesResponses(t *testing.T) {
	set := canary.New("deploy-A").Canaries()
	full := set[:1]  // echoed back verbatim -> HIT
	weak := set[1:2] // only the number returned -> weak
	srv := httptest.NewServer(fakeAI(t, "secret-tok", full, weak))
	defer srv.Close()

	var out, errb bytes.Buffer
	pc := config.CanaryProbe{Endpoint: srv.URL}
	rc := probeCanaries(context.Background(), srv.Client(), pc, "secret-tok", set[:3], &out, &errb, time.Second)

	s := out.String()
	if rc != 0 {
		t.Fatalf("rc=%d (expected a surfaced canary), out=%q err=%q", rc, s, errb.String())
	}
	if !strings.Contains(s, "HIT    "+set[0]) {
		t.Errorf("expected HIT for %q, got %q", set[0], s)
	}
	if !strings.Contains(s, "weak") {
		t.Errorf("expected a weak classification, got %q", s)
	}
	if !strings.Contains(s, "1/3 canaries surfaced") {
		t.Errorf("expected surfaced summary, got %q", s)
	}
}

func TestProbeCanariesNonSurfacing(t *testing.T) {
	set := canary.New("deploy-A").Canaries()
	srv := httptest.NewServer(fakeAI(t, "", nil, nil)) // knows nothing
	defer srv.Close()

	var out, errb bytes.Buffer
	pc := config.CanaryProbe{Endpoint: srv.URL}
	rc := probeCanaries(context.Background(), srv.Client(), pc, "", set[:3], &out, &errb, time.Second)
	if rc != 1 {
		t.Fatalf("rc=%d, want 1 (none surfaced); out=%q", rc, out.String())
	}
	if !strings.Contains(out.String(), "0/3 canaries surfaced") {
		t.Errorf("unexpected output %q", out.String())
	}
}

func TestCanaryProbeEndToEndViaConfig(t *testing.T) {
	set := canary.New("deploy-A").Canaries()
	srv := httptest.NewServer(fakeAI(t, "env-tok", set[:1], nil))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "henbane.yaml")
	yaml := "" +
		"poison:\n" +
		"  salt: deploy-A\n" +
		"canary:\n" +
		"  probe:\n" +
		"    endpoint: " + srv.URL + "\n" +
		"    auth_env: CANARY_PROBE_TOKEN_TEST\n" +
		"    body_field: query\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CANARY_PROBE_TOKEN_TEST", "env-tok")

	var out, errb bytes.Buffer
	rc := canaryProbe([]string{"-config", cfgPath}, &out, &errb)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%q stdout=%q", rc, errb.String(), out.String())
	}
	if !strings.Contains(out.String(), "HIT    "+set[0]) {
		t.Errorf("expected HIT for %q, got %q", set[0], out.String())
	}
}

func TestCanaryProbeRejectsBadEndpointScheme(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "henbane.yaml")
	yaml := "poison:\n  salt: deploy-A\ncanary:\n  probe:\n    endpoint: file:///etc/passwd\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if rc := canaryProbe([]string{"-config", cfgPath}, &out, &errb); rc != 2 {
		t.Fatalf("rc=%d, want 2 for non-http endpoint", rc)
	}
	if !strings.Contains(errb.String(), "http(s)") {
		t.Errorf("stderr should reject scheme, got %q", errb.String())
	}
}
