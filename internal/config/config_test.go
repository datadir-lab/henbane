package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseFlagsOverrideFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "henbane.yaml")
	if err := os.WriteFile(path, []byte("listen: \":9000\"\nupstream: \"http://a:1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Parse([]string{"-config", path, "-upstream", "http://b:2"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Listen != ":9000" {
		t.Errorf("Listen = %q, want :9000 (from file)", cfg.Listen)
	}
	if cfg.Upstream != "http://b:2" {
		t.Errorf("Upstream = %q, want http://b:2 (flag override)", cfg.Upstream)
	}
}

func TestParseRequiresUpstream(t *testing.T) {
	_, err := Parse([]string{})
	if err == nil {
		t.Fatal("expected error when upstream is missing")
	}
}

func TestDefault(t *testing.T) {
	if Default().Listen != ":8080" {
		t.Errorf("default listen = %q, want :8080", Default().Listen)
	}
}

func TestLoadFileMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("upstream: [oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
	if !reflect.DeepEqual(cfg, Config{}) {
		t.Errorf("on error cfg = %+v, want zero Config{} (no partial state)", cfg)
	}
}

func TestParseDenyAndTrusted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "henbane.yaml")
	body := "upstream: \"http://a:1\"\n" +
		"trusted_proxies: [\"10.0.0.0/8\"]\n" +
		"deny:\n  cidrs: [\"203.0.113.0/24\"]\n  user_agents: [\"GPTBot\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]string{"-config", path})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	tp, err := cfg.TrustedPrefixes()
	if err != nil || len(tp) != 1 || tp[0].String() != "10.0.0.0/8" {
		t.Errorf("trusted = %v, %v", tp, err)
	}
	dp, err := cfg.DenyPrefixes()
	if err != nil || len(dp) != 1 || dp[0].String() != "203.0.113.0/24" {
		t.Errorf("deny cidrs = %v, %v", dp, err)
	}
	if len(cfg.Deny.UserAgents) != 1 || cfg.Deny.UserAgents[0] != "GPTBot" {
		t.Errorf("deny uas = %v", cfg.Deny.UserAgents)
	}
}

func TestParseRejectsBadCIDR(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("upstream: \"http://a:1\"\ndeny:\n  cidrs: [\"not-a-cidr\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"-config", path}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}
