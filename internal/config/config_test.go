package config

import (
	"os"
	"path/filepath"
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
