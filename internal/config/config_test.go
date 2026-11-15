package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
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

func TestParseRejectsBroadTrustedProxy(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "henbane.yaml")
		body := "upstream: \"http://a:1\"\ntrusted_proxies: [\"" + cidr + "\"]\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Parse([]string{"-config", path}); err == nil {
			t.Errorf("trusted_proxies %q: expected rejection (trusting all re-enables spoofing)", cidr)
		}
	}
}

func TestParseHoneypot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "henbane.yaml")
	body := "upstream: \"http://a:1\"\nhoneypot:\n  enabled: true\n  path: \"/.well-known/hb-trap\"\n  flag_ttl: \"30m\"\n  max_flagged: 5\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]string{"-config", path})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.Honeypot.Enabled || cfg.Honeypot.Path != "/.well-known/hb-trap" || cfg.Honeypot.MaxFlagged != 5 {
		t.Errorf("honeypot = %+v", cfg.Honeypot)
	}
	ttl, err := cfg.HoneypotTTL()
	if err != nil || ttl != 30*time.Minute {
		t.Errorf("ttl = %v, %v", ttl, err)
	}
}

func TestHoneypotTTLDefault(t *testing.T) {
	ttl, err := Config{}.HoneypotTTL()
	if err != nil || ttl != time.Hour {
		t.Errorf("default ttl = %v, %v", ttl, err)
	}
}

func TestParseRejectsEnabledHoneypotWithoutPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "henbane.yaml")
	if err := os.WriteFile(path, []byte("upstream: \"http://a:1\"\nhoneypot:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"-config", path}); err == nil {
		t.Fatal("expected error: enabled honeypot needs an absolute path")
	}
}

func TestParseRejectsBadFlagTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "henbane.yaml")
	if err := os.WriteFile(path, []byte("upstream: \"http://a:1\"\nhoneypot:\n  enabled: true\n  path: \"/t\"\n  flag_ttl: \"nope\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"-config", path}); err == nil {
		t.Fatal("expected error for invalid flag_ttl")
	}
}

func TestParseLabyrinth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "henbane.yaml")
	if err := os.WriteFile(path, []byte("upstream: \"http://a:1\"\nlabyrinth:\n  links_per_page: 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]string{"-config", path})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Labyrinth.LinksPerPage != 7 {
		t.Errorf("links_per_page = %d, want 7", cfg.Labyrinth.LinksPerPage)
	}
}

func TestParseRejectsNegativeLinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "henbane.yaml")
	if err := os.WriteFile(path, []byte("upstream: \"http://a:1\"\nlabyrinth:\n  links_per_page: -1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"-config", path}); err == nil {
		t.Fatal("expected error for negative links_per_page")
	}
}

func parsePoison(t *testing.T, body string) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "henbane.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Parse([]string{"-config", path})
}

func TestParsePoisonDefaultStrategy(t *testing.T) {
	cfg, err := parsePoison(t, "upstream: \"http://a:1\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Poison.Strategy != "" {
		t.Errorf("strategy = %q, want \"\" (defaults to babble downstream)", cfg.Poison.Strategy)
	}
}

func TestParsePoisonValidStrategies(t *testing.T) {
	for _, s := range []string{"babble", "splice", "article", "canary", "none"} {
		body := "upstream: \"http://a:1\"\npoison:\n  strategy: \"" + s + "\"\n  salt: \"x\"\n"
		if _, err := parsePoison(t, body); err != nil {
			t.Errorf("strategy %q rejected: %v", s, err)
		}
	}
}

func TestParsePoisonUnknownStrategy(t *testing.T) {
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\npoison:\n  strategy: \"bogus\"\n"); err == nil {
		t.Error("expected error for unknown poison.strategy")
	}
}

func TestParsePoisonCanaryRequiresSalt(t *testing.T) {
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\npoison:\n  strategy: \"canary\"\n"); err == nil {
		t.Error("canary without salt must be rejected")
	}
}

func TestParsePoisonNegativeParagraphs(t *testing.T) {
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\npoison:\n  paragraphs_per_page: -1\n"); err == nil {
		t.Error("negative paragraphs_per_page must be rejected")
	}
}

func TestParsePoisonRoundTrip(t *testing.T) {
	body := "upstream: \"http://a:1\"\npoison:\n  strategy: \"babble\"\n  paragraphs_per_page: 4\n  corpus_path: \"/tmp/c.txt\"\n  salt: \"deploy1\"\n"
	cfg, err := parsePoison(t, body)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Poison.ParagraphsPerPage != 4 || cfg.Poison.CorpusPath != "/tmp/c.txt" || cfg.Poison.Salt != "deploy1" {
		t.Errorf("poison = %+v", cfg.Poison)
	}
}

func TestParsePoWValidModes(t *testing.T) {
	for _, m := range []string{"off", "suspect", "all"} {
		if _, err := parsePoison(t, "upstream: \"http://a:1\"\npow:\n  mode: \""+m+"\"\n"); err != nil {
			t.Errorf("pow.mode %q rejected: %v", m, err)
		}
	}
}

func TestParsePoWUnknownMode(t *testing.T) {
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\npow:\n  mode: \"bogus\"\n"); err == nil {
		t.Error("expected error for unknown pow.mode")
	}
}

func TestParsePoWNegativeDifficulty(t *testing.T) {
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\npow:\n  difficulty_bits: -1\n"); err == nil {
		t.Error("negative pow.difficulty_bits must be rejected")
	}
}

func TestParsePoWBadTTL(t *testing.T) {
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\npow:\n  challenge_ttl: \"nope\"\n"); err == nil {
		t.Error("invalid pow.challenge_ttl must be rejected")
	}
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\npow:\n  access_ttl: \"-5m\"\n"); err == nil {
		t.Error("negative pow.access_ttl must be rejected")
	}
}

func TestParsePoWRoundTripAndTTLDefaults(t *testing.T) {
	cfg, err := parsePoison(t, "upstream: \"http://a:1\"\npow:\n  mode: \"all\"\n  difficulty_bits: 18\n  secret: \"s3cr3t\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PoW.Mode != "all" || cfg.PoW.DifficultyBits != 18 || cfg.PoW.Secret != "s3cr3t" {
		t.Errorf("pow = %+v", cfg.PoW)
	}
	ch, _ := cfg.PoWChallengeTTL()
	ac, _ := cfg.PoWAccessTTL()
	if ch != 5*time.Minute || ac != time.Hour {
		t.Errorf("default TTLs = %v / %v, want 5m / 1h", ch, ac)
	}
}

func TestParseBombValidTriggers(t *testing.T) {
	for _, tr := range []string{"off", "confirmed", "blocked"} {
		if _, err := parsePoison(t, "upstream: \"http://a:1\"\nbomb:\n  trigger: \""+tr+"\"\n"); err != nil {
			t.Errorf("bomb.trigger %q rejected: %v", tr, err)
		}
	}
}

func TestParseBombUnknownTrigger(t *testing.T) {
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\nbomb:\n  trigger: \"nuke\"\n"); err == nil {
		t.Error("expected error for unknown bomb.trigger")
	}
}

func TestParseBombNegativeCap(t *testing.T) {
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\nbomb:\n  decompressed_cap_mb: -1\n"); err == nil {
		t.Error("negative bomb.decompressed_cap_mb must be rejected")
	}
}

func TestParseBombRoundTrip(t *testing.T) {
	cfg, err := parsePoison(t, "upstream: \"http://a:1\"\nbomb:\n  trigger: \"confirmed\"\n  decompressed_cap_mb: 128\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Bomb.Trigger != "confirmed" || cfg.Bomb.DecompressedCapMB != 128 {
		t.Errorf("bomb = %+v", cfg.Bomb)
	}
}

func TestParseRobotsDisallowMustBeAbsolute(t *testing.T) {
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\nrobots:\n  serve: true\n  disallow: [\"relative\"]\n"); err == nil {
		t.Error("non-absolute robots.disallow entry must be rejected")
	}
}

func TestParseRobotsRoundTrip(t *testing.T) {
	cfg, err := parsePoison(t, "upstream: \"http://a:1\"\nrobots:\n  serve: true\n  disallow: [\"/private\", \"/admin\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Robots.Serve || len(cfg.Robots.Disallow) != 2 || cfg.Robots.Disallow[0] != "/private" {
		t.Errorf("robots = %+v", cfg.Robots)
	}
}

func TestParseVelocityConfirmedRoundTrip(t *testing.T) {
	cfg, err := parsePoison(t, "upstream: \"http://a:1\"\nvelocity:\n  enabled: true\n  requests: 300\n  window: \"30s\"\n  tier: \"confirmed\"\n  max_tracked: 5000\n")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Velocity.Enabled || cfg.Velocity.Requests != 300 || cfg.Velocity.Tier != "confirmed" || cfg.Velocity.MaxTracked != 5000 {
		t.Errorf("velocity = %+v", cfg.Velocity)
	}
	if w, err := cfg.VelocityWindow(); err != nil || w != 30*time.Second {
		t.Errorf("window = %v, %v; want 30s", w, err)
	}
}

func TestParseVelocitySuspectRequiresPoW(t *testing.T) {
	// Default tier is suspect; with pow off this maps to an unhandled challenge.
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\nvelocity:\n  enabled: true\n"); err == nil {
		t.Error("velocity.tier suspect with pow off must be rejected")
	}
}

func TestParseVelocitySuspectWithPoWAllowed(t *testing.T) {
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\npow:\n  mode: \"suspect\"\nvelocity:\n  enabled: true\n  tier: \"suspect\"\n"); err != nil {
		t.Errorf("velocity suspect with pow suspect must be accepted: %v", err)
	}
}

func TestParseVelocityConfirmedNeedsNoPoW(t *testing.T) {
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\nvelocity:\n  enabled: true\n  tier: \"confirmed\"\n"); err != nil {
		t.Errorf("velocity confirmed must not require pow: %v", err)
	}
}

func TestParseVelocityRejectsBadFields(t *testing.T) {
	cases := map[string]string{
		"bad tier":      "upstream: \"http://a:1\"\nvelocity:\n  enabled: true\n  tier: \"bogus\"\n",
		"negative reqs": "upstream: \"http://a:1\"\nvelocity:\n  enabled: true\n  tier: \"confirmed\"\n  requests: -1\n",
		"negative max":  "upstream: \"http://a:1\"\nvelocity:\n  enabled: true\n  tier: \"confirmed\"\n  max_tracked: -1\n",
		"bad window":    "upstream: \"http://a:1\"\nvelocity:\n  enabled: true\n  tier: \"confirmed\"\n  window: \"nope\"\n",
		"zero window":   "upstream: \"http://a:1\"\nvelocity:\n  enabled: true\n  tier: \"confirmed\"\n  window: \"0s\"\n",
	}
	for name, body := range cases {
		if _, err := parsePoison(t, body); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestParseVelocityDisabledIgnoresFields(t *testing.T) {
	// When disabled, invalid sub-fields must not trip validation.
	if _, err := parsePoison(t, "upstream: \"http://a:1\"\nvelocity:\n  enabled: false\n  tier: \"bogus\"\n  requests: -5\n"); err != nil {
		t.Errorf("disabled velocity must skip validation: %v", err)
	}
}
