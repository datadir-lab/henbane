// Package config loads Henbane configuration from a YAML file, with flag
// overrides and sane defaults.
package config

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Honeypot configures the trap-path honeypot detector.
type Honeypot struct {
	Enabled    bool   `yaml:"enabled"`
	Path       string `yaml:"path"`        // absolute path prefix of the trap
	FlagTTL    string `yaml:"flag_ttl"`    // e.g. "1h"; default 1h
	MaxFlagged int    `yaml:"max_flagged"` // hard cap; 0 => default 100000
}

// Labyrinth configures the maze served to confirmed crawlers.
type Labyrinth struct {
	LinksPerPage int `yaml:"links_per_page"` // 0 => generator default (15)
}

// Poison configures the poison body text injected into maze pages.
type Poison struct {
	Strategy          string `yaml:"strategy"`            // babble|splice|article|canary|none; "" => babble
	ParagraphsPerPage int    `yaml:"paragraphs_per_page"` // 0 => default 3; clamped [0,20] downstream
	CorpusPath        string `yaml:"corpus_path"`         // optional BYO corpus (babble, splice); ignored by article/canary
	Salt              string `yaml:"salt"`                // per-deployment; required for canary
}

// Robots configures the robots.txt Henbane serves. When enabled it Disallows the
// honeypot trap (so well-behaved crawlers avoid it, and any client that fetches it
// is provably ignoring robots.txt → caught by the honeypot).
type Robots struct {
	Serve    bool     `yaml:"serve"`    // if true, Henbane serves /robots.txt
	Disallow []string `yaml:"disallow"` // extra paths to Disallow (operator's own)
}

// Bomb configures the decompression-bomb poison response. Off by default; only
// ever fires on a confirmed-hostile tier for a gzip-capable client.
type Bomb struct {
	Trigger           string `yaml:"trigger"`             // off|confirmed|blocked; "" => off
	DecompressedCapMB int    `yaml:"decompressed_cap_mb"` // 0 => default 64; clamped to [1,1024] downstream
}

// Velocity configures the request-rate detector. When enabled, a client IP that
// exceeds Requests within Window is classified at Tier. The counter keys on the
// resolved client IP and is hard-bounded at MaxTracked entries.
type Velocity struct {
	Enabled    bool   `yaml:"enabled"`
	Requests   int    `yaml:"requests"`    // per-window limit before firing; 0 => default 600
	Window     string `yaml:"window"`      // e.g. "1m"; default 1m
	Tier       string `yaml:"tier"`        // suspect|confirmed; "" => suspect
	MaxTracked int    `yaml:"max_tracked"` // hard cap on tracked IPs; 0 => default 100000
}

// Metrics configures the Prometheus-style metrics endpoint. It is served on a
// SEPARATE listener so aggregate operational data never rides the public proxy
// path; bind Listen to a private interface. Empty Listen => disabled.
type Metrics struct {
	Listen string `yaml:"listen"`
}

// PoW configures the proof-of-work challenge gate.
type PoW struct {
	Mode           string `yaml:"mode"`            // off|suspect|all; "" => off
	DifficultyBits int    `yaml:"difficulty_bits"` // 0 => default 20; clamped [8,32] downstream
	ChallengeTTL   string `yaml:"challenge_ttl"`   // e.g. "5m"; default 5m
	AccessTTL      string `yaml:"access_ttl"`      // e.g. "1h"; default 1h
	Secret         string `yaml:"secret"`          // optional; random per start if empty
}

// Config is the Henbane configuration.
type Config struct {
	Listen         string    `yaml:"listen"`
	Upstream       string    `yaml:"upstream"`
	TrustedProxies []string  `yaml:"trusted_proxies"`
	Deny           Deny      `yaml:"deny"`
	Sinks          Sinks     `yaml:"sinks"`
	Honeypot       Honeypot  `yaml:"honeypot"`
	Labyrinth      Labyrinth `yaml:"labyrinth"`
	Poison         Poison    `yaml:"poison"`
	PoW            PoW       `yaml:"pow"`
	Bomb           Bomb      `yaml:"bomb"`
	Robots         Robots    `yaml:"robots"`
	Velocity       Velocity  `yaml:"velocity"`
	Metrics        Metrics   `yaml:"metrics"`
}

// PoWChallengeTTL parses PoW.ChallengeTTL, defaulting to 5m; must be positive.
func (c Config) PoWChallengeTTL() (time.Duration, error) {
	return parseTTL(c.PoW.ChallengeTTL, 5*time.Minute, "pow.challenge_ttl")
}

// PoWAccessTTL parses PoW.AccessTTL, defaulting to 1h; must be positive.
func (c Config) PoWAccessTTL() (time.Duration, error) {
	return parseTTL(c.PoW.AccessTTL, time.Hour, "pow.access_ttl")
}

// VelocityWindow parses Velocity.Window, defaulting to 1m; must be positive.
func (c Config) VelocityWindow() (time.Duration, error) {
	return parseTTL(c.Velocity.Window, time.Minute, "velocity.window")
}

func parseTTL(s string, def time.Duration, name string) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", name, s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %q", name, s)
	}
	return d, nil
}

// Deny is the operator denylist.
type Deny struct {
	CIDRs      []string `yaml:"cidrs"`
	UserAgents []string `yaml:"user_agents"` // case-insensitive substrings
}

// Sinks configures optional output sinks.
type Sinks struct {
	Fail2ban Fail2ban `yaml:"fail2ban"`
}

// Fail2ban configures the fail2ban ban-line sink.
type Fail2ban struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// TrustedPrefixes parses TrustedProxies into CIDRs.
func (c Config) TrustedPrefixes() ([]netip.Prefix, error) { return parsePrefixes(c.TrustedProxies) }

// DenyPrefixes parses Deny.CIDRs into CIDRs.
func (c Config) DenyPrefixes() ([]netip.Prefix, error) { return parsePrefixes(c.Deny.CIDRs) }

// HoneypotTTL parses FlagTTL, defaulting to 1h. It must be positive.
func (c Config) HoneypotTTL() (time.Duration, error) {
	if c.Honeypot.FlagTTL == "" {
		return time.Hour, nil
	}
	d, err := time.ParseDuration(c.Honeypot.FlagTTL)
	if err != nil {
		return 0, fmt.Errorf("invalid honeypot.flag_ttl %q: %w", c.Honeypot.FlagTTL, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("honeypot.flag_ttl must be positive, got %q", c.Honeypot.FlagTTL)
	}
	return d, nil
}

func parsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Default returns the zero-config defaults.
func Default() Config {
	return Config{Listen: ":8080", Upstream: ""}
}

// LoadFile returns defaults merged with the YAML at path. Empty path => defaults.
func LoadFile(path string) (Config, error) {
	if path == "" {
		return Default(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	loaded := Default()
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return loaded, nil
}

// Parse builds a Config from command-line args. Non-empty flags override the
// file; Upstream is required.
func Parse(args []string) (Config, error) {
	fs := flag.NewFlagSet("henbane", flag.ContinueOnError)
	var path, listen, upstream string
	fs.StringVar(&path, "config", "", "path to henbane.yaml")
	fs.StringVar(&listen, "listen", "", "listen address, e.g. :8080")
	fs.StringVar(&upstream, "upstream", "", "upstream base URL")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg, err := LoadFile(path)
	if err != nil {
		return Config{}, err
	}
	if listen != "" {
		cfg.Listen = listen
	}
	if upstream != "" {
		cfg.Upstream = upstream
	}
	if cfg.Upstream == "" {
		return Config{}, fmt.Errorf("upstream is required (set --upstream or upstream: in config)")
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	// Metrics must not share the public listener, or aggregate operational data
	// would be exposed on the proxy path to every client (crawlers included).
	// This is a CLI-server concern (listen addresses), so it lives here, not in
	// Validate, which covers the transport-agnostic component config.
	if cfg.Metrics.Listen != "" && cfg.Metrics.Listen == cfg.Listen {
		return Config{}, fmt.Errorf("metrics.listen must differ from listen (%q): serve metrics on a separate, private interface", cfg.Listen)
	}
	return cfg, nil
}

// Validate checks the transport-agnostic component configuration — everything
// the detectors, engine, maze, PoW gate, and bomb are built from. It is shared
// by Parse (the CLI) and the embeddable middleware, so both reject the same bad
// config. It does NOT check CLI-only fields (upstream, listen addresses).
func Validate(cfg Config) error {
	tp, err := cfg.TrustedPrefixes()
	if err != nil {
		return err
	}
	// Reject a literal default route (/0), the common footgun that trusts every
	// client. This does NOT catch equivalent broad unions (e.g. 0.0.0.0/1 +
	// 128.0.0.0/1); avoiding those remains the operator's responsibility.
	for _, p := range tp {
		if p.Bits() == 0 {
			return fmt.Errorf("trusted_proxies %q is too broad: trusting all addresses re-enables X-Forwarded-For spoofing", p)
		}
	}
	if _, err := cfg.DenyPrefixes(); err != nil {
		return err
	}
	if cfg.Honeypot.Enabled {
		if !strings.HasPrefix(cfg.Honeypot.Path, "/") {
			return fmt.Errorf("honeypot.path must be an absolute path, got %q", cfg.Honeypot.Path)
		}
		if _, err := cfg.HoneypotTTL(); err != nil {
			return err
		}
		if cfg.Honeypot.MaxFlagged < 0 {
			return fmt.Errorf("honeypot.max_flagged must be >= 0")
		}
	}
	if cfg.Labyrinth.LinksPerPage < 0 {
		return fmt.Errorf("labyrinth.links_per_page must be >= 0")
	}
	switch cfg.Poison.Strategy {
	case "", "babble", "splice", "article", "canary", "none":
	default:
		return fmt.Errorf("poison.strategy %q is not one of babble|splice|article|canary|none", cfg.Poison.Strategy)
	}
	if cfg.Poison.ParagraphsPerPage < 0 {
		return fmt.Errorf("poison.paragraphs_per_page must be >= 0")
	}
	if cfg.Poison.Strategy == "canary" && cfg.Poison.Salt == "" {
		return fmt.Errorf("poison.salt is required when poison.strategy is canary")
	}
	switch cfg.PoW.Mode {
	case "", "off", "suspect", "all":
	default:
		return fmt.Errorf("pow.mode %q is not one of off|suspect|all", cfg.PoW.Mode)
	}
	if cfg.PoW.DifficultyBits < 0 {
		return fmt.Errorf("pow.difficulty_bits must be >= 0")
	}
	if _, err := cfg.PoWChallengeTTL(); err != nil {
		return err
	}
	if _, err := cfg.PoWAccessTTL(); err != nil {
		return err
	}
	switch cfg.Bomb.Trigger {
	case "", "off", "confirmed", "blocked":
	default:
		return fmt.Errorf("bomb.trigger %q is not one of off|confirmed|blocked", cfg.Bomb.Trigger)
	}
	if cfg.Bomb.DecompressedCapMB < 0 {
		return fmt.Errorf("bomb.decompressed_cap_mb must be >= 0")
	}
	if cfg.Robots.Serve {
		for _, p := range cfg.Robots.Disallow {
			if !strings.HasPrefix(p, "/") {
				return fmt.Errorf("robots.disallow entry %q must be an absolute path", p)
			}
		}
	}
	if cfg.Velocity.Enabled {
		tier := cfg.Velocity.Tier
		switch tier {
		case "", "suspect", "confirmed":
		default:
			return fmt.Errorf("velocity.tier %q is not one of suspect|confirmed", tier)
		}
		if tier == "" {
			tier = "suspect"
		}
		// A suspect verdict maps to a proof-of-work challenge; without a gate the
		// gate fails that request closed (500). Reject the combination rather than
		// silently 500 real traffic.
		if tier == "suspect" && cfg.PoW.Mode != "suspect" && cfg.PoW.Mode != "all" {
			return fmt.Errorf("velocity.tier: suspect requires pow.mode suspect or all (a suspect verdict needs a proof-of-work gate); enable pow or use velocity.tier: confirmed")
		}
		if cfg.Velocity.Requests < 0 {
			return fmt.Errorf("velocity.requests must be >= 0")
		}
		if cfg.Velocity.MaxTracked < 0 {
			return fmt.Errorf("velocity.max_tracked must be >= 0")
		}
		if _, err := cfg.VelocityWindow(); err != nil {
			return err
		}
	}
	return nil
}
