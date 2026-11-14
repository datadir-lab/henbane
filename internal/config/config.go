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

// Config is the Henbane configuration.
type Config struct {
	Listen         string   `yaml:"listen"`
	Upstream       string   `yaml:"upstream"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	Deny           Deny     `yaml:"deny"`
	Sinks          Sinks    `yaml:"sinks"`
	Honeypot       Honeypot `yaml:"honeypot"`
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
	tp, err := cfg.TrustedPrefixes()
	if err != nil {
		return Config{}, err
	}
	// Reject a literal default route (/0), the common footgun that trusts every
	// client. This does NOT catch equivalent broad unions (e.g. 0.0.0.0/1 +
	// 128.0.0.0/1); avoiding those remains the operator's responsibility.
	for _, p := range tp {
		if p.Bits() == 0 {
			return Config{}, fmt.Errorf("trusted_proxies %q is too broad: trusting all addresses re-enables X-Forwarded-For spoofing", p)
		}
	}
	if _, err := cfg.DenyPrefixes(); err != nil {
		return Config{}, err
	}
	if cfg.Honeypot.Enabled {
		if !strings.HasPrefix(cfg.Honeypot.Path, "/") {
			return Config{}, fmt.Errorf("honeypot.path must be an absolute path, got %q", cfg.Honeypot.Path)
		}
		if _, err := cfg.HoneypotTTL(); err != nil {
			return Config{}, err
		}
		if cfg.Honeypot.MaxFlagged < 0 {
			return Config{}, fmt.Errorf("honeypot.max_flagged must be >= 0")
		}
	}
	return cfg, nil
}
