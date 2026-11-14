// Package config loads Henbane configuration from a YAML file, with flag
// overrides and sane defaults.
package config

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the Henbane configuration.
type Config struct {
	Listen         string   `yaml:"listen"`
	Upstream       string   `yaml:"upstream"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	Deny           Deny     `yaml:"deny"`
	Sinks          Sinks    `yaml:"sinks"`
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
	for _, p := range tp {
		if p.Bits() == 0 {
			return Config{}, fmt.Errorf("trusted_proxies %q is too broad: trusting all addresses re-enables X-Forwarded-For spoofing", p)
		}
	}
	if _, err := cfg.DenyPrefixes(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
