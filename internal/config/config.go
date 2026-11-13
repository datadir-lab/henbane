// Package config loads Henbane configuration from a YAML file, with flag
// overrides and sane defaults.
package config

import (
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the Henbane configuration.
type Config struct {
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
}

// Default returns the zero-config defaults.
func Default() Config {
	return Config{Listen: ":8080", Upstream: ""}
}

// LoadFile returns defaults merged with the YAML at path. Empty path => defaults.
func LoadFile(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
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
	return cfg, nil
}
