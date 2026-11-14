package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"

	"github.com/datadir-lab/henbane/internal/adapters/challenge"
	"github.com/datadir-lab/henbane/internal/adapters/proxy"
	"github.com/datadir-lab/henbane/internal/adapters/sink"
	"github.com/datadir-lab/henbane/internal/clientip"
	"github.com/datadir-lab/henbane/internal/config"
	"github.com/datadir-lab/henbane/internal/core"
	"github.com/datadir-lab/henbane/internal/detect/browserhint"
	"github.com/datadir-lab/henbane/internal/detect/denylist"
	"github.com/datadir-lab/henbane/internal/detect/honeypot"
	"github.com/datadir-lab/henbane/internal/flagstore"
	"github.com/datadir-lab/henbane/internal/generate/labyrinth"
	"github.com/datadir-lab/henbane/internal/generate/poison"
	"github.com/datadir-lab/henbane/internal/generate/poison/article"
	"github.com/datadir-lab/henbane/internal/generate/poison/babble"
	"github.com/datadir-lab/henbane/internal/generate/poison/canary"
	"github.com/datadir-lab/henbane/internal/ports"
	"github.com/datadir-lab/henbane/internal/pow"
)

// newHandler wires config into the resolver, engine, sinks, and proxy adapter.
// If fail2banW is non-nil a fail2ban sink writing to it is added; the caller
// owns that writer's lifecycle (opening and closing it).
func newHandler(cfg config.Config, logger *slog.Logger, fail2banW io.Writer) (http.Handler, error) {
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream %q: %w", cfg.Upstream, err)
	}
	if upstream.Scheme == "" || upstream.Host == "" {
		return nil, fmt.Errorf("invalid upstream %q: missing scheme or host", cfg.Upstream)
	}

	trusted, err := cfg.TrustedPrefixes()
	if err != nil {
		return nil, err
	}
	denyCIDRs, err := cfg.DenyPrefixes()
	if err != nil {
		return nil, err
	}

	var detectors []ports.Detector
	if len(denyCIDRs) > 0 {
		detectors = append(detectors, denylist.NewIP(denyCIDRs))
	}
	if len(cfg.Deny.UserAgents) > 0 {
		detectors = append(detectors, denylist.NewUA(cfg.Deny.UserAgents))
	}

	if cfg.Honeypot.Enabled {
		ttl, err := cfg.HoneypotTTL()
		if err != nil {
			return nil, err
		}
		max := cfg.Honeypot.MaxFlagged
		if max <= 0 {
			max = 100000
		}
		detectors = append(detectors, honeypot.New(cfg.Honeypot.Path, flagstore.New(max, ttl)))
	}

	// In suspect mode the browser-hint signal is what populates the Suspect tier
	// (→ challenge). Under "all" everyone is already challenged; under "off" a
	// Suspect verdict has no handler, so the signal stays disabled.
	if cfg.PoW.Mode == "suspect" {
		detectors = append(detectors, browserhint.New())
	}

	engine := core.NewEngine(detectors...)
	resolver := clientip.NewResolver(trusted)

	sinks := []ports.Sink{sink.NewSlogSink(logger)}
	if fail2banW != nil {
		sinks = append(sinks, sink.NewFail2banSink(fail2banW))
	}

	poisoner, err := buildPoisoner(cfg)
	if err != nil {
		return nil, err
	}
	maze := labyrinth.New(cfg.Labyrinth.LinksPerPage, poisoner, cfg.Poison.ParagraphsPerPage)
	pw, err := buildPoW(cfg)
	if err != nil {
		return nil, err
	}
	return proxy.New(upstream, engine, sinks, logger, resolver, maze, pw), nil
}

// buildPoW constructs the proof-of-work gate from config. Mode off/"" disables it.
// An empty secret means a fresh random secret per start (tokens reset on restart);
// set pow.secret for stable tokens across restarts or multiple instances.
func buildPoW(cfg config.Config) (proxy.PoW, error) {
	if cfg.PoW.Mode == "" || cfg.PoW.Mode == "off" {
		return proxy.PoW{}, nil
	}
	secret := []byte(cfg.PoW.Secret)
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return proxy.PoW{}, fmt.Errorf("generate pow secret: %w", err)
		}
	}
	bits := cfg.PoW.DifficultyBits
	if bits == 0 {
		bits = 20
	}
	chTTL, err := cfg.PoWChallengeTTL()
	if err != nil {
		return proxy.PoW{}, err
	}
	acTTL, err := cfg.PoWAccessTTL()
	if err != nil {
		return proxy.PoW{}, err
	}
	gate := pow.New(secret, bits, chTTL, acTTL)
	return proxy.PoW{
		Challenger:   challenge.New(gate, false),
		VerifyPath:   challenge.VerifyPath,
		ChallengeAll: cfg.PoW.Mode == "all",
	}, nil
}

// buildPoisoner selects the configured poison strategy. corpus_path (babble only)
// is read here so the poison packages never touch the filesystem or config.
func buildPoisoner(cfg config.Config) (ports.Poisoner, error) {
	switch cfg.Poison.Strategy {
	case "", "babble":
		var corpus []byte
		if cfg.Poison.CorpusPath != "" {
			b, err := os.ReadFile(cfg.Poison.CorpusPath)
			if err != nil {
				return nil, fmt.Errorf("read poison corpus %q: %w", cfg.Poison.CorpusPath, err)
			}
			corpus = b
		}
		return babble.New(corpus, cfg.Poison.Salt), nil
	case "article":
		return article.New(cfg.Poison.Salt), nil
	case "canary":
		return canary.New(cfg.Poison.Salt), nil
	case "none":
		return poison.None{}, nil
	default:
		return nil, fmt.Errorf("unknown poison.strategy %q", cfg.Poison.Strategy)
	}
}
