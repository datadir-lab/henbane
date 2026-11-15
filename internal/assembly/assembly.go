// Package assembly builds Henbane's stateful decision components from config.
// It is the single composition point shared by the standalone proxy (cmd) and
// the embeddable middleware (the public henbane package), so both wire detectors,
// the engine, the maze, the PoW gate, and the bomb identically. Being a
// composition root it imports adapters freely; it is not part of the pure core.
package assembly

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/datadir-lab/henbane/internal/adapters/challenge"
	"github.com/datadir-lab/henbane/internal/adapters/proxy"
	"github.com/datadir-lab/henbane/internal/adapters/report"
	"github.com/datadir-lab/henbane/internal/clientip"
	"github.com/datadir-lab/henbane/internal/config"
	"github.com/datadir-lab/henbane/internal/core"
	"github.com/datadir-lab/henbane/internal/detect/browserhint"
	"github.com/datadir-lab/henbane/internal/detect/denylist"
	"github.com/datadir-lab/henbane/internal/detect/goodbot"
	"github.com/datadir-lab/henbane/internal/detect/honeypot"
	"github.com/datadir-lab/henbane/internal/detect/remotedeny"
	"github.com/datadir-lab/henbane/internal/detect/velocity"
	"github.com/datadir-lab/henbane/internal/detect/webbotauth"
	"github.com/datadir-lab/henbane/internal/flagstore"
	"github.com/datadir-lab/henbane/internal/generate/bomb"
	"github.com/datadir-lab/henbane/internal/generate/labyrinth"
	"github.com/datadir-lab/henbane/internal/generate/poison"
	"github.com/datadir-lab/henbane/internal/generate/poison/article"
	"github.com/datadir-lab/henbane/internal/generate/poison/babble"
	"github.com/datadir-lab/henbane/internal/generate/poison/canary"
	"github.com/datadir-lab/henbane/internal/generate/poison/splice"
	"github.com/datadir-lab/henbane/internal/ports"
	"github.com/datadir-lab/henbane/internal/pow"
)

// FederationParts are the optional federation pieces assembled from config: the
// consumer detector (joins the engine), the reporter sink (joins the sinks), and
// the background tasks (feed refresher, report flusher) the caller must run under
// a cancellable context. Any may be empty when the corresponding half is off.
type FederationParts struct {
	Detectors  []ports.Detector
	Sinks      []ports.Sink
	Background []func(context.Context)
}

// Federation builds the optional federation consumer and reporter from cfg. It is
// shared by the CLI and the embeddable library so both wire federation (and its
// background tasks) identically.
func Federation(cfg config.Config, logger *slog.Logger) (FederationParts, error) {
	var fp FederationParts
	if cfg.Federation.FeedURL != "" {
		refresh, err := cfg.FederationRefresh()
		if err != nil {
			return FederationParts{}, err
		}
		maxEntries := cfg.Federation.MaxEntries
		if maxEntries == 0 {
			maxEntries = 1_000_000
		}
		det := remotedeny.New()
		fp.Detectors = append(fp.Detectors, det)
		fp.Background = append(fp.Background, remotedeny.NewRefresher(det, cfg.Federation.FeedURL, refresh, maxEntries, logger).Run)
	}
	if cfg.Federation.ReportURL != "" {
		rep := report.New(cfg.Federation.ReportURL, cfg.Federation.ReportToken, cfg.Federation.DeploymentID, logger)
		fp.Sinks = append(fp.Sinks, rep)
		fp.Background = append(fp.Background, rep.Run)
	}
	return fp, nil
}

// Components are the stateful decision pieces assembled from config. Sinks and
// the "allowed" origin (reverse proxy or host handler) are supplied by the
// caller, not here.
type Components struct {
	Engine   ports.Engine
	Resolver *clientip.Resolver
	Maze     proxy.MazeWriter
	PoW      proxy.PoW
	Bomb     proxy.Bomb
}

// WebBotAuth builds the Web Bot Auth detector when enabled, fetching the
// configured agent key directories at startup (fetch failures are logged and
// skipped; the keys refresh on restart). It returns nil when disabled, so the
// caller can append it to the engine's detectors only when present.
func WebBotAuth(cfg config.Config, logger *slog.Logger) ports.Detector {
	if !cfg.WebBotAuth.Enabled {
		return nil
	}
	tier := ports.TierBlocked
	switch cfg.WebBotAuth.Tier {
	case "suspect":
		tier = ports.TierSuspect
	case "confirmed":
		tier = ports.TierConfirmed
	}
	client := &http.Client{Timeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	var keys []webbotauth.Key
	for _, origin := range cfg.WebBotAuth.Directories {
		ks, err := webbotauth.FetchDirectory(ctx, client, origin)
		if err != nil {
			logger.Warn("webbotauth: directory fetch failed", "origin", origin, "err", err)
			continue
		}
		logger.Info("webbotauth: directory loaded", "origin", origin, "keys", len(ks))
		keys = append(keys, ks...)
	}
	return webbotauth.NewDetector(webbotauth.NewVerifier(keys), tier)
}

// Build assembles Components from cfg. Any extra detectors (e.g. a federation
// remote-denylist detector the caller also drives with a background refresher)
// are appended to the engine's detector list. It returns an error for any
// invalid sub-config (bad CIDR, unknown poison strategy, unreadable corpus, bad
// TTLs).
func Build(cfg config.Config, extra ...ports.Detector) (Components, error) {
	trusted, err := cfg.TrustedPrefixes()
	if err != nil {
		return Components{}, err
	}
	denyCIDRs, err := cfg.DenyPrefixes()
	if err != nil {
		return Components{}, err
	}

	var detectors []ports.Detector
	if len(denyCIDRs) > 0 {
		detectors = append(detectors, denylist.NewIP(denyCIDRs))
	}
	if len(cfg.Deny.UserAgents) > 0 {
		detectors = append(detectors, denylist.NewUA(cfg.Deny.UserAgents))
	}
	if len(cfg.Deny.TLSFingerprints) > 0 {
		detectors = append(detectors, denylist.NewTLSFP(cfg.Deny.TLSFingerprints))
	}
	if cfg.Honeypot.Enabled {
		ttl, err := cfg.HoneypotTTL()
		if err != nil {
			return Components{}, err
		}
		max := cfg.Honeypot.MaxFlagged
		if max <= 0 {
			max = 100000
		}
		detectors = append(detectors, honeypot.New(cfg.Honeypot.Path, flagstore.New(max, ttl)))
	}
	// In suspect mode the browser-hint signal populates the Suspect tier
	// (→ challenge). Under "all" everyone is already challenged; under "off" a
	// Suspect verdict has no handler, so the signal stays disabled.
	if cfg.PoW.Mode == "suspect" {
		detectors = append(detectors, browserhint.New())
	}
	if cfg.Velocity.Enabled {
		tier := ports.TierSuspect
		if cfg.Velocity.Tier == "confirmed" {
			tier = ports.TierConfirmed
		}
		window, err := cfg.VelocityWindow()
		if err != nil {
			return Components{}, err
		}
		requests := cfg.Velocity.Requests
		if requests == 0 {
			requests = 600
		}
		maxTracked := cfg.Velocity.MaxTracked
		if maxTracked == 0 {
			maxTracked = 100000
		}
		detectors = append(detectors, velocity.New(requests, window, maxTracked, tier))
	}
	detectors = append(detectors, extra...)

	poisoner, err := buildPoisoner(cfg)
	if err != nil {
		return Components{}, err
	}
	pw, err := buildPoW(cfg)
	if err != nil {
		return Components{}, err
	}
	engine := core.NewEngine(detectors...)
	if vs := buildVerifiers(cfg); len(vs) > 0 {
		engine.WithVerifiers(vs...)
	}
	return Components{
		Engine:   engine,
		Resolver: clientip.NewResolver(trusted),
		Maze:     labyrinth.New(cfg.Labyrinth.LinksPerPage, poisoner, cfg.Poison.ParagraphsPerPage),
		PoW:      pw,
		Bomb:     buildBomb(cfg, poisoner),
	}, nil
}

// buildVerifiers builds the engine's verifiers (currently the good-bot FCrDNS
// verifier) from config.
func buildVerifiers(cfg config.Config) []ports.Verifier {
	if !cfg.VerifiedBots.Enabled {
		return nil
	}
	crawlers := goodbot.Defaults()
	if len(cfg.VerifiedBots.Crawlers) > 0 {
		crawlers = crawlers[:0]
		for _, c := range cfg.VerifiedBots.Crawlers {
			crawlers = append(crawlers, goodbot.Crawler{Name: c.Name, UA: c.UA, Domains: c.Domains})
		}
	}
	spoofTier, blockSpoof := ports.TierBlocked, true
	switch cfg.VerifiedBots.SpoofTier {
	case "", "off":
		blockSpoof = false
	case "suspect":
		spoofTier = ports.TierSuspect
	case "confirmed":
		spoofTier = ports.TierConfirmed
	}
	return []ports.Verifier{goodbot.New(crawlers, spoofTier, blockSpoof)}
}

// buildBomb constructs the decompression-bomb response from config, reusing the
// configured poisoner for the bomb's payload. Trigger off/"" disables it.
func buildBomb(cfg config.Config, poisoner ports.Poisoner) proxy.Bomb {
	if cfg.Bomb.Trigger == "" || cfg.Bomb.Trigger == "off" {
		return proxy.Bomb{}
	}
	capBytes := int64(cfg.Bomb.DecompressedCapMB) << 20
	return proxy.Bomb{
		Writer:      bomb.New(poisoner, capBytes),
		OnConfirmed: cfg.Bomb.Trigger == "confirmed",
		OnBlocked:   cfg.Bomb.Trigger == "blocked",
	}
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

// buildPoisoner selects the configured poison strategy. corpus_path (babble and
// splice) is read here so the poison packages never touch the filesystem or
// config.
func buildPoisoner(cfg config.Config) (ports.Poisoner, error) {
	readCorpus := func() ([]byte, error) {
		if cfg.Poison.CorpusPath == "" {
			return nil, nil
		}
		b, err := os.ReadFile(cfg.Poison.CorpusPath)
		if err != nil {
			return nil, fmt.Errorf("read poison corpus %q: %w", cfg.Poison.CorpusPath, err)
		}
		return b, nil
	}
	switch cfg.Poison.Strategy {
	case "", "babble":
		corpus, err := readCorpus()
		if err != nil {
			return nil, err
		}
		return babble.New(corpus, cfg.Poison.Salt), nil
	case "splice":
		corpus, err := readCorpus()
		if err != nil {
			return nil, err
		}
		return splice.New(corpus, cfg.Poison.Salt), nil
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
