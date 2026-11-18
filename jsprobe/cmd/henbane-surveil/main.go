// Command henbane-surveil is the opt-in device/behavioural fingerprinting build of
// Henbane. It is the ordinary reverse proxy and engine, but a Suspect client is
// challenged with the jsprobe device probe (via henbane.WithChallenger) instead of the
// plain proof-of-work puzzle, so a bot that would solve the PoW is still caught by its
// browser fingerprint or lack of human-like input.
//
// This binary SURVEILS: it fingerprints the browser of flagged visitors. That is exactly
// what the core refuses, which is why it is a separate build. It probes only clients the
// classifier already flagged (set pow.mode: suspect), unless you deliberately set
// pow.mode: all to probe everyone. For the probe to fire, the config must produce Suspect
// verdicts: enable scoring and/or velocity with pow.mode: suspect.
//
// jsprobe config is NOT read from henbane.yaml (the core rejects unknown keys); it is set
// by flags here. Usage:
//
//	henbane-surveil --config henbane.yaml --jsprobe-tier device
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/datadir-lab/henbane"
	"github.com/datadir-lab/henbane/jsprobe"
	"github.com/datadir-lab/henbane/tlsfp"
)

const verifyPath = "/.well-known/hb-probe-verify"

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(os.Args[1:], logger); err != nil {
		logger.Error("henbane-surveil stopped", "err", err)
		os.Exit(1)
	}
}

func run(args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("henbane-surveil", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to henbane.yaml")
	tierName := fs.String("jsprobe-tier", "passive", "probe depth: passive | behavioural | device")
	deviceDeny := fs.String("jsprobe-device-deny", "", "comma-separated device-fingerprint denylist (device tier)")
	upstream := fs.String("upstream", "", "upstream origin URL (overrides config)")
	listen := fs.String("listen", "", "listen address (overrides config)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	tier, err := parseTier(*tierName)
	if err != nil {
		return err
	}

	cfg, err := henbane.LoadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if *upstream != "" {
		cfg.Upstream = *upstream
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	up, err := url.Parse(cfg.Upstream)
	if err != nil || up.Scheme == "" || up.Host == "" {
		return fmt.Errorf("invalid upstream %q: want an absolute URL like http://127.0.0.1:8080", cfg.Upstream)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	gate := jsprobe.New(secret, tier, time.Hour, verifyPath, cfg.TLS.Cert != "", splitCSV(*deviceDeny))

	hb, err := henbane.New(cfg, henbane.WithLogger(logger), henbane.WithChallenger(gate, verifyPath))
	if err != nil {
		return err
	}

	rp := httputil.NewSingleHostReverseProxy(up)
	rp.ErrorLog = slog.NewLogLogger(logger.Handler(), slog.LevelError)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("upstream proxy error", "err", err, "path", r.URL.Path)
		w.WriteHeader(http.StatusBadGateway)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           hb.Handler(rp),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hb.Start(ctx)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("henbane-surveil starting", "version", version, "listen", cfg.Listen,
			"upstream", cfg.Upstream, "jsprobe_tier", *tierName, "probe_scope", probeScope(cfg))
		err := listenAndServe(srv, cfg)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// listenAndServe runs srv over plain HTTP, or terminates TLS with the JA4
// fingerprint-capturing listener when tls.cert/key are set.
func listenAndServe(srv *http.Server, cfg henbane.Config) error {
	if cfg.TLS.Cert == "" {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			return err
		}
		return srv.Serve(ln)
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		return fmt.Errorf("load tls cert: %w", err)
	}
	tlsCfg := tlsfp.DecorateConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	srv.ConnContext = tlsfp.ConnContext
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	return srv.Serve(tls.NewListener(tlsfp.WrapListener(ln), tlsCfg))
}

func parseTier(s string) (jsprobe.Tier, error) {
	switch strings.ToLower(s) {
	case "passive", "":
		return jsprobe.Passive, nil
	case "behavioural", "behavioral":
		return jsprobe.Behavioural, nil
	case "device":
		return jsprobe.Device, nil
	default:
		return 0, fmt.Errorf("jsprobe-tier %q is not one of passive|behavioural|device", s)
	}
}

func probeScope(cfg henbane.Config) string {
	if cfg.PoW.Mode == "all" {
		return "everyone"
	}
	return "suspect-only"
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
