// Command henbane-h2 is a standalone Henbane reverse proxy that captures the
// client's HTTP/2 (Akamai) fingerprint in addition to the TLS fingerprint, feeding
// both to the classifier as anti-spoofing signals.
//
// It is a separate binary in the h2capture module because capturing the HTTP/2
// fingerprint needs golang.org/x/net/http2 — a dependency the shipped `henbane`
// binary's zero-dependency core must not take. The shipped binary captures the TLS
// fingerprint but not the HTTP/2 one; this binary captures both. Everything else —
// config, classifier, maze, poison, proof-of-work, metrics, federation — is the same
// embeddable engine the shipped binary runs, driven from the same henbane.yaml.
//
// HTTP/2 fingerprinting requires Henbane to terminate the client's TLS connection, so
// tls.cert and tls.key must be set in the config: a plain-HTTP listener or an upstream
// TLS terminator leaves nothing to fingerprint. Usage:
//
//	henbane-h2 --config henbane.yaml
//	henbane-h2 --config henbane.yaml --listen :8443 --upstream http://127.0.0.1:8080
package main

import (
	"context"
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
	"syscall"
	"time"

	"github.com/datadir-lab/henbane"
	"github.com/datadir-lab/henbane/h2capture"
	"github.com/datadir-lab/henbane/tlsfp"
)

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(os.Args[1:], logger); err != nil {
		logger.Error("henbane-h2 stopped", "err", err)
		os.Exit(1)
	}
}

func run(args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("henbane-h2", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to henbane.yaml (tls.cert/key must be set)")
	upstream := fs.String("upstream", "", "upstream origin URL (overrides config)")
	listen := fs.String("listen", "", "listen address (overrides config)")
	if err := fs.Parse(args); err != nil {
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
	if cfg.TLS.Cert == "" || cfg.TLS.Key == "" {
		return errors.New("tls.cert and tls.key are required: HTTP/2 fingerprinting needs direct TLS termination")
	}
	up, err := url.Parse(cfg.Upstream)
	if err != nil || up.Scheme == "" || up.Host == "" {
		return fmt.Errorf("invalid upstream %q: want an absolute URL like http://127.0.0.1:8080", cfg.Upstream)
	}

	hb, err := henbane.New(cfg, henbane.WithLogger(logger))
	if err != nil {
		return err
	}

	rp := httputil.NewSingleHostReverseProxy(up)
	rp.ErrorLog = slog.NewLogLogger(logger.Handler(), slog.LevelError)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("upstream proxy error", "err", err, "path", r.URL.Path)
		w.WriteHeader(http.StatusBadGateway)
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		return fmt.Errorf("load tls cert: %w", err)
	}
	// DecorateConfig captures the TLS fingerprint during the handshake; Enable (below)
	// adds the HTTP/2 fingerprint and advertises "h2" via ALPN. Both share this config.
	tlsCfg := tlsfp.DecorateConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           hb.Handler(rp),
		TLSConfig:         tlsCfg,
		ConnContext:       tlsfp.ConnContext, // TLS fingerprint on the HTTP/1.1 path
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	// Enable installs the HTTP/2 fingerprint-capture hook. It also propagates the TLS
	// fingerprint onto HTTP/2 connections (which x/net/http2 serves itself, bypassing
	// ConnContext), so both signals reach the classifier regardless of protocol.
	h2capture.Enable(srv)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hb.Start(ctx) // federation background tasks, if configured

	errCh := make(chan error, 2)

	// Wrap the raw TCP listener so each connection carries a TLS-fingerprint holder,
	// then layer TLS over it. ListenAndServeTLS cannot be used here: it owns listener
	// creation, leaving no seam to insert the fingerprint-capturing listener.
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	go func() {
		logger.Info("henbane-h2 starting", "version", version, "listen", cfg.Listen, "upstream", cfg.Upstream, "fingerprints", "tls+http2")
		err := srv.Serve(tls.NewListener(tlsfp.WrapListener(ln), tlsCfg))
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	var msrv *http.Server
	if cfg.Metrics.Listen != "" {
		msrv = &http.Server{
			Addr:              cfg.Metrics.Listen,
			Handler:           hb.MetricsHandler(),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		go func() {
			logger.Info("metrics endpoint starting", "listen", cfg.Metrics.Listen)
			err := msrv.ListenAndServe()
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errCh <- err
		}()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutdown signal received; draining")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if msrv != nil {
		_ = msrv.Shutdown(shutdownCtx) // best-effort; the proxy drain is what matters
	}
	return srv.Shutdown(shutdownCtx)
}
