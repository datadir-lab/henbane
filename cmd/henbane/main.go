package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/datadir-lab/henbane/internal/adapters/metrics"
	"github.com/datadir-lab/henbane/internal/config"
	"github.com/datadir-lab/henbane/internal/tlsfp"
)

func main() {
	if maybePrintVersion(os.Args[1:], os.Stdout) {
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		logger.Error("config error", "err", err)
		os.Exit(2)
	}

	// The caller owns the fail2ban log file so it is closed on shutdown rather
	// than leaked from inside the handler constructor.
	var fail2banW io.Writer
	if cfg.Sinks.Fail2ban.Enabled {
		f, err := os.OpenFile(cfg.Sinks.Fail2ban.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			logger.Error("open fail2ban log", "path", cfg.Sinks.Fail2ban.Path, "err", err)
			os.Exit(2)
		}
		defer f.Close()
		fail2banW = f
	}

	// The metrics registry (when enabled) is both a sink inside the handler and
	// the source for the separate metrics listener's handler.
	var metricsReg *metrics.Registry
	if cfg.Metrics.Listen != "" {
		metricsReg = metrics.New()
	}

	h, background, err := newHandler(cfg, logger, fail2banW, metricsReg)
	if err != nil {
		logger.Error("startup error", "err", err)
		os.Exit(2)
	}

	var metricsH http.Handler
	if metricsReg != nil {
		metricsH = metricsReg.Handler()
	}

	if err := serve(cfg, h, metricsH, background, logger); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// listenAndServe runs srv over plain HTTP, or — when tls.cert/key are set —
// terminates TLS with the fingerprint-capturing listener, so the client's TLS
// fingerprint is available to detectors and the decision log.
func listenAndServe(srv *http.Server, cfg config.Config) error {
	if cfg.TLS.Cert == "" {
		return srv.ListenAndServe()
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		return fmt.Errorf("load tls cert: %w", err)
	}
	tlsCfg := tlsfp.DecorateConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	srv.ConnContext = tlsfp.ConnContext
	return srv.Serve(tls.NewListener(tlsfp.WrapListener(ln), tlsCfg))
}

// serve runs the proxy server (and, when metricsH is non-nil, a separate metrics
// server on cfg.Metrics.Listen) until SIGINT/SIGTERM, then drains in-flight
// requests for up to 10s before returning.
func serve(cfg config.Config, h, metricsH http.Handler, background []func(context.Context), logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Background tasks (e.g. the federation feed refresher) run for the life of
	// the server and stop when ctx is cancelled on shutdown.
	for _, task := range background {
		go task(ctx)
	}

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: h,
		// ReadHeaderTimeout bounds the header read so a Slowloris client cannot
		// hold connections open indefinitely; MaxHeaderBytes caps header size
		// (and therefore X-Forwarded-For length). ReadTimeout/WriteTimeout are
		// deliberately left unset so proxying large uploads or streaming
		// responses is not cut off — slow request *bodies* are therefore not
		// time-bounded here by design and are expected to be constrained upstream.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}

	errCh := make(chan error, 2)
	go func() {
		scheme := "http"
		if cfg.TLS.Cert != "" {
			scheme = "https"
		}
		logger.Info("henbane starting", "version", version, "listen", cfg.Listen, "scheme", scheme, "upstream", cfg.Upstream)
		err := listenAndServe(srv, cfg)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	var msrv *http.Server
	if metricsH != nil && cfg.Metrics.Listen != "" {
		msrv = &http.Server{
			Addr:              cfg.Metrics.Listen,
			Handler:           metricsH,
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

	logger.Info("shutdown signal received; draining (signal again to force exit)")
	// A second signal during drain forces an immediate exit.
	forced := make(chan os.Signal, 1)
	signal.Notify(forced, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-forced
		logger.Warn("second signal received; forcing exit")
		os.Exit(1)
	}()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if msrv != nil {
		_ = msrv.Shutdown(shutdownCtx) // best-effort; the proxy drain is what matters
	}
	return srv.Shutdown(shutdownCtx)
}
