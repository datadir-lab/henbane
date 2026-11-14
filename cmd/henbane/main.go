package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/henbane-sh/henbane/internal/config"
)

func main() {
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

	h, err := newHandler(cfg, logger, fail2banW)
	if err != nil {
		logger.Error("startup error", "err", err)
		os.Exit(2)
	}

	if err := serve(cfg, h, logger); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// serve runs the HTTP server until SIGINT/SIGTERM, then drains in-flight
// requests for up to 10s before returning.
func serve(cfg config.Config, h http.Handler, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: h,
		// ReadHeaderTimeout bounds the header read so a Slowloris client cannot
		// hold connections open indefinitely; MaxHeaderBytes caps header size
		// (and therefore X-Forwarded-For length). ReadTimeout/WriteTimeout are
		// deliberately left unset so proxying large uploads or streaming
		// responses is not cut off.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("henbane starting", "listen", cfg.Listen, "upstream", cfg.Upstream)
		err := srv.ListenAndServe()
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
	return srv.Shutdown(shutdownCtx)
}
