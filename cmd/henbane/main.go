package main

import (
	"context"
	"errors"
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

	h, err := newHandler(cfg, logger)
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

	srv := &http.Server{Addr: cfg.Listen, Handler: h}

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
