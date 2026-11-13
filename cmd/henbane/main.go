package main

import (
	"log/slog"
	"net/http"
	"os"

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

	logger.Info("henbane starting", "listen", cfg.Listen, "upstream", cfg.Upstream)
	srv := &http.Server{Addr: cfg.Listen, Handler: h}
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
