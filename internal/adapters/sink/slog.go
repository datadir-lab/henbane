// Package sink contains ports.Sink implementations.
package sink

import (
	"context"
	"log/slog"

	"github.com/datadir-lab/henbane/internal/ports"
)

// SlogSink renders decision Events via a slog.Logger.
type SlogSink struct {
	logger *slog.Logger
}

// NewSlogSink returns a SlogSink writing to the given logger.
func NewSlogSink(logger *slog.Logger) *SlogSink {
	return &SlogSink{logger: logger}
}

// Emit logs a single structured decision record.
func (s *SlogSink) Emit(e ports.Event) {
	attrs := []slog.Attr{
		slog.String("action", e.Action.String()),
		slog.String("tier", e.Tier.String()),
		slog.String("ip", e.IP.String()),
		slog.String("ua", e.UserAgent),
		slog.String("path", e.Path),
	}
	if e.TLSFingerprint != "" {
		attrs = append(attrs, slog.String("tls_fp", e.TLSFingerprint))
	}
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "decision", attrs...)
}

var _ ports.Sink = (*SlogSink)(nil)
