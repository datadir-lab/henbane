package remotedeny

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// maxBodyBytes bounds a feed response so a hostile or broken feed cannot exhaust
// memory; 32 MiB holds well over a million CIDR lines.
const maxBodyBytes = 32 << 20

// Refresher periodically fetches a remote blocklist and hot-swaps it into a
// Detector. A failed fetch leaves the Detector's current set untouched.
type Refresher struct {
	det        *Detector
	url        string
	interval   time.Duration
	maxEntries int
	logger     *slog.Logger
	client     *http.Client
}

// NewRefresher builds a Refresher for det against url, refreshing every interval
// and keeping at most maxEntries prefixes.
func NewRefresher(det *Detector, url string, interval time.Duration, maxEntries int, logger *slog.Logger) *Refresher {
	return &Refresher{
		det:        det,
		url:        url,
		interval:   interval,
		maxEntries: maxEntries,
		logger:     logger,
		client:     &http.Client{Timeout: 30 * time.Second},
	}
}

// Run fetches immediately, then every interval, until ctx is cancelled. It never
// returns an error: a fetch failure is logged and the last good set is kept.
func (r *Refresher) Run(ctx context.Context) {
	if err := r.refreshOnce(ctx); err != nil {
		r.logger.Warn("remote denylist initial fetch failed; starting empty", "err", err, "url", r.url)
	} else {
		r.logger.Info("remote denylist loaded", "entries", r.det.count(), "url", r.url)
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.refreshOnce(ctx); err != nil {
				r.logger.Warn("remote denylist refresh failed; keeping current set", "err", err, "entries", r.det.count())
			}
		}
	}
}

// refreshOnce fetches and parses the feed and, only on success, swaps the new
// set in. Any error (request, non-200, read) leaves the current set in place.
func (r *Refresher) refreshOnce(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remote denylist %s: status %d", r.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	r.det.replace(parseList(body, r.maxEntries))
	return nil
}
