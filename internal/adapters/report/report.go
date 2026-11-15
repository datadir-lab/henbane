// Package report is the reporter half of federation: a ports.Sink that
// contributes a deployment's confirmed-bad detections to a shared feed. It is
// asynchronous and bounded — Emit never blocks the request path, and a hostile
// or unreachable feed can never back-pressure or exhaust the server.
//
// Privacy by construction (GDPR legitimate interest, Recital 49 — network and
// information security; see docs/legitimate-interest-assessment.md): only
// Confirmed/Blocked tiers are reported (never a human's Pass/Suspect IP), and a
// report carries only {ip, signal, tier, timestamp} — no logs, user-agent, path,
// or payload. The raw IP is sent (not hashed): a hashed IP is still personal data
// and cannot be matched across reporters for the consensus that curates the feed.
package report

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/datadir-lab/henbane/internal/ports"
)

const (
	bufferSize      = 4096 // bounded; Emit drops (never blocks) when full
	defaultBatch    = 256
	defaultFlush    = 10 * time.Second
	requestTimeout  = 15 * time.Second
	maxBatchPerPost = 1024
)

type signal struct {
	IP     string `json:"ip"`
	Signal string `json:"signal"`
	Tier   string `json:"tier"`
	TS     int64  `json:"ts"` // unix seconds
}

type batchBody struct {
	DeploymentID string   `json:"deployment_id,omitempty"`
	Signals      []signal `json:"signals"`
}

// Reporter batches confirmed detections and POSTs them to a federation feed.
type Reporter struct {
	url          string
	token        string
	deploymentID string
	client       *http.Client
	logger       *slog.Logger

	ch         chan signal
	batchSize  int
	flushEvery time.Duration
	dropped    atomic.Int64
}

// New returns a Reporter posting to url (optionally with a bearer token and a
// stable deployment ID for cross-reporter consensus). Run must be called to
// start draining; until then Emit buffers up to bufferSize and drops the rest.
func New(url, token, deploymentID string, logger *slog.Logger) *Reporter {
	return &Reporter{
		url:          url,
		token:        token,
		deploymentID: deploymentID,
		client:       &http.Client{Timeout: requestTimeout},
		logger:       logger,
		ch:           make(chan signal, bufferSize),
		batchSize:    defaultBatch,
		flushEvery:   defaultFlush,
	}
}

// Emit implements ports.Sink. It enqueues only Confirmed/Blocked events with a
// valid IP and never blocks: a full buffer drops the event (counted).
func (r *Reporter) Emit(ev ports.Event) {
	if ev.Tier != ports.TierConfirmed && ev.Tier != ports.TierBlocked {
		return // never report a human (Pass/Suspect)
	}
	ip := ev.IP.Unmap()
	if !ip.IsValid() {
		return
	}
	var sig string
	if len(ev.Signals) > 0 {
		sig = string(ev.Signals[0])
	}
	s := signal{IP: ip.String(), Signal: sig, Tier: ev.Tier.String(), TS: ev.Time.Unix()}
	select {
	case r.ch <- s:
	default:
		r.dropped.Add(1)
	}
}

// Run drains buffered detections, POSTing a batch whenever one fills or every
// flushEvery, until ctx is cancelled — then it makes a final best-effort flush.
func (r *Reporter) Run(ctx context.Context) {
	t := time.NewTicker(r.flushEvery)
	defer t.Stop()
	batch := make([]signal, 0, r.batchSize)
	flush := func(fctx context.Context) {
		if len(batch) == 0 {
			return
		}
		r.post(fctx, batch)
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			// Drain what is already buffered, then a final flush with a fresh,
			// short-lived context (ctx is cancelled).
			fctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
			for drained := false; !drained; {
				select {
				case s := <-r.ch:
					batch = append(batch, s)
					if len(batch) >= maxBatchPerPost {
						flush(fctx)
					}
				default:
					drained = true
				}
			}
			flush(fctx)
			cancel()
			return
		case s := <-r.ch:
			batch = append(batch, s)
			if len(batch) >= r.batchSize {
				flush(ctx)
			}
		case <-t.C:
			flush(ctx)
		}
	}
}

// post sends one batch, best-effort: any error is logged and the batch dropped
// (no retry storm, no blocking).
func (r *Reporter) post(ctx context.Context, batch []signal) {
	body, err := json.Marshal(batchBody{DeploymentID: r.deploymentID, Signals: batch})
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		r.logger.Warn("federation report failed", "err", err, "signals", len(batch))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		r.logger.Warn("federation report rejected", "status", resp.StatusCode, "signals", len(batch))
	}
}

var _ ports.Sink = (*Reporter)(nil)
