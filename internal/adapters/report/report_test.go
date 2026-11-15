package report

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/datadir-lab/henbane/internal/ports"
)

var _ ports.Sink = (*Reporter)(nil)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func confirmed(ip string) ports.Event {
	return ports.Event{
		Time:    time.Unix(1700000000, 0),
		IP:      netip.MustParseAddr(ip),
		Tier:    ports.TierConfirmed,
		Signals: []ports.Signal{"honeypot"},
	}
}

func TestEmitOnlyEnqueuesConfirmedAndBlocked(t *testing.T) {
	r := New("http://example.invalid", "", "dep1", discard())
	r.Emit(confirmed("203.0.113.9"))
	r.Emit(ports.Event{IP: netip.MustParseAddr("203.0.113.1"), Tier: ports.TierPass})    // human
	r.Emit(ports.Event{IP: netip.MustParseAddr("203.0.113.2"), Tier: ports.TierSuspect}) // human
	r.Emit(ports.Event{Tier: ports.TierBlocked})                                         // invalid IP
	if got := len(r.ch); got != 1 {
		t.Errorf("buffered %d events, want 1 (only the confirmed, valid IP)", got)
	}
}

func TestRunPostsBatch(t *testing.T) {
	type payload struct {
		DeploymentID string `json:"deployment_id"`
		Signals      []struct {
			IP     string `json:"ip"`
			Signal string `json:"signal"`
			Tier   string `json:"tier"`
			TS     int64  `json:"ts"`
		} `json:"signals"`
	}
	got := make(chan payload, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer token, got %q", req.Header.Get("Authorization"))
		}
		var p payload
		_ = json.NewDecoder(req.Body).Decode(&p)
		got <- p
	}))
	defer srv.Close()

	r := New(srv.URL, "tok", "dep1", discard())
	r.flushEvery = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	r.Emit(confirmed("203.0.113.9"))

	select {
	case p := <-got:
		if p.DeploymentID != "dep1" || len(p.Signals) != 1 {
			t.Fatalf("payload = %+v", p)
		}
		s := p.Signals[0]
		if s.IP != "203.0.113.9" || s.Signal != "honeypot" || s.Tier != "confirmed" || s.TS != 1700000000 {
			t.Errorf("signal = %+v", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reporter did not POST within 2s")
	}
}

func TestEmitDropsWhenBufferFull(t *testing.T) {
	r := New("http://example.invalid", "", "", discard())
	// Fill the buffer past capacity without a running drainer; Emit must never block.
	done := make(chan struct{})
	go func() {
		for i := 0; i < bufferSize+100; i++ {
			r.Emit(confirmed("203.0.113.9"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked when the buffer was full (must drop instead)")
	}
	if r.dropped.Load() == 0 {
		t.Error("expected some dropped events once the buffer filled")
	}
}

func TestRunSurvivesPostError(t *testing.T) {
	r := New("http://127.0.0.1:1", "", "", discard()) // nothing listening
	r.flushEvery = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)
	r.Emit(confirmed("203.0.113.9"))
	time.Sleep(60 * time.Millisecond) // let it try and fail
	cancel()
	// No panic, no hang = pass.
}

func TestConcurrentEmit(t *testing.T) {
	r := New("http://example.invalid", "", "", discard())
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				r.Emit(confirmed("203.0.113.9"))
			}
		}()
	}
	wg.Wait()
}
