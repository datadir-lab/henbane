package metrics

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/datadir-lab/henbane/internal/ports"
)

var _ ports.Sink = (*Registry)(nil)

func render(r *Registry) string {
	var b strings.Builder
	r.Render(&b)
	return b.String()
}

func TestCountsRequestsByActionAndTier(t *testing.T) {
	r := New()
	r.Emit(ports.Event{Action: ports.ActionAllow, Tier: ports.TierPass})
	r.Emit(ports.Event{Action: ports.ActionAllow, Tier: ports.TierPass})
	r.Emit(ports.Event{Action: ports.ActionTarpit, Tier: ports.TierConfirmed})

	out := render(r)
	if !strings.Contains(out, `henbane_requests_total{action="allow",tier="pass"} 2`) {
		t.Errorf("missing allow/pass=2:\n%s", out)
	}
	if !strings.Contains(out, `henbane_requests_total{action="tarpit",tier="confirmed"} 1`) {
		t.Errorf("missing tarpit/confirmed=1:\n%s", out)
	}
	// Prometheus exposition hygiene: HELP and TYPE lines present.
	if !strings.Contains(out, "# TYPE henbane_requests_total counter") {
		t.Errorf("missing TYPE line:\n%s", out)
	}
}

func TestCountsSignals(t *testing.T) {
	r := New()
	r.Emit(ports.Event{Action: ports.ActionTarpit, Tier: ports.TierConfirmed, Signals: []ports.Signal{"honeypot", "velocity"}})
	r.Emit(ports.Event{Action: ports.ActionTarpit, Tier: ports.TierConfirmed, Signals: []ports.Signal{"honeypot"}})
	out := render(r)
	if !strings.Contains(out, `henbane_signals_total{signal="honeypot"} 2`) {
		t.Errorf("missing honeypot=2:\n%s", out)
	}
	if !strings.Contains(out, `henbane_signals_total{signal="velocity"} 1`) {
		t.Errorf("missing velocity=1:\n%s", out)
	}
}

func TestIgnoresOutOfRangeActionTier(t *testing.T) {
	r := New()
	// A corrupt event with out-of-range codes must not panic (no array OOB).
	r.Emit(ports.Event{Action: ports.Action(99), Tier: ports.Tier(-1)})
	_ = render(r) // must not panic
}

func TestSignalLabelEscaped(t *testing.T) {
	r := New()
	r.Emit(ports.Event{Signals: []ports.Signal{`we"ird` + "\n"}})
	out := render(r)
	if !strings.Contains(out, `signal="we\"ird\n"`) {
		t.Errorf("label not escaped per Prometheus rules:\n%s", out)
	}
}

func TestSignalCardinalityIsCapped(t *testing.T) {
	r := New()
	for i := 0; i < maxSignals+50; i++ {
		r.Emit(ports.Event{Signals: []ports.Signal{ports.Signal("sig-" + string(rune('A'+i%26)) + string(rune('0'+i/26)))}})
	}
	out := render(r)
	if !strings.Contains(out, "henbane_signals_dropped_total") {
		t.Errorf("expected a dropped-counter once the cardinality cap is hit:\n%s", out)
	}
}

func TestHandlerServesPrometheusText(t *testing.T) {
	r := New()
	r.Emit(ports.Event{Action: ports.ActionBlock, Tier: ports.TierBlocked})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	r.Handler().ServeHTTP(rec, req)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q, want text/plain", ct)
	}
	if !strings.Contains(rec.Body.String(), `henbane_requests_total{action="block",tier="blocked"} 1`) {
		t.Errorf("handler body missing the block counter:\n%s", rec.Body.String())
	}
}

func TestConcurrentEmitAndScrapeAreSafe(t *testing.T) {
	r := New()
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				r.Emit(ports.Event{Action: ports.ActionChallenge, Tier: ports.TierSuspect, Signals: []ports.Signal{"velocity"}})
			}
		}()
	}
	for i := 0; i < 50; i++ {
		_ = render(r)
	}
	wg.Wait()
	if !strings.Contains(render(r), `henbane_requests_total{action="challenge",tier="suspect"} 8000`) {
		t.Errorf("concurrent count mismatch:\n%s", render(r))
	}
}
