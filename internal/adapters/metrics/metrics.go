// Package metrics is a zero-dependency Prometheus-text sink: it folds decision
// Events into counters and renders them in the Prometheus exposition format by
// hand (no client library, per Henbane's stdlib-only rule). It is meant to be
// served on a SEPARATE, operator-private listener — the counters are aggregate
// (no per-IP or per-path labels), so they carry operational data, not user data.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/datadir-lab/henbane/internal/ports"
)

const (
	numActions = 5   // ports.Action enum size
	numTiers   = 4   // ports.Tier enum size
	maxSignals = 128 // hard cap on distinct signal labels (cardinality bound)
)

// Registry accumulates decision counters. Its zero value is not usable; call New.
type Registry struct {
	requests [numActions][numTiers]atomic.Int64
	dropped  atomic.Int64 // signal observations dropped at the cardinality cap

	mu      sync.Mutex
	signals map[string]int64
}

// New returns an empty Registry.
func New() *Registry {
	return &Registry{signals: make(map[string]int64)}
}

// Emit implements ports.Sink: it folds one event into the counters. It must not
// block the request path — request/tier counts are atomic; the signal map takes
// a brief lock. Out-of-range action/tier codes are ignored (no array OOB).
func (r *Registry) Emit(ev ports.Event) {
	if a, t := int(ev.Action), int(ev.Tier); a >= 0 && a < numActions && t >= 0 && t < numTiers {
		r.requests[a][t].Add(1)
	}
	if len(ev.Signals) == 0 {
		return
	}
	r.mu.Lock()
	for _, s := range ev.Signals {
		name := string(s)
		if _, ok := r.signals[name]; !ok && len(r.signals) >= maxSignals {
			r.dropped.Add(1)
			continue
		}
		r.signals[name]++
	}
	r.mu.Unlock()
}

// Render renders the current counters in Prometheus text format.
func (r *Registry) Render(w io.Writer) {
	var b strings.Builder
	b.WriteString("# HELP henbane_requests_total Classifier decisions, by action and tier.\n")
	b.WriteString("# TYPE henbane_requests_total counter\n")
	for a := 0; a < numActions; a++ {
		for t := 0; t < numTiers; t++ {
			fmt.Fprintf(&b, "henbane_requests_total{action=%q,tier=%q} %d\n",
				ports.Action(a).String(), ports.Tier(t).String(), r.requests[a][t].Load())
		}
	}

	r.mu.Lock()
	names := make([]string, 0, len(r.signals))
	for n := range r.signals {
		names = append(names, n)
	}
	sort.Strings(names)
	vals := make([]int64, len(names))
	for i, n := range names {
		vals[i] = r.signals[n]
	}
	r.mu.Unlock()

	b.WriteString("# HELP henbane_signals_total Detector signals fired, by signal.\n")
	b.WriteString("# TYPE henbane_signals_total counter\n")
	for i, n := range names {
		fmt.Fprintf(&b, "henbane_signals_total{signal=\"%s\"} %d\n", escapeLabel(n), vals[i])
	}

	if d := r.dropped.Load(); d > 0 {
		b.WriteString("# HELP henbane_signals_dropped_total Signal observations dropped at the label-cardinality cap.\n")
		b.WriteString("# TYPE henbane_signals_dropped_total counter\n")
		fmt.Fprintf(&b, "henbane_signals_dropped_total %d\n", d)
	}

	_, _ = io.WriteString(w, b.String())
}

// Handler serves the metrics in Prometheus text format at any path.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.Render(w)
	})
}

// escapeLabel applies Prometheus label-value escaping: backslash, double-quote,
// and newline. Signal names are developer-defined, but escaping defensively
// keeps the exposition format valid regardless.
func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

var _ ports.Sink = (*Registry)(nil)
