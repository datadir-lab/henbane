// Package classifierbench is a reproducible evaluation of Henbane's scoring
// classifier against a labelled corpus of representative request shapes. It
// measures what the classifier actually claims to do — catch clients that wear a
// browser User-Agent but don't behave like that browser — with precision/recall,
// a per-signal ablation, and a threshold sweep, and it documents rather than
// hides the cases it cannot catch (a real headless browser; an honest non-browser
// client, which the other detection layers handle).
//
// Run it with `go test -v ./research/classifierbench` to print every table.
// Methodology and the competitive comparison are in research/classifier-benchmark.md.
package classifierbench

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/datadir-lab/henbane/internal/core"
	"github.com/datadir-lab/henbane/internal/detect/consistency"
	"github.com/datadir-lab/henbane/internal/ports"
)

// class labels what a profile should ideally be judged as.
type class int

const (
	human     class = iota // a real browser — must NOT be escalated (false positive if it is)
	spoofer                // a scraper library wearing a browser UA — should be caught (>= Suspect)
	knownMiss              // out of this classifier's scope; documented, not asserted
)

func (c class) String() string {
	switch c {
	case human:
		return "human"
	case spoofer:
		return "spoofer"
	default:
		return "known-miss"
	}
}

// profile is one corpus entry: a representative request shape. Header sets are
// the defaults these clients typically send; exact values drift by version, so
// the corpus is representative, not a version-pinned capture.
type profile struct {
	name    string
	class   class
	ua      string
	headers map[string]string
	proto   int // HTTP major version the client negotiates
}

const (
	chromeUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	firefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
	safariUA  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"
	edgeUA    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
)

// browserHeaders is the shape a real graphical browser sends.
func browserHeaders() map[string]string {
	return map[string]string{
		"Sec-Fetch-Site":  "none",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br, zstd",
	}
}

func corpus() []profile {
	return []profile{
		// --- real browsers: must pass ---
		{"chrome-desktop", human, chromeUA, browserHeaders(), 2},
		{"firefox-desktop", human, firefoxUA, browserHeaders(), 2},
		{"safari-desktop", human, safariUA, browserHeaders(), 2},
		{"edge-desktop", human, edgeUA, browserHeaders(), 2},
		{"chrome-android", human, "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36", browserHeaders(), 2},
		// Firefox over HTTP/1.1 (older server / corporate proxy) — must still pass:
		// everything else is browser-shaped, so the lone legacy-http point stays below threshold.
		{"firefox-h1", human, firefoxUA, browserHeaders(), 1},

		// --- scraper libraries wearing a spoofed Chrome UA: should be caught ---
		{"go-net-http", spoofer, chromeUA, map[string]string{"Accept-Encoding": "gzip"}, 2},
		{"python-requests", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "gzip, deflate"}, 1},
		{"python-httpx", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "gzip, deflate, br"}, 1},
		{"curl", spoofer, chromeUA, map[string]string{"Accept": "*/*"}, 2},
		{"scrapy", spoofer, chromeUA, map[string]string{"Accept": "text/html,application/xhtml+xml", "Accept-Language": "en", "Accept-Encoding": "gzip, deflate"}, 1},
		{"node-http", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "gzip, deflate, br"}, 1},
		{"java-httpclient", spoofer, chromeUA, map[string]string{"Accept-Encoding": "gzip"}, 2},
		{"wget", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "identity"}, 1},

		// --- out of scope: documented, not asserted ---
		// A real headless browser sends the full browser shape — this scorer can't
		// tell it apart; a TLS/HTTP-2 or behavioural signal is needed.
		{"headless-chrome", knownMiss, chromeUA, browserHeaders(), 2},
		{"headless-playwright", knownMiss, firefoxUA, browserHeaders(), 2},
		// An honest non-browser client doesn't claim to be a browser, so the
		// consistency scorer correctly ignores it; denylists/velocity/good-bot
		// verification are the layers for these.
		{"honest-curl", knownMiss, "curl/8.5.0", map[string]string{"Accept": "*/*"}, 2},
	}
}

// req adapts a profile to ports.RequestView (+ ProtocolViewer).
type req struct{ p profile }

func (r req) IP() netip.Addr         { return netip.MustParseAddr("203.0.113.10") }
func (r req) UserAgent() string      { return r.p.ua }
func (r req) Method() string         { return "GET" }
func (r req) Path() string           { return "/article/42" }
func (r req) Header(n string) string { return r.p.headers[n] }
func (r req) HTTPMajorVersion() int  { return r.p.proto }

// decide runs the scoring engine with the given weights and thresholds and
// reports the verdict tier per profile.
func decide(t *testing.T, w consistency.Weights, suspectAt, confirmAt int) map[string]ports.Tier {
	t.Helper()
	engine := core.NewEngine().WithScoring(suspectAt, confirmAt, consistency.New(w))
	out := make(map[string]ports.Tier, len(corpus()))
	for _, p := range corpus() {
		v, _ := engine.Decide(t.Context(), req{p})
		out[p.name] = v.Tier
	}
	return out
}

// metrics is a confusion summary for a run. Positive = "caught" (tier >= Suspect).
type metrics struct{ tp, fp, fn, tn int }

func (m metrics) precision() float64 {
	if m.tp+m.fp == 0 {
		return 0
	}
	return float64(m.tp) / float64(m.tp+m.fp)
}
func (m metrics) recall() float64 {
	if m.tp+m.fn == 0 {
		return 0
	}
	return float64(m.tp) / float64(m.tp+m.fn)
}
func (m metrics) f1() float64 {
	p, r := m.precision(), m.recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

// score computes a confusion matrix. positives is the set of classes treated as
// "should be caught"; humans are always the negatives.
func score(tiers map[string]ports.Tier, positives ...class) metrics {
	posSet := map[class]bool{}
	for _, c := range positives {
		posSet[c] = true
	}
	var m metrics
	for _, p := range corpus() {
		caught := tiers[p.name] >= ports.TierSuspect
		switch {
		case p.class == human && caught:
			m.fp++
		case p.class == human:
			m.tn++
		case posSet[p.class] && caught:
			m.tp++
		case posSet[p.class]:
			m.fn++
		}
	}
	return m
}

func TestClassifierBenchmark(t *testing.T) {
	const suspectAt, confirmAt = 2, 4
	w := consistency.DefaultWeights()
	tiers := decide(t, w, suspectAt, confirmAt)

	// --- per-profile table + invariants ---
	t.Logf("%-20s %-11s %s", "profile", "class", "verdict")
	t.Logf("%s", "-------------------------------------------------")
	for _, p := range corpus() {
		t.Logf("%-20s %-11s %s", p.name, p.class, tiers[p.name])
		switch p.class {
		case human:
			if tiers[p.name] != ports.TierPass {
				t.Errorf("FALSE POSITIVE: real browser %q escalated to %v", p.name, tiers[p.name])
			}
		case spoofer:
			if tiers[p.name] < ports.TierSuspect {
				t.Errorf("MISS: naive spoofer %q not caught (tier %v)", p.name, tiers[p.name])
			}
		}
	}

	// --- metrics: the scorer's claimed scope vs. the realistic ceiling ---
	naive := score(tiers, spoofer)
	realistic := score(tiers, spoofer, knownMiss) // counts headless as a positive it misses
	t.Logf("")
	t.Logf("metrics (positive = caught at tier >= Suspect):")
	t.Logf("  naive scrapers vs browsers:   precision %.2f  recall %.2f  F1 %.2f  (tp=%d fp=%d fn=%d tn=%d)",
		naive.precision(), naive.recall(), naive.f1(), naive.tp, naive.fp, naive.fn, naive.tn)
	t.Logf("  + headless as positives:      precision %.2f  recall %.2f  F1 %.2f  (recall falls — the honest ceiling)",
		realistic.precision(), realistic.recall(), realistic.f1())

	// --- ablation: zero each weight, measure spoofers still caught ---
	t.Logf("")
	t.Logf("ablation (spoofers caught of %d with one signal disabled):", naive.tp+naive.fn)
	base := consistency.DefaultWeights()
	for _, a := range []struct {
		name string
		mod  func(*consistency.Weights)
	}{
		{"— (all signals)", func(*consistency.Weights) {}},
		{"no fetch-metadata", func(w *consistency.Weights) { w.NoFetchMetadata = 0 }},
		{"no accept", func(w *consistency.Weights) { w.NoAccept = 0 }},
		{"no accept-language", func(w *consistency.Weights) { w.NoAcceptLang = 0 }},
		{"no modern-encoding", func(w *consistency.Weights) { w.NoModernEncoding = 0 }},
		{"no legacy-http", func(w *consistency.Weights) { w.LegacyHTTP = 0 }},
	} {
		ww := base
		a.mod(&ww)
		m := score(decide(t, ww, suspectAt, confirmAt), spoofer)
		t.Logf("  %-22s caught %d/%d   (FP %d)", a.name, m.tp, m.tp+m.fn, m.fp)
	}

	// --- threshold sweep: the detection / false-positive tradeoff ---
	t.Logf("")
	t.Logf("threshold sweep (confirm = suspect+2):")
	t.Logf("  %-10s %-18s %s", "suspect@", "spoofers caught", "false positives")
	for s := 1; s <= 5; s++ {
		m := score(decide(t, base, s, s+2), spoofer)
		t.Logf("  %-10d %-18s %d/%d", s, fmt.Sprintf("%d/%d", m.tp, m.tp+m.fn), m.fp, m.fp+m.tn)
	}
}
