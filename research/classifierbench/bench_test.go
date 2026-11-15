// Package classifierbench is a reproducible evaluation of Henbane's scoring
// classifier against a labelled corpus of representative request shapes, grounded
// in each client's *verified* default headers (see research/classifier-benchmark.md
// for the per-client citations). It measures what the classifier claims to do —
// catch clients that wear a browser User-Agent but don't behave like that browser
// — AND, deliberately, where it draws false positives (legitimate browsers that
// predate the Fetch Metadata headers) and where it is fundamentally blind (real
// headless browsers; careful scrapers that are header-identical to an old browser).
//
// Run with `go test -v ./research/classifierbench` to print every table.
package classifierbench

import (
	"net/netip"
	"testing"

	"github.com/datadir-lab/henbane/internal/core"
	"github.com/datadir-lab/henbane/internal/detect/consistency"
	"github.com/datadir-lab/henbane/internal/ports"
)

// class labels what a profile is, which determines how a verdict is scored.
type class int

const (
	human       class = iota // a modern mainstream browser — must NOT be escalated
	humanEdge                // a legitimate but pre-Fetch-Metadata browser — the honest FP surface
	goodBot                  // a verified crawler the scorer flags but the good-bot verifier rescues
	spoofer                  // a naive scraper library wearing a browser UA — should be caught
	spooferHard              // a careful scraper, header-identical to an old browser — the ceiling
	knownMiss                // a real headless browser — out of this signal class entirely
)

func (c class) String() string {
	return [...]string{"human", "human-edge", "good-bot", "spoofer", "spoofer-hard", "known-miss"}[c]
}

// profile is one corpus entry. Header sets are each client's VERIFIED defaults
// (project source / docs, cited in the companion doc); br/zstd in Accept-Encoding
// is treated as env-dependent and only included where a client sends it by default.
type profile struct {
	name    string
	class   class
	ua      string
	headers map[string]string
	proto   int // HTTP major version on an HTTPS request
}

const (
	chromeUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	firefoxUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
	safariUA   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"
	edgeUA     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
	safari15UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15"
	firefox89  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
	chrome75UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36"
	// Googlebot smartphone UA carries Chrome+Safari tokens, so the scorer treats it as
	// a browser-claimer; the crawl fetch sends no Sec-Fetch.
	googlebotUA = "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

func browserHeaders() map[string]string {
	return map[string]string{
		"Sec-Fetch-Site":  "none",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br, zstd",
	}
}

// preFetchMetadata is a real browser's headers MINUS Sec-Fetch — the shape sent
// by any browser released before Fetch Metadata (Chrome <76, Firefox <90,
// Safari <16.4). These are legitimate humans.
func preFetchMetadata() map[string]string {
	h := browserHeaders()
	delete(h, "Sec-Fetch-Site")
	return h
}

func corpus() []profile {
	return []profile{
		// --- modern mainstream browsers: must pass ---
		{"chrome-desktop", human, chromeUA, browserHeaders(), 2},
		{"firefox-desktop", human, firefoxUA, browserHeaders(), 2},
		{"safari-18", human, safariUA, browserHeaders(), 2},
		{"edge-desktop", human, edgeUA, browserHeaders(), 2},
		{"chrome-android", human, "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36", browserHeaders(), 2},
		{"firefox-h1", human, firefoxUA, browserHeaders(), 1}, // legit HTTP/1.1 (proxy/old server): the lone legacy-http point stays below threshold

		// --- legitimate but pre-Fetch-Metadata browsers: the honest FALSE-POSITIVE surface ---
		{"safari-15.6", humanEdge, safari15UA, preFetchMetadata(), 2}, // Safari <16.4 (2023) — OS-pinned, large real population
		{"firefox-89", humanEdge, firefox89, preFetchMetadata(), 2},   // Firefox <90 (2021)
		{"chrome-75", humanEdge, chrome75UA, preFetchMetadata(), 2},   // Chrome <76 (2019)

		// --- a verified crawler the scorer flags but the full stack rescues ---
		{"googlebot", goodBot, googlebotUA, map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Encoding": "gzip, deflate, br"}, 2},

		// --- naive scraper libraries wearing a spoofed Chrome UA: should be caught (verified defaults) ---
		{"go-net-http", spoofer, chromeUA, map[string]string{"Accept-Encoding": "gzip"}, 2},                                                                                                           // no Accept/lang/Sec-Fetch
		{"python-requests", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "gzip, deflate"}, 1},                                                                             // urllib3
		{"python-httpx", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "gzip, deflate"}, 1},                                                                                // h1 default
		{"curl", spoofer, chromeUA, map[string]string{"Accept": "*/*"}, 2},                                                                                                                            // no Accept-Encoding unless --compressed
		{"wget", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "identity"}, 1},                                                                                             // identity = non-browser tell
		{"node-axios", spoofer, chromeUA, map[string]string{"Accept": "application/json, text/plain, */*", "Accept-Encoding": "gzip, compress, deflate, br"}, 1},                                      // 'compress' token is non-browser
		{"java-httpclient", spoofer, chromeUA, map[string]string{}, 2},                                                                                                                                // no Accept, no Accept-Encoding; h2
		{"scrapy", spoofer, chromeUA, map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en", "Accept-Encoding": "gzip, deflate"}, 1}, // only Sec-Fetch missing

		// --- a careful scraper: sets every browser header EXCEPT Sec-Fetch; header-identical to safari-15.6 ---
		{"stealth-scraper", spooferHard, chromeUA, preFetchMetadata(), 2},

		// --- real headless browsers: send the full browser shape; out of this signal class ---
		{"headless-chrome", knownMiss, chromeUA, browserHeaders(), 2},
		{"headless-playwright", knownMiss, firefoxUA, browserHeaders(), 2},
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

// decide runs the scoring engine with the given weights/thresholds and returns
// the verdict tier per profile.
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

// metrics is a confusion summary. Positive = "caught" (tier >= Suspect).
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

// score builds a confusion matrix. positives = classes that SHOULD be caught;
// negatives = classes that should NOT be. Unlisted classes are ignored.
func score(tiers map[string]ports.Tier, positives, negatives []class) metrics {
	pos, neg := map[class]bool{}, map[class]bool{}
	for _, c := range positives {
		pos[c] = true
	}
	for _, c := range negatives {
		neg[c] = true
	}
	var m metrics
	for _, p := range corpus() {
		caught := tiers[p.name] >= ports.TierSuspect
		switch {
		case neg[p.class] && caught:
			m.fp++
		case neg[p.class]:
			m.tn++
		case pos[p.class] && caught:
			m.tp++
		case pos[p.class]:
			m.fn++
		}
	}
	return m
}

func TestClassifierBenchmark(t *testing.T) {
	const suspectAt, confirmAt = 2, 4
	tiers := decide(t, consistency.DefaultWeights(), suspectAt, confirmAt)

	// --- per-profile table + invariants (only the unambiguous classes are asserted) ---
	t.Logf("%-20s %-12s %s", "profile", "class", "verdict")
	t.Logf("%s", "--------------------------------------------------")
	for _, p := range corpus() {
		t.Logf("%-20s %-12s %s", p.name, p.class, tiers[p.name])
		switch p.class {
		case human:
			if tiers[p.name] != ports.TierPass {
				t.Errorf("FALSE POSITIVE on a modern browser %q: %v", p.name, tiers[p.name])
			}
		case spoofer:
			if tiers[p.name] < ports.TierSuspect {
				t.Errorf("MISS: naive spoofer %q not caught (%v)", p.name, tiers[p.name])
			}
		}
	}

	// --- headline metrics, by adversary difficulty ---
	naive := score(tiers, []class{spoofer}, []class{human})
	hard := score(tiers, []class{spoofer, spooferHard}, []class{human})
	ceiling := score(tiers, []class{spoofer, spooferHard, knownMiss}, []class{human})
	t.Logf("")
	t.Logf("detection by adversary difficulty (negatives = modern browsers only):")
	t.Logf("  naive scrapers:            precision %.2f recall %.2f F1 %.2f", naive.precision(), naive.recall(), naive.f1())
	t.Logf("  + careful (header-perfect): precision %.2f recall %.2f F1 %.2f", hard.precision(), hard.recall(), hard.f1())
	t.Logf("  + headless browsers:        precision %.2f recall %.2f F1 %.2f  (the honest ceiling)", ceiling.precision(), ceiling.recall(), ceiling.f1())

	// --- the false-positive surface, measured ---
	fpEdge := score(tiers, nil, []class{humanEdge})
	t.Logf("")
	t.Logf("FALSE POSITIVES on legitimate pre-Fetch-Metadata browsers: %d/%d", fpEdge.fp, fpEdge.fp+fpEdge.tn)
	t.Logf("  (Safari<16.4, Firefox<90, Chrome<76 lack Sec-Fetch-Site and are flagged → challenged, not blocked.)")

	// --- the fundamental indistinguishability ---
	t.Logf("")
	t.Logf("header-layer indistinguishability: safari-15.6 -> %s, stealth-scraper -> %s",
		tiers["safari-15.6"], tiers["stealth-scraper"])
	t.Logf("  A careful scraper that omits only Sec-Fetch is IDENTICAL to an old real browser at")
	t.Logf("  this layer; no header signal can separate them. In the full stack the good-bot")
	t.Logf("  verifier rescues real crawlers (googlebot -> %s here, allowed once FCrDNS-verified).", tiers["googlebot"])
}
