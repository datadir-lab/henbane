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
	proto   int    // HTTP major version on an HTTPS request
	h2      string // Akamai HTTP/2 fingerprint when the optional h2capture module is wired; "" for HTTP/1.1 or no capture
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
	// headlessChromeUA is headless Chrome's DEFAULT UA: a full Chrome engine (every
	// browser header, a real Chrome h2 fingerprint) that still announces HeadlessChrome.
	headlessChromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36"
)

// Measured Akamai HTTP/2 fingerprints (SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-order),
// Nov 2026. Browser fingerprints use a browser pseudo-header order and never the
// bare HEADER_TABLE_SIZE 4096, so h2fp.ContradictsBrowser leaves them alone; the
// library fingerprints are flagged (Go/curl/Java by a non-browser pseudo-order,
// httpx by its 4096 table size even though it copies Chrome's order). The edge
// browsers reuse their engine's current fingerprint: the classifier keys on the
// pseudo-order and table size, both of which are stable across an engine's versions.
const (
	h2Chrome  = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	h2Firefox = "1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s"
	h2Safari  = "3:100;4:4194304|10420225|0|m,s,p,a"
	h2Go      = "2:0;4:4194304;5:1048576;6:10485760|1073741824|0|a,m,p,s"
	h2Curl    = "3:100;4:65536;2:0|1048510465|0|m,s,a,p"
	h2Java    = "1:16384;2:0;3:0;4:16777216;5:16384;6:393216|33488897|0|m,s,a,p"
	h2Httpx   = "1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p"
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
		// --- modern mainstream browsers: must pass (real browser h2 fingerprint) ---
		{"chrome-desktop", human, chromeUA, browserHeaders(), 2, h2Chrome},
		{"firefox-desktop", human, firefoxUA, browserHeaders(), 2, h2Firefox},
		{"safari-18", human, safariUA, browserHeaders(), 2, h2Safari},
		{"edge-desktop", human, edgeUA, browserHeaders(), 2, h2Chrome},
		{"chrome-android", human, "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36", browserHeaders(), 2, h2Chrome},
		{"firefox-h1", human, firefoxUA, browserHeaders(), 1, ""}, // legit HTTP/1.1 (proxy/old server): the lone legacy-http point stays below threshold

		// --- legitimate but pre-Fetch-Metadata browsers: the honest FALSE-POSITIVE surface.
		// Each carries its engine's real browser h2 fingerprint, so the h2 signal adds NO new FP here. ---
		{"safari-15.6", humanEdge, safari15UA, preFetchMetadata(), 2, h2Safari}, // Safari <16.4 (2023): OS-pinned, large real population
		{"firefox-89", humanEdge, firefox89, preFetchMetadata(), 2, h2Firefox},  // Firefox <90 (2021)
		{"chrome-75", humanEdge, chrome75UA, preFetchMetadata(), 2, h2Chrome},   // Chrome <76 (2019)

		// --- a verified crawler the scorer flags but the full stack rescues (h2 fp unknown/unused) ---
		{"googlebot", goodBot, googlebotUA, map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Encoding": "gzip, deflate, br"}, 2, ""},

		// --- naive scraper libraries wearing a spoofed Chrome UA: should be caught (verified defaults) ---
		{"go-net-http", spoofer, chromeUA, map[string]string{"Accept-Encoding": "gzip"}, 2, h2Go},                                                                                                         // no Accept/lang/Sec-Fetch
		{"python-requests", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "gzip, deflate"}, 1, ""},                                                                             // urllib3, HTTP/1.1
		{"python-httpx", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "gzip, deflate"}, 1, ""},                                                                                // h1 default
		{"curl", spoofer, chromeUA, map[string]string{"Accept": "*/*"}, 2, h2Curl},                                                                                                                        // no Accept-Encoding unless --compressed
		{"wget", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "identity"}, 1, ""},                                                                                             // identity = non-browser tell
		{"node-axios", spoofer, chromeUA, map[string]string{"Accept": "application/json, text/plain, */*", "Accept-Encoding": "gzip, compress, deflate, br"}, 1, ""},                                      // 'compress' token is non-browser
		{"java-httpclient", spoofer, chromeUA, map[string]string{}, 2, h2Java},                                                                                                                            // no Accept, no Accept-Encoding; h2
		{"scrapy", spoofer, chromeUA, map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en", "Accept-Encoding": "gzip, deflate"}, 1, ""}, // only Sec-Fetch missing

		// --- careful scrapers: set every browser header EXCEPT Sec-Fetch, header-identical to safari-15.6.
		// Over HTTP/2 their h2 fingerprint betrays them, which headers alone cannot. ---
		{"stealth-scraper", spooferHard, chromeUA, preFetchMetadata(), 2, h2Go},          // Go h2 client: a,m,p,s pseudo-order
		{"stealth-scraper-httpx", spooferHard, chromeUA, preFetchMetadata(), 2, h2Httpx}, // httpx (http2=True): copies Chrome's order but sends table size 4096

		// --- naive headless: default headless Chrome keeps its "HeadlessChrome" UA, a
		// self-identifying automation token, so the consistency scorer catches it even
		// though its headers and h2 fingerprint are a real browser's. ---
		{"headless-chrome-naive", spoofer, headlessChromeUA, browserHeaders(), 2, h2Chrome},

		// --- stealth headless: a real browser engine driven by automation that has
		// overridden its UA to a normal browser string. Full browser shape AND a real
		// browser h2 fingerprint, no automation token: out of this signal class. Catching
		// it needs behavioural analysis a reverse proxy cannot do (documented scope). ---
		{"headless-chrome", knownMiss, chromeUA, browserHeaders(), 2, h2Chrome},
		{"headless-playwright", knownMiss, firefoxUA, browserHeaders(), 2, h2Firefox},
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

// TLSFingerprint makes the corpus represent the direct-TLS-termination scenario,
// where the HTTP-version (legacy_http) signal is valid. Behind a proxy that
// signal is correctly suppressed (see internal/detect/consistency).
func (r req) TLSFingerprint() string { return "corpus-direct-tls" }

// H2Fingerprint supplies the client's Akamai HTTP/2 fingerprint, as the optional
// h2capture module would when Henbane terminates the client's h2 connection. Empty
// for HTTP/1.1 clients and where no fingerprint is modelled.
func (r req) H2Fingerprint() string { return r.p.h2 }

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

	// --- the header-layer tie, and the HTTP/2 fingerprint breaking it ---
	headerOnly := consistency.DefaultWeights()
	headerOnly.H2Mismatch = 0
	hdr := decide(t, headerOnly, suspectAt, confirmAt)
	t.Logf("")
	t.Logf("header layer alone:      safari-15.6 -> %s, stealth-scraper -> %s  (IDENTICAL; no header signal separates them)",
		hdr["safari-15.6"], hdr["stealth-scraper"])
	t.Logf("with HTTP/2 fingerprint: safari-15.6 -> %s, stealth-scraper -> %s  (the tie is broken; see TestHTTP2Signal)",
		tiers["safari-15.6"], tiers["stealth-scraper"])
	t.Logf("  In the full stack the good-bot verifier rescues real crawlers (googlebot -> %s, allowed once FCrDNS-verified).", tiers["googlebot"])
}

// TestHTTP2Signal measures what the optional HTTP/2 fingerprint adds on top of the
// header layer. The header-only study established the ceiling: a careful scraper
// that omits only Sec-Fetch is identical to an old browser, so both land at Suspect
// and you cannot treat one worse than the other. The h2 fingerprint is a non-header
// signal that breaks that tie: a scraper's h2 stack is not a browser's, while an old
// browser's still is.
func TestHTTP2Signal(t *testing.T) {
	const suspectAt, confirmAt = 2, 4
	headerOnly := consistency.DefaultWeights()
	headerOnly.H2Mismatch = 0
	base := decide(t, headerOnly, suspectAt, confirmAt)
	withH2 := decide(t, consistency.DefaultWeights(), suspectAt, confirmAt)

	// 1. The tie, broken: careful scrapers escalate to Confirmed; old browsers do not move.
	t.Logf("verdict with the header layer alone vs. with the HTTP/2 fingerprint:")
	t.Logf("  %-24s %-14s %s", "profile", "header-only", "with h2")
	for _, n := range []string{"safari-15.6", "firefox-89", "chrome-75", "stealth-scraper", "stealth-scraper-httpx"} {
		t.Logf("  %-24s %-14s %s", n, base[n], withH2[n])
	}
	for _, s := range []string{"stealth-scraper", "stealth-scraper-httpx"} {
		if base[s] != ports.TierSuspect {
			t.Errorf("header-only: %s should be Suspect (tied with old browsers), got %v", s, base[s])
		}
		if withH2[s] != ports.TierConfirmed {
			t.Errorf("with h2: %s should reach Confirmed, got %v", s, withH2[s])
		}
	}
	for _, e := range []string{"safari-15.6", "firefox-89", "chrome-75"} {
		if withH2[e] != ports.TierSuspect {
			t.Errorf("with h2: old browser %s must stay Suspect (no new false positive), got %v", e, withH2[e])
		}
	}

	// 2. Detection at the Confirmed (tarpit) threshold: careful scrapers in, old browsers out.
	confHard := func(tiers map[string]ports.Tier) (caught, total, edgeFP, edgeTotal int) {
		for _, p := range corpus() {
			conf := tiers[p.name] >= ports.TierConfirmed
			switch p.class {
			case spooferHard:
				total++
				if conf {
					caught++
				}
			case humanEdge:
				edgeTotal++
				if conf {
					edgeFP++
				}
			}
		}
		return
	}
	bc, bt, bfp, bet := confHard(base)
	hc, ht, hfp, het := confHard(withH2)
	t.Logf("")
	t.Logf("careful scrapers reaching Confirmed (tarpit + poison), and old-browser false positives at that tier:")
	t.Logf("  header layer alone:  careful scrapers %d/%d,  old-browser FP %d/%d", bc, bt, bfp, bet)
	t.Logf("  with HTTP/2:         careful scrapers %d/%d,  old-browser FP %d/%d", hc, ht, hfp, het)
	if hfp != 0 {
		t.Errorf("the h2 signal must push NO old browser to Confirmed; got %d/%d", hfp, het)
	}
	if hc != ht {
		t.Errorf("with h2, all careful scrapers should reach Confirmed; got %d/%d", hc, ht)
	}

	// 3. Headless browsers are NOT caught: they carry a genuine browser's h2 fingerprint.
	t.Logf("")
	t.Logf("headless browsers stay uncaught (they send a real browser h2 fingerprint): the honest remaining gap")
	for _, n := range []string{"headless-chrome", "headless-playwright"} {
		t.Logf("  %-24s with h2 -> %s", n, withH2[n])
		if withH2[n] != ports.TierPass {
			t.Errorf("headless %s should stay Pass under h2, got %v", n, withH2[n])
		}
	}
}
