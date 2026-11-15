// Package classifierbench is a reproducible benchmark of Henbane's scoring
// classifier against a labelled corpus of representative request shapes. It
// measures what the classifier actually claims to do — catch clients that wear a
// browser User-Agent but don't behave like that browser — and documents, rather
// than hides, the cases it cannot catch (a real headless browser; an honest
// non-browser client, which the other detection layers handle).
//
// Run it with `go test -v ./research/classifierbench` to print the full table.
// The library methodology behind the corpus is documented in
// research/classifier-benchmark.md.
package classifierbench

import (
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

		// --- scraper libraries wearing a spoofed Chrome UA: should be caught ---
		// Go net/http: auto Accept-Encoding gzip only; no Accept, lang, or Sec-Fetch; h2 over TLS.
		{"go-net-http", spoofer, chromeUA, map[string]string{"Accept-Encoding": "gzip"}, 2},
		// Python requests (urllib3): Accept */*, Accept-Encoding gzip,deflate; no lang/Sec-Fetch; HTTP/1.1.
		{"python-requests", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "gzip, deflate"}, 1},
		// Python httpx (default h1): Accept */*, gzip,deflate,br; no lang/Sec-Fetch.
		{"python-httpx", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "gzip, deflate, br"}, 1},
		// curl --http2 (no --compressed): Accept */*; no encoding/lang/Sec-Fetch.
		{"curl", spoofer, chromeUA, map[string]string{"Accept": "*/*"}, 2},
		// Scrapy: default Accept + Accept-Language 'en' + gzip,deflate; no Sec-Fetch; Twisted h1.
		{"scrapy", spoofer, chromeUA, map[string]string{"Accept": "text/html,application/xhtml+xml", "Accept-Language": "en", "Accept-Encoding": "gzip, deflate"}, 1},
		// node axios/got: Accept */*, gzip,deflate,br; no lang/Sec-Fetch; often h1.
		{"node-http", spoofer, chromeUA, map[string]string{"Accept": "*/*", "Accept-Encoding": "gzip, deflate, br"}, 1},

		// --- out of scope: documented, not asserted ---
		// A real headless browser sends the full browser shape — this scorer can't
		// tell it apart; a TLS/HTTP-2 or behavioural signal is needed.
		{"headless-chrome", knownMiss, chromeUA, browserHeaders(), 2},
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

func TestClassifierBenchmark(t *testing.T) {
	const suspectAt, confirmAt = 2, 4
	engine := core.NewEngine().WithScoring(suspectAt, confirmAt, consistency.New(consistency.DefaultWeights()))

	var caughtSpoofers, totalSpoofers, falsePositives, totalHumans int

	t.Logf("%-18s %-11s %-10s %s", "profile", "class", "verdict", "action")
	t.Logf("%s", "----------------------------------------------------------")
	for _, p := range corpus() {
		v, _ := engine.Decide(t.Context(), req{p})
		t.Logf("%-18s %-11s %-10s %s", p.name, p.class, v.Tier, v.Action)

		switch p.class {
		case human:
			totalHumans++
			if v.Tier != ports.TierPass {
				falsePositives++
				t.Errorf("FALSE POSITIVE: real browser %q escalated to %v", p.name, v.Tier)
			}
		case spoofer:
			totalSpoofers++
			if v.Tier >= ports.TierSuspect {
				caughtSpoofers++
			} else {
				t.Errorf("MISS: spoofer %q not caught (tier %v)", p.name, v.Tier)
			}
		}
	}

	t.Logf("")
	t.Logf("spoofers caught:  %d/%d", caughtSpoofers, totalSpoofers)
	t.Logf("false positives:  %d/%d real browsers", falsePositives, totalHumans)
}
