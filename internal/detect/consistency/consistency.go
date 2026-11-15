// Package consistency scores how well a request's HTTP behaviour matches the
// mainstream browser its User-Agent claims to be. Spoofing a browser User-Agent
// is the single most common scraper evasion, but copying the header is cheap
// while reproducing a real browser's whole request shape is not: browsers send
// Sec-Fetch metadata, an Accept header, a language, a modern compression
// preference, and negotiate HTTP/2. Each of those a browser-claiming client
// omits is weak evidence on its own; the engine's scoring layer accumulates
// them, so one miss costs only a brief challenge while several compound into a
// confident "this is not the browser it says it is".
//
// It only looks at clients wearing a browser User-Agent — honest non-browser
// clients (curl, Python with their own UA) are left to the other detectors — so
// its false-positive surface is narrow.
package consistency

import (
	"strings"

	"github.com/datadir-lab/henbane/internal/ports"
)

// Weights is the points each browser-behaviour mismatch contributes.
type Weights struct {
	NoFetchMetadata  int // no Sec-Fetch-Site (every modern browser sends it)
	NoAccept         int // no Accept header
	NoAcceptLang     int // no Accept-Language
	NoModernEncoding int // Accept-Encoding without gzip or br
	LegacyHTTP       int // HTTP/1.1 while claiming a modern browser (needs ProtocolViewer)
}

// DefaultWeights tunes a single strong miss (missing fetch metadata or Accept)
// to reach a Suspect-level score of 2, and two misses to compound toward
// Confirmed at 4.
func DefaultWeights() Weights {
	return Weights{NoFetchMetadata: 2, NoAccept: 2, NoAcceptLang: 1, NoModernEncoding: 1, LegacyHTTP: 1}
}

// Scorer implements ports.Scorer.
type Scorer struct{ w Weights }

// New returns a consistency scorer with the given weights.
func New(w Weights) *Scorer { return &Scorer{w: w} }

// Name identifies the scorer.
func (s *Scorer) Name() string { return "browser_consistency" }

// Score returns one result per browser behaviour the client omits, or nil if the
// client does not claim a mainstream browser.
func (s *Scorer) Score(r ports.RequestView) []ports.ScoreResult {
	if !claimsBrowser(r.UserAgent()) {
		return nil
	}
	var out []ports.ScoreResult
	add := func(sig string, pts int) {
		if pts > 0 {
			out = append(out, ports.ScoreResult{Signal: ports.Signal(sig), Points: pts})
		}
	}
	if r.Header("Sec-Fetch-Site") == "" {
		add("browser_mismatch:no_fetch_metadata", s.w.NoFetchMetadata)
	}
	if r.Header("Accept") == "" {
		add("browser_mismatch:no_accept", s.w.NoAccept)
	}
	if r.Header("Accept-Language") == "" {
		add("browser_mismatch:no_accept_language", s.w.NoAcceptLang)
	}
	if ae := r.Header("Accept-Encoding"); !strings.Contains(ae, "gzip") && !strings.Contains(ae, "br") {
		add("browser_mismatch:no_modern_encoding", s.w.NoModernEncoding)
	}
	// Protocol is only meaningful when Henbane terminates the client connection;
	// behind a proxy the RequestView won't expose it (or reports the proxy hop).
	if pv, ok := r.(ports.ProtocolViewer); ok && pv.HTTPMajorVersion() == 1 {
		add("browser_mismatch:legacy_http", s.w.LegacyHTTP)
	}
	return out
}

// claimsBrowser reports whether ua looks like a mainstream graphical browser: a
// Mozilla-prefixed string carrying a known engine/product token.
func claimsBrowser(ua string) bool {
	if !strings.HasPrefix(ua, "Mozilla/") {
		return false
	}
	for _, tok := range []string{"Chrome/", "Firefox/", "Safari/", "Edg/", "OPR/"} {
		if strings.Contains(ua, tok) {
			return true
		}
	}
	return false
}

var _ ports.Scorer = (*Scorer)(nil)
