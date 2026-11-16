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

	"github.com/datadir-lab/henbane/h2fp"
	"github.com/datadir-lab/henbane/internal/ports"
)

// Weights is the points each browser-behaviour mismatch contributes.
type Weights struct {
	NoFetchMetadata  int // no Sec-Fetch-Site (every modern browser sends it)
	NoAccept         int // no Accept header
	NoAcceptLang     int // no Accept-Language
	NoModernEncoding int // Accept-Encoding without gzip or br
	LegacyHTTP       int // HTTP/1.1 while claiming a modern browser (needs ProtocolViewer)
	H2Mismatch       int // HTTP/2 fingerprint whose pseudo-header order no browser uses (needs H2Fingerprinter)
}

// DefaultWeights tunes a single strong miss (missing fetch metadata, Accept, or a
// browser-impossible HTTP/2 fingerprint) to reach a Suspect-level score of 2, and
// two misses to compound toward Confirmed at 4.
func DefaultWeights() Weights {
	return Weights{NoFetchMetadata: 2, NoAccept: 2, NoAcceptLang: 1, NoModernEncoding: 1, LegacyHTTP: 1, H2Mismatch: 2}
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
	// Content-codings are case-insensitive (RFC 7231), so compare in lower case —
	// otherwise a client advertising "GZIP" would be wrongly flagged.
	if ae := strings.ToLower(r.Header("Accept-Encoding")); !strings.Contains(ae, "gzip") && !strings.Contains(ae, "br") {
		add("browser_mismatch:no_modern_encoding", s.w.NoModernEncoding)
	}
	// The client's HTTP version is only trustworthy when Henbane terminated the
	// client's TLS itself. Behind a proxy or CDN, ProtocolViewer reports the
	// proxy→Henbane hop (and most CDNs re-originate as HTTP/1.1), which would
	// flag every real browser; so the signal is applied only when a TLS
	// fingerprint proves Henbane is the direct TLS terminator. (Trade-off: on a
	// plaintext :80 endpoint there is no fingerprint, so this signal is suppressed
	// even though the version would be the client's — a client could choose the
	// plaintext port to dodge this single point. Serving the public site over TLS
	// avoids that; the signal is worth only one point regardless.)
	if terminatedTLS(r) {
		if pv, ok := r.(ports.ProtocolViewer); ok && pv.HTTPMajorVersion() == 1 {
			add("browser_mismatch:legacy_http", s.w.LegacyHTTP)
		}
	}
	// The HTTP/2 fingerprint is the strongest anti-spoof signal: a client wearing a
	// browser User-Agent whose h2 pseudo-header order is one no browser emits is not
	// that browser. It is present only when the optional h2capture module terminated
	// the client's HTTP/2 connection; absent (plain HTTP/1.1, behind a proxy, or no
	// capture wired) it is silently skipped, so enabling capture is purely additive.
	if h2, ok := r.(ports.H2Fingerprinter); ok {
		if h2fp.ContradictsBrowser(h2.H2Fingerprint()) {
			add("browser_mismatch:h2_fingerprint", s.w.H2Mismatch)
		}
	}
	return out
}

// terminatedTLS reports whether Henbane terminated the client's TLS connection
// itself (a non-empty TLS fingerprint is only captured on direct termination), so
// the request's HTTP version reflects the client rather than an upstream proxy.
func terminatedTLS(r ports.RequestView) bool {
	f, ok := r.(ports.TLSFingerprinter)
	return ok && f.TLSFingerprint() != ""
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
