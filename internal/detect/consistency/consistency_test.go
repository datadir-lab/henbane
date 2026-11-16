package consistency

import (
	"net/netip"
	"testing"

	"github.com/datadir-lab/henbane/internal/ports"
)

var _ ports.Scorer = (*Scorer)(nil)

type view struct {
	ua      string
	headers map[string]string
	proto   int    // 0 = don't implement ProtocolViewer
	tlsfp   string // "" = Henbane did not terminate TLS (behind a proxy)
	h2      string // "" = no HTTP/2 fingerprint captured (no h2capture module)
}

func (v view) IP() netip.Addr    { return netip.Addr{} }
func (v view) UserAgent() string { return v.ua }
func (v view) Method() string    { return "GET" }
func (v view) Path() string      { return "/" }
func (v view) Header(n string) string {
	return v.headers[n]
}

// protoView adds the optional ProtocolViewer + TLSFingerprinter capabilities,
// as the production requestView does. The protocol signal only applies when a
// TLS fingerprint proves Henbane terminated the client's TLS directly.
type protoView struct{ view }

func (v protoView) HTTPMajorVersion() int  { return v.view.proto }
func (v protoView) TLSFingerprint() string { return v.view.tlsfp }
func (v protoView) H2Fingerprint() string  { return v.view.h2 }

const (
	// chromeH2 is a real Chrome HTTP/2 fingerprint (pseudo-order m,a,s,p).
	chromeH2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	// goH2 is the Go/x-net client fingerprint (pseudo-order a,m,p,s — no browser).
	goH2 = "2:0;4:4194304;5:1048576;6:10485760|1073741824|0|a,m,p,s"
)

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"

// realBrowserHeaders is what an actual Chrome request carries.
func realBrowserHeaders() map[string]string {
	return map[string]string{
		"Sec-Fetch-Site":  "none",
		"Accept":          "text/html,application/xhtml+xml",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br",
	}
}

func total(rs []ports.ScoreResult) int {
	n := 0
	for _, r := range rs {
		n += r.Points
	}
	return n
}

func TestRealBrowserScoresZero(t *testing.T) {
	s := New(DefaultWeights())
	rs := s.Score(protoView{view{ua: chromeUA, headers: realBrowserHeaders(), proto: 2}})
	if total(rs) != 0 {
		t.Errorf("a well-formed browser request must score 0, got %d (%v)", total(rs), rs)
	}
}

func TestNonBrowserUAIgnored(t *testing.T) {
	s := New(DefaultWeights())
	// An honest curl UA with none of the browser headers must still score nothing —
	// consistency only judges clients that CLAIM to be a browser.
	if rs := s.Score(view{ua: "curl/8.5.0", headers: nil}); rs != nil {
		t.Errorf("non-browser UA must be ignored, got %v", rs)
	}
}

func TestBareBotWithBrowserUACompounds(t *testing.T) {
	s := New(DefaultWeights())
	// A stock HTTP client wearing a Chrome UA: sends none of the browser headers.
	rs := s.Score(view{ua: chromeUA, headers: nil})
	// no_fetch_metadata(2) + no_accept(2) + no_accept_language(1) + no_modern_encoding(1) = 6
	if total(rs) < 4 {
		t.Errorf("a bare bot with a browser UA should compound past the confirm threshold, got %d (%v)", total(rs), rs)
	}
}

func TestSingleMissIsSuspectLevel(t *testing.T) {
	s := New(DefaultWeights())
	h := realBrowserHeaders()
	delete(h, "Sec-Fetch-Site")
	rs := s.Score(protoView{view{ua: chromeUA, headers: h, proto: 2}})
	if total(rs) != DefaultWeights().NoFetchMetadata {
		t.Errorf("a single missing Sec-Fetch should score exactly the fetch-metadata weight, got %d (%v)", total(rs), rs)
	}
}

func TestLegacyHTTPAddsPoints(t *testing.T) {
	s := New(DefaultWeights())
	h := realBrowserHeaders()
	// Everything present but speaking HTTP/1.1 while claiming modern Chrome, and
	// Henbane terminated TLS itself (non-empty fp), so the version is the client's.
	rs := s.Score(protoView{view{ua: chromeUA, headers: h, proto: 1, tlsfp: "abc123"}})
	if total(rs) != DefaultWeights().LegacyHTTP {
		t.Errorf("HTTP/1.1 while claiming a browser (direct TLS) should add the legacy-http weight, got %d (%v)", total(rs), rs)
	}
}

func TestLegacyHTTPSkippedBehindProxy(t *testing.T) {
	s := New(DefaultWeights())
	h := realBrowserHeaders()
	// HTTP/1.1 but NO TLS fingerprint (Henbane is behind a proxy): r.ProtoMajor is
	// the proxy→Henbane hop, not the client's, so the signal must NOT fire — else
	// every real browser behind an HTTP/1.1-upstream CDN would be flagged.
	if rs := s.Score(protoView{view{ua: chromeUA, headers: h, proto: 1, tlsfp: ""}}); total(rs) != 0 {
		t.Errorf("behind a proxy (no TLS termination) the protocol signal must be skipped, got %v", rs)
	}
}

func TestLegacyHTTPSkippedWithoutProtocolView(t *testing.T) {
	s := New(DefaultWeights())
	h := realBrowserHeaders()
	// Same headers but the view does NOT implement ProtocolViewer: skipped.
	if rs := s.Score(view{ua: chromeUA, headers: h}); total(rs) != 0 {
		t.Errorf("without a ProtocolViewer the protocol signal must be skipped, got %v", rs)
	}
}

func TestH2MismatchAddsPoints(t *testing.T) {
	s := New(DefaultWeights())
	h := realBrowserHeaders()
	// A perfect-looking browser request — every header right, HTTP/2 — but the
	// captured h2 fingerprint is the Go client's (pseudo-order a,m,p,s), which no
	// browser emits. Only the h2 signal should fire.
	rs := s.Score(protoView{view{ua: chromeUA, headers: h, proto: 2, tlsfp: "x", h2: goH2}})
	if total(rs) != DefaultWeights().H2Mismatch {
		t.Errorf("a browser-impossible h2 fingerprint should add exactly the h2 weight, got %d (%v)", total(rs), rs)
	}
}

func TestH2BrowserFingerprintScoresZero(t *testing.T) {
	s := New(DefaultWeights())
	h := realBrowserHeaders()
	// Same request but with a real Chrome h2 fingerprint: nothing fires.
	if rs := s.Score(protoView{view{ua: chromeUA, headers: h, proto: 2, tlsfp: "x", h2: chromeH2}}); total(rs) != 0 {
		t.Errorf("a genuine browser h2 fingerprint must not be flagged, got %v", rs)
	}
}

func TestH2AbsentIsInert(t *testing.T) {
	s := New(DefaultWeights())
	h := realBrowserHeaders()
	// No capture module wired: H2Fingerprint() is "" and the signal is skipped.
	if rs := s.Score(protoView{view{ua: chromeUA, headers: h, proto: 2, tlsfp: "x", h2: ""}}); total(rs) != 0 {
		t.Errorf("an absent h2 fingerprint must be inert, got %v", rs)
	}
}

func TestH2SkippedWithoutH2View(t *testing.T) {
	s := New(DefaultWeights())
	h := realBrowserHeaders()
	// A view that does not implement H2Fingerprinter: the signal cannot be consulted.
	if rs := s.Score(view{ua: chromeUA, headers: h}); total(rs) != 0 {
		t.Errorf("without an H2Fingerprinter the h2 signal must be skipped, got %v", rs)
	}
}

func TestCaseInsensitiveEncoding(t *testing.T) {
	s := New(DefaultWeights())
	h := realBrowserHeaders()
	h["Accept-Encoding"] = "GZIP" // upper case is still valid gzip (RFC 7231)
	if rs := s.Score(protoView{view{ua: chromeUA, headers: h, proto: 2, tlsfp: "x"}}); total(rs) != 0 {
		t.Errorf("an upper-case GZIP must not be flagged as missing modern encoding, got %v", rs)
	}
}

func TestNoModernEncoding(t *testing.T) {
	s := New(DefaultWeights())
	h := realBrowserHeaders()
	h["Accept-Encoding"] = "identity"
	rs := s.Score(protoView{view{ua: chromeUA, headers: h, proto: 2}})
	if total(rs) != DefaultWeights().NoModernEncoding {
		t.Errorf("Accept-Encoding without gzip/br should score the encoding weight, got %d (%v)", total(rs), rs)
	}
}
