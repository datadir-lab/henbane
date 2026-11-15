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
