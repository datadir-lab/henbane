package hostingip

import (
	"net/netip"
	"testing"

	"github.com/datadir-lab/henbane/internal/ports"
)

var _ ports.Scorer = (*Scorer)(nil)

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"

type view struct {
	ua string
	ip netip.Addr
}

func (v view) IP() netip.Addr       { return v.ip }
func (v view) UserAgent() string    { return v.ua }
func (v view) Method() string       { return "GET" }
func (v view) Path() string         { return "/" }
func (v view) Header(string) string { return "" }

func points(rs []ports.ScoreResult) int {
	n := 0
	for _, r := range rs {
		n += r.Points
	}
	return n
}

// fixed is a Scorer over a small, stable CIDR set so the behaviour tests do not depend
// on the live bundled data.
func fixed(weight int) *Scorer {
	return New([]string{"203.0.113.0/24", "198.51.100.0/24"}, []string{"2001:db8::/32"}, weight)
}

func TestBrowserFromHostingFlagged(t *testing.T) {
	s := fixed(2)
	rs := s.Score(view{ua: chromeUA, ip: netip.MustParseAddr("203.0.113.9")})
	if points(rs) != 2 {
		t.Errorf("a browser from a hosting range should score the weight (2), got %d (%v)", points(rs), rs)
	}
	if len(rs) == 1 && string(rs[0].Signal) != "browser_mismatch:datacenter_ip" {
		t.Errorf("unexpected signal %q", rs[0].Signal)
	}
}

func TestNonBrowserFromHostingIgnored(t *testing.T) {
	s := fixed(0)
	// An honest bot from a datacenter is expected and must not be penalized.
	if rs := s.Score(view{ua: "curl/8.5.0", ip: netip.MustParseAddr("203.0.113.9")}); rs != nil {
		t.Errorf("a non-browser from a hosting range must not be flagged, got %v", rs)
	}
}

func TestBrowserFromResidentialNotFlagged(t *testing.T) {
	s := fixed(0)
	// 192.0.2.0/24 (TEST-NET-1) is outside the hosting set: a normal residential client.
	if rs := s.Score(view{ua: chromeUA, ip: netip.MustParseAddr("192.0.2.5")}); rs != nil {
		t.Errorf("a browser from a non-hosting IP must not be flagged, got %v", rs)
	}
}

func TestInvalidIPIgnored(t *testing.T) {
	s := fixed(0)
	if rs := s.Score(view{ua: chromeUA, ip: netip.Addr{}}); rs != nil {
		t.Errorf("an invalid IP must not be flagged, got %v", rs)
	}
}

func TestIPv6Hosting(t *testing.T) {
	s := fixed(1)
	if rs := s.Score(view{ua: chromeUA, ip: netip.MustParseAddr("2001:db8::1")}); points(rs) != 1 {
		t.Errorf("a browser from a v6 hosting range should be flagged, got %v", rs)
	}
	if rs := s.Score(view{ua: chromeUA, ip: netip.MustParseAddr("2001:dead::1")}); rs != nil {
		t.Errorf("a browser from a v6 non-hosting range must not be flagged, got %v", rs)
	}
}

func TestDefaultWeightApplied(t *testing.T) {
	if s := fixed(0); s.weight != DefaultWeight {
		t.Errorf("weight <= 0 should fall back to DefaultWeight (%d), got %d", DefaultWeight, s.weight)
	}
}

// TestBundledDataSortedNonOverlapping verifies the invariant the runtime binary search
// relies on, directly on the generated data: each family is sorted by address and no
// prefix contains the next. A gen bug that broke this would make membership unreliable.
func TestBundledDataSortedNonOverlapping(t *testing.T) {
	s := NewDefault(0)
	if len(s.v4) == 0 || len(s.v6) == 0 {
		t.Fatalf("bundled data looks empty: v4=%d v6=%d", len(s.v4), len(s.v6))
	}
	for _, set := range [][]netip.Prefix{s.v4, s.v6} {
		for i := 1; i < len(set); i++ {
			if set[i].Addr().Compare(set[i-1].Addr()) < 0 {
				t.Fatalf("prefixes not sorted at %d: %v before %v", i, set[i-1], set[i])
			}
			if set[i-1].Contains(set[i].Addr()) {
				t.Fatalf("overlapping prefixes: %v contains %v", set[i-1], set[i])
			}
		}
	}
	// Self-consistent match: a browser from the first bundled range is flagged.
	ip := s.v4[0].Addr()
	if rs := s.Score(view{ua: chromeUA, ip: ip}); points(rs) != DefaultWeight {
		t.Errorf("a browser from a bundled hosting range should be flagged, got %v", rs)
	}
	if rs := s.Score(view{ua: "python-requests/2.32", ip: ip}); rs != nil {
		t.Errorf("a non-browser from a bundled hosting range must not be flagged, got %v", rs)
	}
}
