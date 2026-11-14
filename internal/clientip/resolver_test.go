package clientip

import (
	"net/netip"
	"testing"
)

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("bad cidr %q: %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		trusted    []netip.Prefix
		remoteAddr string
		xff        []string
		want       string // "" => invalid
	}{
		{"edge mode ignores xff", nil, "198.51.100.7:5000", []string{"203.0.113.9"}, "198.51.100.7"},
		{"single trusted proxy returns client", prefixes(t, "10.0.0.0/8"), "10.0.0.1:5000", []string{"203.0.113.9"}, "203.0.113.9"},
		{"multi-hop skips trusted, spoofed leftmost ignored", prefixes(t, "10.0.0.0/8"), "10.0.0.1:5000", []string{"1.2.3.4, 203.0.113.9, 10.0.0.2"}, "203.0.113.9"},
		{"untrusted connection ignores xff", prefixes(t, "10.0.0.0/8"), "198.51.100.7:5000", []string{"203.0.113.9"}, "198.51.100.7"},
		{"port stripped from xff entry", prefixes(t, "10.0.0.0/8"), "10.0.0.1:5000", []string{"203.0.113.9:12345"}, "203.0.113.9"},
		{"ipv6 client via trusted proxy", prefixes(t, "10.0.0.0/8"), "10.0.0.1:5000", []string{"2001:db8::1"}, "2001:db8::1"},
		{"malformed entries skipped", prefixes(t, "10.0.0.0/8"), "10.0.0.1:5000", []string{",, garbage ,203.0.113.9, 10.0.0.2"}, "203.0.113.9"},
		{"all trusted falls back to invalid", prefixes(t, "10.0.0.0/8"), "10.0.0.1:5000", []string{"10.0.0.2, 10.0.0.3"}, ""},
		{"multiple xff header lines merged", prefixes(t, "10.0.0.0/8"), "10.0.0.1:5000", []string{"1.2.3.4", "203.0.113.9, 10.0.0.2"}, "203.0.113.9"},
		{"edge mode bracketed ipv6 connection", nil, "[2001:db8::1]:5000", nil, "2001:db8::1"},
		{"bracketed ipv6 client via trusted proxy", prefixes(t, "10.0.0.0/8"), "10.0.0.1:5000", []string{"[2001:db8::1]:443"}, "2001:db8::1"},
		{"quoted xff entry", prefixes(t, "10.0.0.0/8"), "10.0.0.1:5000", []string{"\"203.0.113.9\""}, "203.0.113.9"},
		{"ipv4-mapped ipv6 xff entry is unmapped", prefixes(t, "10.0.0.0/8"), "10.0.0.1:5000", []string{"::ffff:203.0.113.9"}, "203.0.113.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NewResolver(tc.trusted).ClientIP(tc.remoteAddr, tc.xff)
			if tc.want == "" {
				if got.IsValid() {
					t.Fatalf("got %v, want invalid", got)
				}
				return
			}
			if got != netip.MustParseAddr(tc.want) {
				t.Fatalf("got %v, want %s", got, tc.want)
			}
		})
	}
}
