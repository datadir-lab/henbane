package denylist

import (
	"net/netip"
	"testing"

	"github.com/datadir-lab/henbane/internal/ports"
)

type view struct {
	ip netip.Addr
	ua string
}

func (v view) IP() netip.Addr       { return v.ip }
func (v view) UserAgent() string    { return v.ua }
func (v view) Method() string       { return "GET" }
func (v view) Path() string         { return "/" }
func (v view) Header(string) string { return "" }

func TestIPDetector(t *testing.T) {
	d := NewIP([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	res, ok := d.Inspect(view{ip: netip.MustParseAddr("203.0.113.9")})
	if !ok || res.Signal != "denylist_ip" || res.Tier != ports.TierBlocked {
		t.Errorf("match = %+v, %v", res, ok)
	}
	// IPv4-mapped-IPv6 still matches.
	if _, ok := d.Inspect(view{ip: netip.MustParseAddr("::ffff:203.0.113.9")}); !ok {
		t.Error("ipv4-mapped-ipv6 should match ipv4 cidr")
	}
	if _, ok := d.Inspect(view{ip: netip.MustParseAddr("198.51.100.1")}); ok {
		t.Error("non-denylisted IP should not fire")
	}
}

func TestUADetector(t *testing.T) {
	d := NewUA([]string{"GPTBot", ""}) // empty entry ignored
	if _, ok := d.Inspect(view{ua: "Mozilla gptBOT/1"}); !ok {
		t.Error("case-insensitive substring should match")
	}
	if _, ok := d.Inspect(view{ua: "Mozilla/5.0"}); ok {
		t.Error("non-denylisted UA should not fire")
	}
	if _, ok := d.Inspect(view{ua: ""}); ok {
		t.Error("empty UA should not fire")
	}
}

// fpView additionally implements ports.TLSFingerprinter.
type fpView struct {
	view
	fp string
}

func (v fpView) TLSFingerprint() string { return v.fp }

func TestTLSFPDetector(t *testing.T) {
	d := NewTLSFP([]string{"deadbeefdeadbeef", "", "cafebabecafebabe"})

	res, ok := d.Inspect(fpView{fp: "deadbeefdeadbeef"})
	if !ok || res.Signal != "denylist_tls" || res.Tier != ports.TierBlocked {
		t.Errorf("listed fingerprint = %+v, %v; want blocked", res, ok)
	}
	if _, ok := d.Inspect(fpView{fp: "0000000000000000"}); ok {
		t.Error("an unlisted fingerprint must not fire")
	}
	if _, ok := d.Inspect(fpView{fp: ""}); ok {
		t.Error("an empty fingerprint (no TLS termination) must not fire")
	}
	// A RequestView that does not expose a TLS fingerprint must not fire.
	if _, ok := d.Inspect(view{}); ok {
		t.Error("a non-TLSFingerprinter view must not fire")
	}
}
