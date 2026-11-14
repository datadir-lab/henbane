package honeypot

import (
	"net/netip"
	"testing"

	"github.com/henbane-sh/henbane/internal/ports"
)

type view struct {
	ip       netip.Addr
	path     string
	secFetch string
}

func (v view) IP() netip.Addr    { return v.ip }
func (v view) UserAgent() string { return "" }
func (v view) Method() string    { return "GET" }
func (v view) Path() string      { return v.path }
func (v view) Header(name string) string {
	if name == "Sec-Fetch-Site" {
		return v.secFetch
	}
	return ""
}

type memStore map[netip.Addr]bool

func (m memStore) Flag(ip netip.Addr)         { m[ip] = true }
func (m memStore) Flagged(ip netip.Addr) bool { return m[ip] }

func TestTrapHitFlagsAndFires(t *testing.T) {
	store := memStore{}
	d := New("/.well-known/hb-trap", store)
	ip := netip.MustParseAddr("203.0.113.9")

	res, ok := d.Inspect(view{ip: ip, path: "/.well-known/hb-trap/x"})
	if !ok || res.Signal != "honeypot" || res.Tier != ports.TierConfirmed {
		t.Errorf("trap hit = %+v, %v", res, ok)
	}
	if !store.Flagged(ip) {
		t.Error("trap hit must flag the client")
	}
}

func TestPreviouslyFlaggedFires(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.9")
	store := memStore{ip: true}
	d := New("/.well-known/hb-trap", store)

	res, ok := d.Inspect(view{ip: ip, path: "/normal"})
	if !ok || res.Signal != "flagged" || res.Tier != ports.TierConfirmed {
		t.Errorf("flagged = %+v, %v", res, ok)
	}
}

func TestNormalRequestDoesNotFire(t *testing.T) {
	d := New("/.well-known/hb-trap", memStore{})
	if _, ok := d.Inspect(view{ip: netip.MustParseAddr("203.0.113.9"), path: "/index.html"}); ok {
		t.Error("normal request should not fire")
	}
}

func TestInvalidIPNotFlagged(t *testing.T) {
	store := memStore{}
	d := New("/.well-known/hb-trap", store)
	res, ok := d.Inspect(view{ip: netip.Addr{}, path: "/.well-known/hb-trap/x"})
	if !ok || res.Signal != "honeypot" || res.Tier != ports.TierConfirmed {
		t.Errorf("trap must still fire for an invalid IP: res=%+v ok=%v", res, ok)
	}
	if store.Flagged(netip.Addr{}) {
		t.Error("invalid IP must not be flagged")
	}
}

func TestCrossSiteTrapNotFlagged(t *testing.T) {
	store := memStore{}
	d := New("/.well-known/hb-trap", store)
	ip := netip.MustParseAddr("203.0.113.9")
	// A victim's browser lured into loading the trap cross-site (attacker embed)
	// must NOT be flagged — otherwise an attacker could 403 arbitrary users.
	res, ok := d.Inspect(view{ip: ip, path: "/.well-known/hb-trap/x", secFetch: "cross-site"})
	if ok {
		t.Errorf("cross-site subresource must not fire the trap: res=%+v", res)
	}
	if store.Flagged(ip) {
		t.Error("cross-site trap load must not flag the client")
	}
}
