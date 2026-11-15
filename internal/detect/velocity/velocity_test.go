package velocity

import (
	"net/netip"
	"testing"
	"time"

	"github.com/datadir-lab/henbane/internal/ports"
)

type view struct {
	ip netip.Addr
}

func (v view) IP() netip.Addr            { return v.ip }
func (v view) UserAgent() string         { return "" }
func (v view) Method() string            { return "GET" }
func (v view) Path() string              { return "/" }
func (v view) Header(name string) string { return "" }

func TestDetectorFiresAtConfiguredTierOverLimit(t *testing.T) {
	d := New(2, time.Minute, 100, ports.TierSuspect)
	ip := netip.MustParseAddr("203.0.113.20")
	r := view{ip: ip}

	for i := 1; i <= 2; i++ {
		if _, ok := d.Inspect(r); ok {
			t.Fatalf("request %d fired under the limit of 2", i)
		}
	}
	res, ok := d.Inspect(r)
	if !ok {
		t.Fatal("3rd request should exceed the limit and fire")
	}
	if res.Signal != "velocity" || res.Tier != ports.TierSuspect {
		t.Errorf("result = %+v, want velocity/suspect", res)
	}
}

func TestDetectorHonorsConfirmedTier(t *testing.T) {
	d := New(1, time.Minute, 100, ports.TierConfirmed)
	ip := netip.MustParseAddr("203.0.113.21")
	r := view{ip: ip}
	d.Inspect(r) // 1st under limit
	res, ok := d.Inspect(r)
	if !ok || res.Tier != ports.TierConfirmed {
		t.Errorf("confirmed-tier detector = %+v, %v", res, ok)
	}
}

func TestDetectorIgnoresInvalidIP(t *testing.T) {
	d := New(1, time.Minute, 100, ports.TierSuspect)
	r := view{ip: netip.Addr{}}
	for i := 0; i < 5; i++ {
		if _, ok := d.Inspect(r); ok {
			t.Fatal("an invalid client IP must never fire the velocity signal")
		}
	}
}

func TestDetectorName(t *testing.T) {
	if got := New(1, time.Minute, 1, ports.TierSuspect).Name(); got != "velocity" {
		t.Errorf("Name() = %q, want velocity", got)
	}
}
