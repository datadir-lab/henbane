package flagstore

import (
	"net/netip"
	"testing"
	"time"
)

func TestFlagAndFlagged(t *testing.T) {
	s := New(10, time.Hour)
	ip := netip.MustParseAddr("203.0.113.9")
	if s.Flagged(ip) {
		t.Fatal("not flagged yet")
	}
	s.Flag(ip)
	if !s.Flagged(ip) {
		t.Fatal("should be flagged")
	}
}

func TestExpiry(t *testing.T) {
	s := New(10, time.Minute)
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	ip := netip.MustParseAddr("203.0.113.9")
	s.Flag(ip)
	if !s.Flagged(ip) {
		t.Fatal("flagged within ttl")
	}
	now = now.Add(2 * time.Minute)
	if s.Flagged(ip) {
		t.Fatal("should have expired")
	}
}

func TestInvalidIPIgnored(t *testing.T) {
	s := New(10, time.Hour)
	s.Flag(netip.Addr{}) // invalid
	if s.Flagged(netip.Addr{}) {
		t.Fatal("invalid IP must never be flagged")
	}
}

func TestMaxBound(t *testing.T) {
	s := New(3, time.Hour)
	for i := 0; i < 100; i++ {
		s.Flag(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}))
	}
	if n := s.len(); n > 3 {
		t.Fatalf("store grew to %d, want <= 3 (hard bound)", n)
	}
}
