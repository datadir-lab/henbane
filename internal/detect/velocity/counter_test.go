package velocity

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestCounterFiresWhenLimitExceeded(t *testing.T) {
	c := newCounter(3, time.Minute, 100)
	ip := netip.MustParseAddr("203.0.113.7")

	// First `limit` requests stay under; the (limit+1)th fires.
	for i := 1; i <= 3; i++ {
		if c.hit(ip) {
			t.Fatalf("hit %d fired early (limit 3)", i)
		}
	}
	if !c.hit(ip) {
		t.Fatal("4th hit should exceed the limit of 3 and fire")
	}
}

func TestCounterWindowResets(t *testing.T) {
	c := newCounter(2, time.Minute, 100)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cur := base
	c.now = func() time.Time { return cur }
	ip := netip.MustParseAddr("203.0.113.8")

	c.hit(ip)
	c.hit(ip)
	if !c.hit(ip) {
		t.Fatal("3rd hit in-window should fire (limit 2)")
	}
	// Advance past the window: the counter must reset and not fire again until
	// the new window is itself exceeded.
	cur = base.Add(time.Minute + time.Second)
	if c.hit(ip) {
		t.Fatal("first hit of a fresh window must not fire")
	}
	if c.hit(ip) {
		t.Fatal("second hit of a fresh window (limit 2) must not fire")
	}
	if !c.hit(ip) {
		t.Fatal("third hit of the fresh window should fire")
	}
}

func TestCounterInvalidIPNeverFiresOrTracks(t *testing.T) {
	c := newCounter(1, time.Minute, 100)
	for i := 0; i < 5; i++ {
		if c.hit(netip.Addr{}) {
			t.Fatal("invalid IP must never fire")
		}
	}
	if got := c.len(); got != 0 {
		t.Fatalf("invalid IPs must not be tracked, len=%d", got)
	}
}

func TestCounterUnmapsSharesCount(t *testing.T) {
	c := newCounter(1, time.Minute, 100)
	v4 := netip.MustParseAddr("1.2.3.4")
	mapped := netip.MustParseAddr("::ffff:1.2.3.4")
	if c.hit(v4) {
		t.Fatal("first hit should not fire (limit 1)")
	}
	// The mapped form is the same client: the 2nd combined hit must fire.
	if !c.hit(mapped) {
		t.Fatal("IPv4 and its IPv4-in-IPv6 form must share one counter")
	}
}

func TestCounterIsBounded(t *testing.T) {
	const max = 64
	c := newCounter(1000, time.Minute, max)
	// Insert far more distinct IPs than the cap; the map must never exceed it.
	for i := 0; i < 1000; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		c.hit(ip)
		if got := c.len(); got > max {
			t.Fatalf("store exceeded cap: len=%d max=%d", got, max)
		}
	}
}

func TestCounterCountSaturates(t *testing.T) {
	c := newCounter(2, time.Minute, 100)
	ip := netip.MustParseAddr("203.0.113.9")
	// Hammer well past the limit within one window; the stored count must not
	// grow without bound (saturates at limit+1) while still firing.
	for i := 0; i < 1_000_000; i++ {
		c.hit(ip)
	}
	if got := c.byIP[ip].count; got > 3 {
		t.Fatalf("count must saturate at limit+1=3, got %d", got)
	}
	if !c.hit(ip) {
		t.Fatal("still over the limit, must keep firing")
	}
}

func TestCounterConcurrentHitsAreSafe(t *testing.T) {
	c := newCounter(10, time.Minute, 1000)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ip := netip.AddrFrom4([4]byte{10, 0, 0, byte(g)})
			for i := 0; i < 500; i++ {
				c.hit(ip)
			}
		}(g)
	}
	wg.Wait()
	if got := c.len(); got > 16 {
		t.Fatalf("expected at most 16 tracked IPs, got %d", got)
	}
}
