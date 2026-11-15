package velocity

import (
	"net/netip"
	"sync"
	"time"
)

// entry is one IP's fixed-window request count.
type entry struct {
	windowStart time.Time
	count       int
}

// counter is a bounded, fixed-window per-IP request counter. It holds at most
// max entries; at capacity it evicts expired windows then one arbitrary entry,
// a hard memory bound against counter-flooding from many source IPs.
type counter struct {
	mu     sync.Mutex
	byIP   map[netip.Addr]entry
	limit  int
	window time.Duration
	max    int
	now    func() time.Time
}

// newCounter returns a counter that fires once an IP exceeds limit requests
// within window, tracking at most max distinct IPs. Degenerate arguments are
// clamped so the store is always bounded and useful.
func newCounter(limit int, window time.Duration, max int) *counter {
	if limit < 1 {
		limit = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	if max < 1 {
		max = 1
	}
	return &counter{
		byIP:   make(map[netip.Addr]entry),
		limit:  limit,
		window: window,
		max:    max,
		now:    time.Now,
	}
}

// hit records a request from ip and reports whether ip has exceeded the limit
// within the current window. Invalid IPs are never tracked and never fire.
func (c *counter) hit(ip netip.Addr) bool {
	// Unmap defensively so an IPv4-in-IPv6 form cannot split a client's rate
	// across two keys, regardless of what the caller passed.
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	e, ok := c.byIP[ip]
	if !ok || !now.Before(e.windowStart.Add(c.window)) {
		// New IP, or its window has elapsed: start a fresh window. Only a brand
		// new IP can grow the map, so bound it here.
		if !ok && len(c.byIP) >= c.max {
			c.evictLocked(now)
		}
		c.byIP[ip] = entry{windowStart: now, count: 1}
		return 1 > c.limit
	}
	// Same window: increment, saturating at limit+1 so a sustained flood cannot
	// overflow the count.
	if e.count <= c.limit {
		e.count++
	}
	c.byIP[ip] = e
	return e.count > c.limit
}

// evictLocked frees room in a full map: drop every expired window, and if still
// full, one arbitrary entry. Caller holds the lock.
func (c *counter) evictLocked(now time.Time) {
	for ip, e := range c.byIP {
		if !now.Before(e.windowStart.Add(c.window)) {
			delete(c.byIP, ip)
		}
	}
	if len(c.byIP) >= c.max {
		for ip := range c.byIP {
			delete(c.byIP, ip)
			break
		}
	}
}

// len reports the current entry count (test helper).
func (c *counter) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byIP)
}
