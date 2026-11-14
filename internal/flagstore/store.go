// Package flagstore is a bounded, TTL'd in-memory set of flagged client IPs.
// It imports only the standard library.
package flagstore

import (
	"net/netip"
	"sync"
	"time"
)

// Store records flagged client IPs with a TTL and a hard capacity bound.
type Store struct {
	mu      sync.Mutex
	entries map[netip.Addr]time.Time // ip -> expiry
	max     int
	ttl     time.Duration
	now     func() time.Time
}

// New returns a Store holding at most max entries, each expiring after ttl.
func New(max int, ttl time.Duration) *Store {
	return &Store{
		entries: make(map[netip.Addr]time.Time),
		max:     max,
		ttl:     ttl,
		now:     time.Now,
	}
}

// Flag records ip as flagged until now+ttl. Invalid IPs are ignored. When the
// store is at capacity it first evicts expired entries, then one arbitrary
// entry — a hard memory bound against flag-flooding from many IPs.
func (s *Store) Flag(ip netip.Addr) {
	if !ip.IsValid() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if _, ok := s.entries[ip]; !ok && len(s.entries) >= s.max {
		s.evictLocked(now)
	}
	s.entries[ip] = now.Add(s.ttl)
}

// Flagged reports whether ip is currently flagged (present and unexpired).
func (s *Store) Flagged(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.entries[ip]
	if !ok {
		return false
	}
	if !s.now().Before(exp) {
		delete(s.entries, ip)
		return false
	}
	return true
}

func (s *Store) evictLocked(now time.Time) {
	for ip, exp := range s.entries {
		if !now.Before(exp) {
			delete(s.entries, ip)
		}
	}
	if len(s.entries) >= s.max {
		for ip := range s.entries { // drop one arbitrary entry to make room
			delete(s.entries, ip)
			break
		}
	}
}

// len reports the current entry count (test helper).
func (s *Store) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
