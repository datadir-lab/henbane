// Package remotedeny is a denylist detector whose blocked prefixes are fetched
// from a remote feed and hot-swapped at runtime. It is the consumer half of
// federation: point it at a shared bad-IP blocklist (a public threat feed, your
// own, or a future Poison Garden) and every listed client is blocked. The set is
// swapped atomically by a Refresher; the detector itself only reads.
//
// Trust model: the feed is operator-chosen and trusted, but parsing is strict and
// bounded — over-broad prefixes are rejected (a feed cannot inject 0.0.0.0/0 to
// block everyone), the entry count is capped, and a failed fetch keeps the last
// good set (fail-safe), never blocking-all or allowing-all.
package remotedeny

import (
	"bufio"
	"bytes"
	"net/netip"
	"sync/atomic"

	"github.com/datadir-lab/henbane/internal/ports"
)

// blockset is an immutable set of denied prefixes.
type blockset struct {
	prefixes []netip.Prefix
}

func (s *blockset) contains(ip netip.Addr) bool {
	for _, p := range s.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Detector fires Blocked for a client IP in the current remote denylist.
type Detector struct {
	cur atomic.Pointer[blockset]
}

// New returns a Detector with an empty set (fires for nothing until refreshed).
func New() *Detector {
	d := &Detector{}
	d.cur.Store(&blockset{})
	return d
}

// Name identifies the detector.
func (d *Detector) Name() string { return "remote_denylist" }

// Inspect fires for a client IP present in the current set.
func (d *Detector) Inspect(r ports.RequestView) (ports.Result, bool) {
	ip := r.IP().Unmap()
	if !ip.IsValid() {
		return ports.Result{}, false
	}
	if d.cur.Load().contains(ip) {
		return ports.Result{Signal: "remote_denylist", Tier: ports.TierBlocked}, true
	}
	return ports.Result{}, false
}

// replace atomically swaps in a new set of prefixes.
func (d *Detector) replace(prefixes []netip.Prefix) {
	d.cur.Store(&blockset{prefixes: prefixes})
}

// count reports the current prefix count (test/metrics helper).
func (d *Detector) count() int { return len(d.cur.Load().prefixes) }

// parseList parses a line-based blocklist: one CIDR or bare IP per line, '#'
// comments and blank lines ignored. Invalid lines are skipped; a bare IP becomes
// a host prefix (/32 or /128); a /0 prefix is rejected (it would block every
// client); at most maxEntries prefixes are returned.
func parseList(data []byte, maxEntries int) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := string(bytes.TrimSpace(sc.Bytes()))
		if line == "" || line[0] == '#' {
			continue
		}
		p, ok := parsePrefix(line)
		if !ok || p.Bits() == 0 {
			continue
		}
		out = append(out, p)
		if maxEntries > 0 && len(out) >= maxEntries {
			break
		}
	}
	return out
}

// parsePrefix accepts either a CIDR ("1.2.3.0/24") or a bare IP ("1.2.3.4",
// which becomes a host prefix), returning the masked prefix.
func parsePrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}
