// Package honeypot provides a trap-path honeypot detector: any request under a
// configured path prefix flags the client as confirmed-hostile.
package honeypot

import (
	"net/netip"
	"strings"

	"github.com/datadir-lab/henbane/internal/ports"
)

// Store records and reports flagged client IPs.
type Store interface {
	Flag(netip.Addr)
	Flagged(netip.Addr) bool
}

type detector struct {
	prefix string
	store  Store
}

// New returns a Detector that flags any client requesting a path under prefix,
// and fires for previously-flagged clients.
func New(prefix string, store Store) ports.Detector {
	return detector{prefix: prefix, store: store}
}

func (d detector) Name() string { return "honeypot" }

func (d detector) Inspect(r ports.RequestView) (ports.Result, bool) {
	ip := r.IP().Unmap()
	if strings.HasPrefix(r.Path(), d.prefix) {
		// The trap path is public (robots.txt + a hidden link), so an attacker
		// can lure a victim's browser into fetching it cross-site (e.g.
		// <img src=trap>) to get that victim's real IP flagged and blocked. A
		// browser loading a cross-site subresource sends Sec-Fetch-Site:
		// cross-site, so ignore those. Real crawlers fetch the bait same-origin
		// while crawling, or are non-browser clients that send no Sec-Fetch
		// headers — both still trip the trap.
		if r.Header("Sec-Fetch-Site") == "cross-site" {
			return ports.Result{}, false
		}
		if ip.IsValid() {
			d.store.Flag(ip)
		}
		return ports.Result{Signal: "honeypot", Tier: ports.TierConfirmed}, true
	}
	if d.store.Flagged(ip) {
		return ports.Result{Signal: "flagged", Tier: ports.TierConfirmed}, true
	}
	return ports.Result{}, false
}
