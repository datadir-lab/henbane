// Package velocity provides a request-rate detector: a client IP that exceeds a
// configured number of requests within a fixed window is classified at a
// configured tier. It imports only the ports package and the standard library.
package velocity

import (
	"time"

	"github.com/datadir-lab/henbane/internal/ports"
)

type detector struct {
	c    *counter
	tier ports.Tier
}

// New returns a Detector that fires at tier once a client IP exceeds limit
// requests within window, tracking at most maxTracked distinct IPs. The
// detector keys on the resolved client IP; callers wire it only when the tier
// it reports has a handler (a suspect verdict needs a proof-of-work gate).
func New(limit int, window time.Duration, maxTracked int, tier ports.Tier) ports.Detector {
	return detector{c: newCounter(limit, window, maxTracked), tier: tier}
}

func (d detector) Name() string { return "velocity" }

func (d detector) Inspect(r ports.RequestView) (ports.Result, bool) {
	ip := r.IP().Unmap()
	if !ip.IsValid() {
		return ports.Result{}, false
	}
	if d.c.hit(ip) {
		return ports.Result{Signal: "velocity", Tier: d.tier}, true
	}
	return ports.Result{}, false
}
