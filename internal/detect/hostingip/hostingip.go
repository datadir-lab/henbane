// Package hostingip scores a soft signal: a client that claims to be a browser but
// originates from a cloud or hosting provider's published IP range is more likely
// automated than a real user, who browses from a residential or mobile ISP. Anti-bot
// stacks check the originating network before almost anything else, because a browser
// does not run in a datacenter.
//
// It is a weak, COMPOUNDING signal, not a block. A thin legitimate population browses
// from these ranges too (corporate secure-web-gateways, cloud VPNs), so on its own the
// point stays below the challenge threshold; it tips a browser-claimer that ALSO trips
// a header or fingerprint signal toward a confident verdict. The sophisticated scrapers
// evade it entirely with residential proxies (Imperva's 2025 data attributes 21% of bot
// attacks to residential proxies, specifically to beat this signal), so it catches the
// cheap, datacenter-hosted majority, not the determined adversary. Verified good bots
// are allowlisted by the verifiers before scoring runs, so a crawler from its own cloud
// is never penalized here.
//
// The bundled ranges come from the providers' own feeds; refresh them with gen.
//
//go:generate go run ./gen
package hostingip

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/datadir-lab/henbane/internal/ports"
)

// DefaultWeight is a single compounding point: below the Suspect threshold on its own
// (a legitimate cloud-VPN user is not challenged), but enough to push a browser-claimer
// that also trips another signal toward Confirmed.
const DefaultWeight = 1

// Scorer implements ports.Scorer over a set of cloud/hosting prefixes.
type Scorer struct {
	v4, v6 []netip.Prefix // each sorted by address, non-overlapping (binary-searchable)
	weight int
}

// New returns a Scorer over the given CIDR sets with the given weight (<=0 uses
// DefaultWeight). Invalid or wrong-family CIDRs are skipped. Use NewDefault for the
// bundled provider ranges.
func New(v4CIDRs, v6CIDRs []string, weight int) *Scorer {
	if weight <= 0 {
		weight = DefaultWeight
	}
	return &Scorer{v4: parseSorted(v4CIDRs, true), v6: parseSorted(v6CIDRs, false), weight: weight}
}

// NewDefault returns a Scorer over the bundled cloud-provider ranges.
func NewDefault(weight int) *Scorer { return New(lines(bundledV4), lines(bundledV6), weight) }

// Name identifies the scorer.
func (s *Scorer) Name() string { return "hosting_ip" }

// Score adds the hosting-IP point when the client claims a mainstream browser yet
// originates from a cloud/hosting range. It only judges browser-claimers, so an honest
// non-browser client (which is expected to run in a datacenter) is never penalized.
func (s *Scorer) Score(r ports.RequestView) []ports.ScoreResult {
	if !claimsBrowser(r.UserAgent()) {
		return nil
	}
	ip := r.IP().Unmap()
	if !ip.IsValid() || !s.contains(ip) {
		return nil
	}
	return []ports.ScoreResult{{Signal: ports.Signal("browser_mismatch:datacenter_ip"), Points: s.weight}}
}

// contains reports whether ip falls in any bundled prefix, via a binary search over the
// non-overlapping sorted set: the only possible container is the rightmost prefix whose
// network address is <= ip.
func (s *Scorer) contains(ip netip.Addr) bool {
	set := s.v4
	if ip.Is6() {
		set = s.v6
	}
	i := sort.Search(len(set), func(i int) bool { return set[i].Addr().Compare(ip) > 0 }) - 1
	return i >= 0 && set[i].Contains(ip)
}

func parseSorted(cidrs []string, wantV4 bool) []netip.Prefix {
	var out []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		p = p.Masked()
		if p.Addr().Is4() != wantV4 {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Compare(out[j].Addr()) < 0 })
	return out
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// claimsBrowser mirrors the consistency scorer: a Mozilla-prefixed UA carrying a known
// engine token. Duplicated rather than imported to keep this detector independent.
func claimsBrowser(ua string) bool {
	if !strings.HasPrefix(ua, "Mozilla/") {
		return false
	}
	for _, tok := range []string{"Chrome/", "Firefox/", "Safari/", "Edg/", "OPR/"} {
		if strings.Contains(ua, tok) {
			return true
		}
	}
	return false
}

var _ ports.Scorer = (*Scorer)(nil)
