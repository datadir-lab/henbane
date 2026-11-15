// Package crawlerips verifies AI crawlers by their published IP ranges. The
// major AI crawlers — OpenAI's GPTBot/ChatGPT-User/OAI-SearchBot, Anthropic's
// ClaudeBot family, PerplexityBot — publish the CIDR blocks their requests
// originate from but expose no reverse DNS, so the FCrDNS good-bot verifier
// cannot confirm them. This verifier is the complement: a client whose
// User-Agent claims one of these crawlers is the real thing only if its IP falls
// inside that crawler's published ranges. A verified crawler is allowed (so an
// operator does not poison the AI crawlers they want indexing them); a client
// that claims a crawler from an IP outside its ranges is a spoofer, optionally
// blocked. Matching is a pure in-memory CIDR check — never any request-path I/O.
//
//go:generate go run ./gen
package crawlerips

import (
	"net/netip"
	"strings"

	"github.com/datadir-lab/henbane/internal/ports"
)

// Crawler is a recognized AI crawler verifiable by its published IP ranges.
type Crawler struct {
	Name     string
	UAs      []string       // User-Agent substrings (lowercased) a genuine instance presents
	Prefixes []netip.Prefix // masked CIDR prefixes its requests legitimately originate from
}

// Defaults returns the bundled set of IP-range-verifiable AI crawlers. Refresh
// the snapshot with `go generate ./internal/detect/crawlerips/...`, which
// re-fetches each vendor's own feed. Invalid bundled prefixes are skipped rather
// than panicking, so a bad snapshot can never crash the gateway at startup.
func Defaults() []Crawler {
	out := make([]Crawler, 0, len(bundled))
	for _, b := range bundled {
		c := Crawler{Name: b.name}
		for _, ua := range b.uas {
			c.UAs = append(c.UAs, strings.ToLower(ua))
		}
		for _, s := range b.cidrs {
			if p, err := netip.ParsePrefix(s); err == nil {
				c.Prefixes = append(c.Prefixes, p.Masked())
			}
		}
		if len(c.Prefixes) > 0 && len(c.UAs) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// Verifier implements ports.Verifier by matching a crawler's User-Agent and then
// confirming the client IP falls inside that crawler's published ranges.
type Verifier struct {
	crawlers   []Crawler
	spoofTier  ports.Tier
	blockSpoof bool
}

// New returns a Verifier for the given crawlers. If blockSpoof is true, a client
// whose User-Agent claims a crawler but originates outside its published ranges
// is forced to spoofTier; otherwise such a client gets no opinion (only verified
// crawlers are acted on).
func New(crawlers []Crawler, spoofTier ports.Tier, blockSpoof bool) *Verifier {
	cs := make([]Crawler, len(crawlers))
	for i, c := range crawlers {
		uas := make([]string, len(c.UAs))
		for j, ua := range c.UAs {
			uas[j] = strings.ToLower(ua)
		}
		c.UAs = uas
		cs[i] = c
	}
	return &Verifier{crawlers: cs, spoofTier: spoofTier, blockSpoof: blockSpoof}
}

// Name identifies the verifier.
func (v *Verifier) Name() string { return "ai_crawler" }

// Verify allows an IP-range-verified AI crawler and (when configured) blocks a
// spoofer. It performs no I/O: the published ranges are held in memory.
func (v *Verifier) Verify(r ports.RequestView) (ports.Signal, ports.Tier, bool) {
	c := v.match(strings.ToLower(r.UserAgent()))
	if c == nil {
		return "", 0, false // not claiming to be a recognized AI crawler
	}
	ip := r.IP().Unmap()
	if !ip.IsValid() {
		return "", 0, false
	}
	if c.contains(ip) {
		return ports.Signal("ai_crawler:" + c.Name), ports.TierPass, true
	}
	if v.blockSpoof {
		return ports.Signal("spoofed:" + c.Name), v.spoofTier, true
	}
	return "", 0, false
}

func (v *Verifier) match(ua string) *Crawler {
	if ua == "" {
		return nil
	}
	for i := range v.crawlers {
		for _, tok := range v.crawlers[i].UAs {
			if strings.Contains(ua, tok) {
				return &v.crawlers[i]
			}
		}
	}
	return nil
}

func (c *Crawler) contains(ip netip.Addr) bool {
	for _, p := range c.Prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

var _ ports.Verifier = (*Verifier)(nil)
