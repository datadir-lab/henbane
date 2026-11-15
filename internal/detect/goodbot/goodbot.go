// Package goodbot verifies well-behaved search crawlers by forward-confirmed
// reverse DNS (FCrDNS): a client whose User-Agent claims to be Googlebot/Bingbot
// is the real thing only if its IP reverse-resolves to the crawler's domain and
// that hostname forward-resolves back to the same IP. A verified crawler is
// allowed (so an operator does not poison the search crawlers they want); a
// client that claims a crawler but fails verification is a spoofer, optionally
// blocked. Lookups run in the background — never on the request path.
package goodbot

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/datadir-lab/henbane/internal/ports"
)

// Crawler is a recognized good bot: a User-Agent substring and the reverse-DNS
// domain suffixes a genuine instance resolves to.
type Crawler struct {
	Name    string
	UA      string   // matched as a lowercased substring of the User-Agent
	Domains []string // forward-confirmed hostname must end with one, e.g. ".googlebot.com"
}

// Defaults returns the built-in reverse-DNS-verifiable crawlers.
func Defaults() []Crawler {
	return []Crawler{
		{Name: "googlebot", UA: "googlebot", Domains: []string{".googlebot.com", ".google.com"}},
		{Name: "bingbot", UA: "bingbot", Domains: []string{".search.msn.com"}},
		{Name: "applebot", UA: "applebot", Domains: []string{".applebot.apple.com"}},
	}
}

// resolver is the DNS surface, injectable for tests.
type resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type entry struct {
	host   string // forward-confirmed PTR hostname, or "" if none confirmed
	expiry time.Time
}

// Verifier implements ports.Verifier via FCrDNS.
type Verifier struct {
	crawlers   []Crawler
	spoofTier  ports.Tier
	blockSpoof bool
	res        resolver
	now        func() time.Time
	ttl        time.Duration
	timeout    time.Duration
	max        int
	sem        chan struct{}

	mu      sync.Mutex
	cache   map[netip.Addr]entry
	pending map[netip.Addr]bool
}

// New returns a Verifier for the given crawlers. If blockSpoof is true, a client
// whose User-Agent claims a crawler it cannot be verified as is forced to
// spoofTier; otherwise such a client gets no opinion (only verified good bots are
// acted on).
func New(crawlers []Crawler, spoofTier ports.Tier, blockSpoof bool) *Verifier {
	cs := make([]Crawler, len(crawlers))
	for i, c := range crawlers {
		c.UA = strings.ToLower(c.UA)
		cs[i] = c
	}
	return &Verifier{
		crawlers:   cs,
		spoofTier:  spoofTier,
		blockSpoof: blockSpoof,
		res:        net.DefaultResolver,
		now:        time.Now,
		ttl:        time.Hour,
		timeout:    3 * time.Second,
		max:        100000,
		sem:        make(chan struct{}, 16),
		cache:      map[netip.Addr]entry{},
		pending:    map[netip.Addr]bool{},
	}
}

// Name identifies the verifier.
func (v *Verifier) Name() string { return "good_bot" }

// Verify allows a reverse-DNS-verified crawler and (when configured) blocks a
// spoofer. It never blocks the request path: an unresolved IP gets no opinion.
func (v *Verifier) Verify(r ports.RequestView) (ports.Signal, ports.Tier, bool) {
	c := v.match(lowerUA(r.UserAgent()))
	if c == nil {
		return "", 0, false // not claiming to be a recognized crawler
	}
	ip := r.IP().Unmap()
	if !ip.IsValid() {
		return "", 0, false
	}
	host, resolved := v.lookup(ip)
	if !resolved {
		return "", 0, false // not resolved yet — no opinion this request
	}
	if host != "" && matchesDomain(host, c.Domains) {
		return ports.Signal("good_bot:" + c.Name), ports.TierPass, true
	}
	if v.blockSpoof {
		return ports.Signal("spoofed:" + c.Name), v.spoofTier, true
	}
	return "", 0, false
}

// lookup returns the cached forward-confirmed hostname for ip; on a miss it
// triggers a bounded background resolution and reports resolved=false.
func (v *Verifier) lookup(ip netip.Addr) (string, bool) {
	v.mu.Lock()
	if e, ok := v.cache[ip]; ok && v.now().Before(e.expiry) {
		v.mu.Unlock()
		return e.host, true
	}
	if v.pending[ip] {
		v.mu.Unlock()
		return "", false
	}
	v.pending[ip] = true
	v.mu.Unlock()

	select {
	case v.sem <- struct{}{}:
		go func() { defer func() { <-v.sem }(); v.resolve(ip) }()
	default:
		// At capacity: clear the pending flag so a later request retries.
		v.mu.Lock()
		delete(v.pending, ip)
		v.mu.Unlock()
	}
	return "", false
}

// resolve performs FCrDNS for ip and caches the result.
func (v *Verifier) resolve(ip netip.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()
	host, ok := v.fcrdns(ctx, ip)
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.pending, ip)
	if !ok {
		return // transient resolver failure: do not cache, retry next time
	}
	if len(v.cache) >= v.max {
		v.evictLocked()
	}
	v.cache[ip] = entry{host: host, expiry: v.now().Add(v.ttl)}
}

// fcrdns returns the forward-confirmed PTR hostname for ip. ok is false only on a
// transient resolver error (so the caller does not cache it); a successful lookup
// that confirms nothing returns ("", true).
func (v *Verifier) fcrdns(ctx context.Context, ip netip.Addr) (string, bool) {
	names, err := v.res.LookupAddr(ctx, ip.String())
	if err != nil {
		if dnsStable(err) {
			return "", true // no PTR record — a definitive non-confirmation
		}
		return "", false
	}
	for i, name := range names {
		if i >= maxPTRNames {
			break // bound the forward-lookup fan-out an attacker-controlled PTR set can drive
		}
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		addrs, err := v.res.LookupHost(ctx, name)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if pa, err := netip.ParseAddr(a); err == nil && pa.Unmap() == ip {
				return name, true
			}
		}
	}
	return "", true // reverse records existed but none forward-confirmed
}

func dnsStable(err error) bool {
	var de *net.DNSError
	if errors.As(err, &de) {
		return de.IsNotFound
	}
	return false
}

// maxUABytes caps the User-Agent considered for matching (real crawler UAs are
// far shorter), so an attacker-sized UA can't force a large allocation on the
// per-request verifier path. maxPTRNames bounds the forward-lookup fan-out.
const (
	maxUABytes  = 512
	maxPTRNames = 8
)

func lowerUA(ua string) string {
	if len(ua) > maxUABytes {
		ua = ua[:maxUABytes]
	}
	return strings.ToLower(ua)
}

func (v *Verifier) match(ua string) *Crawler {
	if ua == "" {
		return nil
	}
	for i := range v.crawlers {
		if strings.Contains(ua, v.crawlers[i].UA) {
			return &v.crawlers[i]
		}
	}
	return nil
}

// matchesDomain reports whether host is under one of the allowed domain suffixes.
// The leading dot is required so "evil-googlebot.com" does not match ".googlebot.com".
func matchesDomain(host string, domains []string) bool {
	for _, d := range domains {
		if strings.HasSuffix(host, d) || host == strings.TrimPrefix(d, ".") {
			return true
		}
	}
	return false
}

func (v *Verifier) evictLocked() {
	now := v.now()
	for k, e := range v.cache {
		if !now.Before(e.expiry) {
			delete(v.cache, k)
		}
	}
	if len(v.cache) >= v.max {
		for k := range v.cache {
			delete(v.cache, k)
			break
		}
	}
}
