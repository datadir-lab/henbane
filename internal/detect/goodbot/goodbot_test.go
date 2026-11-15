package goodbot

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/datadir-lab/henbane/internal/ports"
)

var _ ports.Verifier = (*Verifier)(nil)

type fakeResolver struct {
	ptr  map[string][]string // ip -> hostnames
	host map[string][]string // hostname -> ips
}

func (f fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if h, ok := f.ptr[addr]; ok {
		return h, nil
	}
	return nil, &net.DNSError{IsNotFound: true}
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := f.host[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{IsNotFound: true}
}

type view struct {
	ip netip.Addr
	ua string
}

func (v view) IP() netip.Addr       { return v.ip }
func (v view) UserAgent() string    { return v.ua }
func (v view) Method() string       { return "GET" }
func (v view) Path() string         { return "/" }
func (v view) Header(string) string { return "" }

func newV(fr resolver, blockSpoof bool) *Verifier {
	v := New(Defaults(), ports.TierBlocked, blockSpoof)
	v.res = fr
	return v
}

const googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

func TestVerifiedGooglebotAllowed(t *testing.T) {
	ip := netip.MustParseAddr("66.249.66.1")
	fr := fakeResolver{
		ptr:  map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		host: map[string][]string{"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}},
	}
	v := newV(fr, true)
	v.resolve(ip) // synchronously populate the cache
	sig, tier, ok := v.Verify(view{ip: ip, ua: googlebotUA})
	if !ok || tier != ports.TierPass {
		t.Fatalf("verified Googlebot = %q, %v, %v; want allow (pass)", sig, tier, ok)
	}
	if sig != "good_bot:googlebot" {
		t.Errorf("signal = %q", sig)
	}
}

func TestSpoofedGooglebot(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.9")
	fr := fakeResolver{
		ptr:  map[string][]string{"203.0.113.9": {"evil.example.com."}},
		host: map[string][]string{"evil.example.com": {"203.0.113.9"}},
	}
	v := newV(fr, true)
	v.resolve(ip)
	if _, tier, ok := v.Verify(view{ip: ip, ua: "Googlebot/2.1"}); !ok || tier != ports.TierBlocked {
		t.Errorf("spoofed Googlebot = %v, %v; want blocked", tier, ok)
	}
	// With spoof-blocking off, a spoofer gets no opinion (only verified bots act).
	off := newV(fr, false)
	off.resolve(ip)
	if _, _, ok := off.Verify(view{ip: ip, ua: "Googlebot/2.1"}); ok {
		t.Error("spoofer with blockSpoof off must be no-opinion")
	}
}

func TestForwardConfirmMismatchIsSpoofed(t *testing.T) {
	ip := netip.MustParseAddr("66.249.66.1")
	// PTR claims googlebot.com, but it forward-resolves to a different IP.
	fr := fakeResolver{
		ptr:  map[string][]string{"66.249.66.1": {"fake.googlebot.com."}},
		host: map[string][]string{"fake.googlebot.com": {"10.0.0.1"}},
	}
	v := newV(fr, true)
	v.resolve(ip)
	if _, tier, ok := v.Verify(view{ip: ip, ua: "Googlebot"}); !ok || tier != ports.TierBlocked {
		t.Errorf("forward-confirm mismatch must be spoofed: %v, %v", tier, ok)
	}
}

func TestNonCrawlerNoOpinion(t *testing.T) {
	v := newV(fakeResolver{}, true)
	if _, _, ok := v.Verify(view{ip: netip.MustParseAddr("1.2.3.4"), ua: "Mozilla/5.0"}); ok {
		t.Error("a non-crawler User-Agent must get no opinion")
	}
}

func TestNoOpinionUntilResolved(t *testing.T) {
	v := newV(fakeResolver{ptr: map[string][]string{}}, true)
	// Cache miss on the first request → no opinion (lookup happens in the background).
	if _, _, ok := v.Verify(view{ip: netip.MustParseAddr("66.249.66.1"), ua: "Googlebot"}); ok {
		t.Error("before resolution the verifier must give no opinion")
	}
}

func TestMatchesDomainRejectsLookalike(t *testing.T) {
	if matchesDomain("evil-googlebot.com", []string{".googlebot.com"}) {
		t.Error("evil-googlebot.com must not match .googlebot.com")
	}
	if !matchesDomain("crawl.googlebot.com", []string{".googlebot.com"}) {
		t.Error("crawl.googlebot.com must match .googlebot.com")
	}
}
