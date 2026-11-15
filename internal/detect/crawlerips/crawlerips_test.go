package crawlerips

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/datadir-lab/henbane/internal/ports"
)

var _ ports.Verifier = (*Verifier)(nil)

type view struct {
	ip netip.Addr
	ua string
}

func (v view) IP() netip.Addr       { return v.ip }
func (v view) UserAgent() string    { return v.ua }
func (v view) Method() string       { return "GET" }
func (v view) Path() string         { return "/" }
func (v view) Header(string) string { return "" }

// testCrawlers is a fixed synthetic set so the verifier logic does not depend on
// the (drifting) bundled snapshot.
func testCrawlers() []Crawler {
	return []Crawler{
		{Name: "gptbot", UAs: []string{"gptbot"}, Prefixes: []netip.Prefix{
			netip.MustParsePrefix("20.171.0.0/16"),
			netip.MustParsePrefix("2600:1900::/28"),
		}},
		{Name: "anthropic", UAs: []string{"claudebot", "claude-user"}, Prefixes: []netip.Prefix{
			netip.MustParsePrefix("160.79.104.0/23"),
		}},
	}
}

const gptbotUA = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot"

func TestVerifiedCrawlerAllowed(t *testing.T) {
	v := New(testCrawlers(), ports.TierBlocked, true)
	sig, tier, ok := v.Verify(view{ip: netip.MustParseAddr("20.171.206.5"), ua: gptbotUA})
	if !ok || tier != ports.TierPass {
		t.Fatalf("verified GPTBot = %q, %v, %v; want allow (pass)", sig, tier, ok)
	}
	if sig != "ai_crawler:gptbot" {
		t.Errorf("signal = %q, want ai_crawler:gptbot", sig)
	}
}

func TestVerifiedCrawlerIPv6(t *testing.T) {
	v := New(testCrawlers(), ports.TierBlocked, true)
	if _, tier, ok := v.Verify(view{ip: netip.MustParseAddr("2600:1900::abcd"), ua: gptbotUA}); !ok || tier != ports.TierPass {
		t.Errorf("verified GPTBot over IPv6 = %v, %v; want allow", tier, ok)
	}
}

func TestSpoofedCrawlerBlocked(t *testing.T) {
	v := New(testCrawlers(), ports.TierBlocked, true)
	// Claims GPTBot but from an IP outside GPTBot's published ranges.
	sig, tier, ok := v.Verify(view{ip: netip.MustParseAddr("203.0.113.7"), ua: gptbotUA})
	if !ok || tier != ports.TierBlocked {
		t.Fatalf("spoofed GPTBot = %q, %v, %v; want blocked", sig, tier, ok)
	}
	if sig != "spoofed:gptbot" {
		t.Errorf("signal = %q, want spoofed:gptbot", sig)
	}
}

func TestSpoofWithBlockOffIsNoOpinion(t *testing.T) {
	v := New(testCrawlers(), ports.TierBlocked, false)
	if _, _, ok := v.Verify(view{ip: netip.MustParseAddr("203.0.113.7"), ua: gptbotUA}); ok {
		t.Error("a spoofer with blockSpoof off must get no opinion (detectors decide)")
	}
}

func TestMultiTokenCrawlerMatches(t *testing.T) {
	v := New(testCrawlers(), ports.TierBlocked, true)
	// "claude-user" is a second UA token sharing Anthropic's one IP list.
	ua := "Mozilla/5.0 (compatible; Claude-User/1.0; +https://anthropic.com)"
	sig, tier, ok := v.Verify(view{ip: netip.MustParseAddr("160.79.104.10"), ua: ua})
	if !ok || tier != ports.TierPass || sig != "ai_crawler:anthropic" {
		t.Errorf("verified Claude-User = %q, %v, %v; want allow ai_crawler:anthropic", sig, tier, ok)
	}
}

func TestNonCrawlerNoOpinion(t *testing.T) {
	v := New(testCrawlers(), ports.TierBlocked, true)
	if _, _, ok := v.Verify(view{ip: netip.MustParseAddr("20.171.206.5"), ua: "Mozilla/5.0 (Windows NT 10.0)"}); ok {
		t.Error("a non-crawler User-Agent must get no opinion")
	}
}

func TestEmptyUANoOpinion(t *testing.T) {
	v := New(testCrawlers(), ports.TierBlocked, true)
	if _, _, ok := v.Verify(view{ip: netip.MustParseAddr("20.171.206.5"), ua: ""}); ok {
		t.Error("an empty User-Agent must get no opinion")
	}
}

// TestBundledDefaults checks the generated snapshot is structurally sound without
// asserting specific (drifting) addresses.
func TestBundledDefaults(t *testing.T) {
	d := Defaults()
	if len(d) == 0 {
		t.Fatal("Defaults() is empty — did data_gen.go fail to generate?")
	}
	names := map[string]bool{}
	total := 0
	for _, c := range d {
		names[c.Name] = true
		if len(c.UAs) == 0 {
			t.Errorf("crawler %q has no UA tokens", c.Name)
		}
		if len(c.Prefixes) == 0 {
			t.Errorf("crawler %q has no prefixes", c.Name)
		}
		for _, p := range c.Prefixes {
			if p != p.Masked() {
				t.Errorf("crawler %q prefix %v is not in masked form", c.Name, p)
			}
		}
		total += len(c.Prefixes)
	}
	for _, want := range []string{"gptbot", "anthropic", "perplexitybot"} {
		if !names[want] {
			t.Errorf("bundled defaults missing expected crawler %q", want)
		}
	}
	if total < 20 {
		t.Errorf("only %d bundled prefixes; expected the feeds to carry many more", total)
	}
}

func TestUALengthCapped(t *testing.T) {
	v := New(Defaults(), ports.TierBlocked, true)
	ua := strings.Repeat("x", 600) + "gptbot"
	if _, _, ok := v.Verify(view{ip: netip.MustParseAddr("20.171.206.5"), ua: ua}); ok {
		t.Error("a crawler token past the 512-byte UA cap must not be matched")
	}
}
