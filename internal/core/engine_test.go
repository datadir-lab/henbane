package core

import (
	"context"
	"net/netip"
	"testing"

	"github.com/henbane-sh/henbane/internal/ports"
)

type fakeView struct {
	ip   netip.Addr
	ua   string
	path string
}

func (v fakeView) IP() netip.Addr            { return v.ip }
func (v fakeView) UserAgent() string         { return v.ua }
func (v fakeView) Method() string            { return "GET" }
func (v fakeView) Path() string              { return v.path }
func (v fakeView) Header(name string) string { return "" }

func TestDecideAllowsByDefault(t *testing.T) {
	e := NewEngine(Policy{})
	v := fakeView{ip: netip.MustParseAddr("203.0.113.5"), ua: "curl/8", path: "/x"}

	verdict, events := e.Decide(context.Background(), v)

	if verdict.Action != ports.ActionAllow || verdict.Tier != ports.TierPass {
		t.Errorf("verdict = %+v, want allow/pass", verdict)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Action != ports.ActionAllow || ev.Tier != ports.TierPass || ev.Path != "/x" || ev.UserAgent != "curl/8" {
		t.Errorf("event = %+v, want allow/pass /x curl/8", ev)
	}
	if ev.IP != v.ip || ev.Time.IsZero() {
		t.Errorf("event IP/Time = %v/%v", ev.IP, ev.Time)
	}
}

func TestDecideBlocksDenyCIDR(t *testing.T) {
	e := NewEngine(Policy{DenyCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})
	verdict, events := e.Decide(context.Background(),
		fakeView{ip: netip.MustParseAddr("203.0.113.9"), ua: "curl/8", path: "/p"})

	if verdict.Action != ports.ActionBlock || verdict.Tier != ports.TierBlocked {
		t.Errorf("verdict = %+v, want block/blocked", verdict)
	}
	if len(events) != 1 || events[0].Action != ports.ActionBlock {
		t.Fatalf("events = %+v", events)
	}
	if len(verdict.Reasons) != 1 || verdict.Reasons[0] != ports.Signal("denylist_ip") {
		t.Errorf("reasons = %v, want [denylist_ip]", verdict.Reasons)
	}
}

func TestDecideBlocksDenyUACaseInsensitive(t *testing.T) {
	e := NewEngine(Policy{DenyUserAgents: []string{"GPTBot"}})
	verdict, _ := e.Decide(context.Background(),
		fakeView{ip: netip.MustParseAddr("198.51.100.1"), ua: "Mozilla gptBOT/1.1", path: "/p"})

	if verdict.Action != ports.ActionBlock {
		t.Errorf("action = %v, want block (case-insensitive UA match)", verdict.Action)
	}
	if len(verdict.Reasons) != 1 || verdict.Reasons[0] != ports.Signal("denylist_ua") {
		t.Errorf("reasons = %v, want [denylist_ua]", verdict.Reasons)
	}
}

func TestDecideAllowsNonDenied(t *testing.T) {
	e := NewEngine(Policy{
		DenyCIDRs:      []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		DenyUserAgents: []string{"GPTBot"},
	})
	verdict, _ := e.Decide(context.Background(),
		fakeView{ip: netip.MustParseAddr("198.51.100.1"), ua: "Mozilla/5.0", path: "/p"})
	if verdict.Action != ports.ActionAllow {
		t.Errorf("action = %v, want allow", verdict.Action)
	}
}
