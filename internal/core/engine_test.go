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

func TestDecideAllowsEverything(t *testing.T) {
	e := NewEngine()
	v := fakeView{ip: netip.MustParseAddr("203.0.113.5"), ua: "curl/8", path: "/x"}

	verdict, events := e.Decide(context.Background(), v)

	if verdict.Action != ports.ActionAllow {
		t.Errorf("Action = %v, want allow", verdict.Action)
	}
	if verdict.Tier != ports.TierPass {
		t.Errorf("Tier = %v, want pass", verdict.Tier)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Action != ports.ActionAllow || ev.Path != "/x" || ev.UserAgent != "curl/8" {
		t.Errorf("event = %+v, want allow /x curl/8", ev)
	}
	if ev.IP != v.ip {
		t.Errorf("event IP = %v, want %v", ev.IP, v.ip)
	}
	if ev.Time.IsZero() {
		t.Error("event Time must be set")
	}
}
