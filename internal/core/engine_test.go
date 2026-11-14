package core

import (
	"context"
	"net/netip"
	"testing"

	"github.com/henbane-sh/henbane/internal/ports"
)

type fakeView struct{}

func (fakeView) IP() netip.Addr       { return netip.Addr{} }
func (fakeView) UserAgent() string    { return "" }
func (fakeView) Method() string       { return "GET" }
func (fakeView) Path() string         { return "/" }
func (fakeView) Header(string) string { return "" }

type fakeDet struct {
	res   ports.Result
	fired bool
}

func (fakeDet) Name() string                                     { return "fake" }
func (d fakeDet) Inspect(ports.RequestView) (ports.Result, bool) { return d.res, d.fired }

func TestDecideAllowsWithNoDetectors(t *testing.T) {
	v, events := NewEngine().Decide(context.Background(), fakeView{})
	if v.Action != ports.ActionAllow || v.Tier != ports.TierPass {
		t.Errorf("verdict = %+v, want allow/pass", v)
	}
	if len(events) != 1 || events[0].Action != ports.ActionAllow {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Time.IsZero() {
		t.Error("event time must be set")
	}
}

func TestDecideTakesHighestTierAndCollectsSignals(t *testing.T) {
	e := NewEngine(
		fakeDet{res: ports.Result{Signal: "a", Tier: ports.TierConfirmed}, fired: true},
		fakeDet{res: ports.Result{Signal: "b", Tier: ports.TierBlocked}, fired: true},
		fakeDet{fired: false},
	)
	v, _ := e.Decide(context.Background(), fakeView{})
	if v.Tier != ports.TierBlocked || v.Action != ports.ActionBlock {
		t.Errorf("verdict = %+v, want blocked/block", v)
	}
	if len(v.Reasons) != 2 || v.Reasons[0] != "a" || v.Reasons[1] != "b" {
		t.Errorf("reasons = %v, want [a b]", v.Reasons)
	}
}

func TestDecideAllowsWhenNoneFire(t *testing.T) {
	v, _ := NewEngine(fakeDet{fired: false}).Decide(context.Background(), fakeView{})
	if v.Action != ports.ActionAllow {
		t.Errorf("action = %v, want allow", v.Action)
	}
}

func TestDecideKeepsHighestTierRegardlessOfOrder(t *testing.T) {
	// Higher tier fires FIRST, lower SECOND: the max-accumulator must not
	// downgrade to the later, lower tier.
	e := NewEngine(
		fakeDet{res: ports.Result{Signal: "hi", Tier: ports.TierBlocked}, fired: true},
		fakeDet{res: ports.Result{Signal: "lo", Tier: ports.TierConfirmed}, fired: true},
	)
	v, _ := e.Decide(context.Background(), fakeView{})
	if v.Tier != ports.TierBlocked {
		t.Errorf("tier = %v, want blocked (descending order must not downgrade)", v.Tier)
	}
}
