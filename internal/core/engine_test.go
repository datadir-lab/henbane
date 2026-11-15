package core

import (
	"context"
	"net/netip"
	"testing"

	"github.com/datadir-lab/henbane/internal/ports"
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

func TestDecideConfirmedTarpits(t *testing.T) {
	e := NewEngine(fakeDet{res: ports.Result{Signal: "honeypot", Tier: ports.TierConfirmed}, fired: true})
	v, _ := e.Decide(context.Background(), fakeView{})
	if v.Action != ports.ActionTarpit || v.Tier != ports.TierConfirmed {
		t.Errorf("verdict = %+v, want tarpit/confirmed", v)
	}
}

func TestDecideSuspectChallenges(t *testing.T) {
	e := NewEngine(fakeDet{res: ports.Result{Signal: "signal", Tier: ports.TierSuspect}, fired: true})
	v, _ := e.Decide(context.Background(), fakeView{})
	if v.Action != ports.ActionChallenge || v.Tier != ports.TierSuspect {
		t.Errorf("verdict = %+v, want challenge/suspect", v)
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

type fpView struct{ fakeView }

func (fpView) TLSFingerprint() string { return "abcdef0123456789" }

func TestDecidePopulatesTLSFingerprint(t *testing.T) {
	_, events := NewEngine().Decide(context.Background(), fpView{})
	if events[0].TLSFingerprint != "abcdef0123456789" {
		t.Errorf("event TLSFingerprint = %q, want it taken from the RequestView", events[0].TLSFingerprint)
	}
	// A RequestView without the capability leaves it empty.
	_, ev2 := NewEngine().Decide(context.Background(), fakeView{})
	if ev2[0].TLSFingerprint != "" {
		t.Errorf("non-fingerprinter view must leave TLSFingerprint empty, got %q", ev2[0].TLSFingerprint)
	}
}
