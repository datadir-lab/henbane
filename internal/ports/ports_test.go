package ports

import "testing"

func TestActionString(t *testing.T) {
	cases := map[Action]string{
		ActionAllow:     "allow",
		ActionChallenge: "challenge",
		ActionTarpit:    "tarpit",
		ActionPoison:    "poison",
		ActionBlock:     "block",
	}
	for a, want := range cases {
		if got := a.String(); got != want {
			t.Errorf("Action(%d).String() = %q, want %q", a, got, want)
		}
	}
}

func TestTierString(t *testing.T) {
	cases := map[Tier]string{
		TierPass:      "pass",
		TierSuspect:   "suspect",
		TierConfirmed: "confirmed",
		TierBlocked:   "blocked",
	}
	for tr, want := range cases {
		if got := tr.String(); got != want {
			t.Errorf("Tier(%d).String() = %q, want %q", tr, got, want)
		}
	}
}

func TestDetectorInterfaceShape(t *testing.T) {
	// Compile-time: a minimal detector satisfies the interface and Result holds
	// a signal + tier.
	var d Detector = fakeDet{}
	res, ok := d.Inspect(nil)
	if ok || res.Signal != "" || res.Tier != TierPass {
		t.Errorf("zero detector = %+v, %v", res, ok)
	}
	if d.Name() != "fake" {
		t.Errorf("name = %q", d.Name())
	}
}

type fakeDet struct{}

func (fakeDet) Name() string                       { return "fake" }
func (fakeDet) Inspect(RequestView) (Result, bool) { return Result{}, false }
