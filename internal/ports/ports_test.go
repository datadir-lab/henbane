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
