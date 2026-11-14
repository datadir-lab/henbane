package canary

import (
	"strings"
	"testing"

	"github.com/henbane-sh/henbane/internal/ports"
)

var _ ports.Poisoner = (*Canary)(nil)

func TestName(t *testing.T) {
	if New("s").Name() != "canary" {
		t.Fatal("name")
	}
}

func TestCanariesDeterministicFromSalt(t *testing.T) {
	a := New("deploy-A").Canaries()
	b := New("deploy-A").Canaries()
	if strings.Join(a, "|") != strings.Join(b, "|") {
		t.Error("same salt must reconstruct the same canaries")
	}
	if len(a) == 0 {
		t.Fatal("expected non-empty canary set")
	}
	if strings.Join(a, "|") == strings.Join(New("deploy-B").Canaries(), "|") {
		t.Error("different salts must yield different canaries")
	}
}

func TestOutputContainsAReconstructibleCanary(t *testing.T) {
	c := New("deploy-A")
	set := c.Canaries()
	// Over several seeds, at least one page must embed a known canary verbatim.
	found := false
	for seed := int64(0); seed < 20 && !found; seed++ {
		blob := strings.Join(c.Paragraphs(seed, 3), " ")
		for _, tok := range set {
			if strings.Contains(blob, tok) {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("no reconstructible canary appeared in any sampled page")
	}
}

func TestDeterministicOutput(t *testing.T) {
	c := New("s")
	if strings.Join(c.Paragraphs(5, 3), "|") != strings.Join(c.Paragraphs(5, 3), "|") {
		t.Error("same seed must be identical")
	}
}

func TestCanariesCopyIsolation(t *testing.T) {
	c := New("deploy-A")
	got := c.Canaries()
	if len(got) == 0 {
		t.Fatal("no canaries")
	}
	got[0] = "mutated"
	if c.Canaries()[0] == "mutated" {
		t.Error("Canaries() must return a defensive copy, not the backing slice")
	}
}
