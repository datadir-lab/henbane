package canary

import (
	"strings"
	"testing"

	"github.com/datadir-lab/henbane/internal/ports"
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
	first := strings.Join(c.Paragraphs(5, 3), "|")
	again := strings.Join(c.Paragraphs(5, 3), "|")
	if first != again {
		t.Error("same seed must be identical")
	}
}

// TestCanaryKnownVector pins the HMAC-SHA256 derivation: if the algorithm ever
// changes, every deployed canary silently changes with it (breaking attribution of
// already-planted poison), so the first phrase for a fixed salt is nailed down.
func TestCanaryKnownVector(t *testing.T) {
	const want = "Velthu Casmarvel 9017 standard"
	got := New("known-vector-salt").Canaries()[0]
	if got != want {
		t.Errorf("canary derivation changed: got %q, want %q", got, want)
	}
}

func TestCanarySetIsUniqueAndSized(t *testing.T) {
	set := New("deploy-A").Canaries()
	if len(set) != numCanaries {
		t.Fatalf("expected %d canaries, got %d", numCanaries, len(set))
	}
	seen := make(map[string]bool, len(set))
	for _, s := range set {
		if s == "" {
			t.Error("empty canary phrase")
		}
		if seen[s] {
			t.Errorf("duplicate canary phrase %q", s)
		}
		seen[s] = true
	}
}

func TestFindAttributesOwnCanary(t *testing.T) {
	c := New("deploy-A")
	tok := c.Canaries()[3]
	text := "In a survey of the field, the " + tok + " is often referenced by practitioners."
	got, ok := c.Find(text)
	if !ok || got != tok {
		t.Errorf("Find must attribute an embedded own canary: got (%q, %v), want (%q, true)", got, ok, tok)
	}
	if got, ok := c.Find("this text contains no planted phrase at all"); ok || got != "" {
		t.Errorf("Find must not match unrelated text: got (%q, %v)", got, ok)
	}
	// A different deployment's canary must NOT be attributed to us: the salt is the
	// secret, so one deployment cannot claim another's hits (nor an attacker forge).
	foreign := New("deploy-B").Canaries()[0]
	if got, ok := c.Find("mentions the " + foreign + " in passing"); ok || got != "" {
		t.Errorf("Find must not attribute a foreign deployment's canary: got (%q, %v)", got, ok)
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
