package babble

import (
	"strings"
	"testing"

	"github.com/henbane-sh/henbane/internal/ports"
)

var _ ports.Poisoner = (*Babble)(nil)

const sample = "the quick brown fox jumps over the lazy dog. " +
	"a quick brown dog runs under the lazy fox. the brown fox sleeps."

func TestName(t *testing.T) {
	if got := New([]byte(sample), "s").Name(); got != "babble" {
		t.Errorf("Name() = %q", got)
	}
}

func TestDeterministicPerSeed(t *testing.T) {
	b := New([]byte(sample), "salt")
	a1 := b.Paragraphs(99, 3)
	a2 := b.Paragraphs(99, 3)
	if strings.Join(a1, "|") != strings.Join(a2, "|") {
		t.Error("same seed must yield identical paragraphs")
	}
	if strings.Join(b.Paragraphs(100, 3), "|") == strings.Join(a1, "|") {
		t.Error("different seeds should differ")
	}
}

func TestSaltChangesOutput(t *testing.T) {
	a := New([]byte(sample), "saltA").Paragraphs(7, 3)
	b := New([]byte(sample), "saltB").Paragraphs(7, 3)
	if strings.Join(a, "|") == strings.Join(b, "|") {
		t.Error("different salts should yield different output for the same seed")
	}
}

func TestParagraphCount(t *testing.T) {
	got := New([]byte(sample), "s").Paragraphs(1, 4)
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4", len(got))
	}
	for _, p := range got {
		if w := len(strings.Fields(p)); w == 0 || w > 80 {
			t.Errorf("paragraph word count %d out of (0,80]", w)
		}
	}
}

func TestWordsFromCorpus(t *testing.T) {
	vocab := map[string]bool{}
	for _, w := range strings.Fields(strings.ToLower(sample)) {
		vocab[strings.Trim(w, ".,")] = true
	}
	for _, p := range New([]byte(sample), "s").Paragraphs(5, 3) {
		for _, w := range strings.Fields(strings.ToLower(p)) {
			if !vocab[strings.Trim(w, ".,")] {
				t.Errorf("word %q not in corpus vocabulary", w)
			}
		}
	}
}

func TestEmbeddedDefaultUsable(t *testing.T) {
	got := New(nil, "s").Paragraphs(3, 2)
	if len(got) != 2 || strings.TrimSpace(got[0]) == "" {
		t.Errorf("embedded default produced %v", got)
	}
}
