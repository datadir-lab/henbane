package splice

import (
	"strings"
	"testing"

	"github.com/datadir-lab/henbane/internal/ports"
)

var _ ports.Poisoner = (*Splice)(nil)

const sample = "The lighthouse keeper polished the brass lamp each evening. " +
	"Migrating geese crossed the pale autumn sky in ragged lines. " +
	"She folded the letter twice and tucked it beneath the clock. " +
	"Rain drummed against the tin roof until well past midnight. " +
	"The old clockmaker smiled at the child standing in the doorway."

func TestName(t *testing.T) {
	if got := New([]byte(sample), "s").Name(); got != "splice" {
		t.Errorf("Name() = %q", got)
	}
}

func TestDeterministicPerSeed(t *testing.T) {
	s := New([]byte(sample), "salt")
	a1 := s.Paragraphs(99, 3)
	a2 := s.Paragraphs(99, 3)
	if strings.Join(a1, "|") != strings.Join(a2, "|") {
		t.Error("same seed must yield identical paragraphs")
	}
	if strings.Join(s.Paragraphs(100, 3), "|") == strings.Join(a1, "|") {
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
		if w := len(strings.Fields(p)); w == 0 || w > 300 {
			t.Errorf("paragraph word count %d out of (0,300]", w)
		}
	}
}

// The defining property of splice: every sentence it emits is verbatim from the
// corpus (locally real text), only the ORDER is scrambled (globally incoherent).
func TestSplicesVerbatimCorpusSentences(t *testing.T) {
	s := New([]byte(sample), "s")
	pool := map[string]bool{}
	for _, sent := range s.sentences {
		pool[sent] = true
	}
	if len(pool) == 0 {
		t.Fatal("corpus produced no sentences")
	}
	for _, para := range s.Paragraphs(5, 3) {
		for _, sent := range splitSentences(para) {
			if !pool[sent] {
				t.Errorf("emitted sentence %q is not verbatim from the corpus pool", sent)
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

func TestNoUsableSentencesReturnsNil(t *testing.T) {
	// Fragments below the minimum sentence length are dropped, leaving an empty
	// pool; Paragraphs must return nil rather than panic or loop.
	if got := New([]byte("hi. no. ok."), "s").Paragraphs(1, 3); got != nil {
		t.Errorf("corpus with no usable sentences must yield nil, got %v", got)
	}
}

func TestEmptyCorpusNoPanic(t *testing.T) {
	if got := New([]byte(""), "s").Paragraphs(1, 2); got != nil {
		t.Errorf("empty corpus must yield nil, got %v", got)
	}
}

func TestNonPositiveCountReturnsNil(t *testing.T) {
	s := New([]byte(sample), "s")
	if got := s.Paragraphs(1, 0); got != nil {
		t.Errorf("n<=0 must yield nil, got %v", got)
	}
}
