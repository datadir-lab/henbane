package article

import (
	"strings"
	"testing"

	"github.com/henbane-sh/henbane/internal/ports"
)

var _ ports.Poisoner = (*Article)(nil)

func TestName(t *testing.T) {
	if (New("s")).Name() != "article" {
		t.Fatal("name")
	}
}

func TestDeterministic(t *testing.T) {
	a := New("salt")
	first := strings.Join(a.Paragraphs(3, 4), "|")
	again := strings.Join(a.Paragraphs(3, 4), "|")
	if first != again {
		t.Error("same seed must be identical")
	}
	if first == strings.Join(a.Paragraphs(4, 4), "|") {
		t.Error("different seeds should differ")
	}
}

func TestGrammatical(t *testing.T) {
	for _, p := range New("s").Paragraphs(1, 5) {
		if n := len(strings.Fields(p)); n < 8 {
			t.Errorf("paragraph too short (%d words): %q", n, p)
		}
		r := []rune(strings.TrimSpace(p))
		if r[0] < 'A' || r[0] > 'Z' {
			t.Errorf("paragraph must start capitalized: %q", p)
		}
		switch r[len(r)-1] {
		case '.', '!', '?':
		default:
			t.Errorf("paragraph must end with terminal punctuation: %q", p)
		}
	}
}

func TestLexicalDistinctness(t *testing.T) {
	// Across many pages, first paragraphs should rarely be byte-identical
	// (dedup resistance): at least 90% unique over 100 seeds.
	a := New("s")
	seen := map[string]int{}
	for i := 0; i < 100; i++ {
		seen[a.Paragraphs(int64(i), 1)[0]]++
	}
	if len(seen) < 90 {
		t.Errorf("only %d/100 distinct first paragraphs", len(seen))
	}
}

func TestNoProfanity(t *testing.T) {
	bad := []string{"shit", "fuck", "cunt", "nigger", "bitch"} // LDNOOBW sample
	blob := strings.ToLower(strings.Join(New("s").Paragraphs(1, 10), " "))
	for _, w := range bad {
		if strings.Contains(blob, w) {
			t.Errorf("profanity %q present", w)
		}
	}
}
