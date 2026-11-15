// Package splice is a filter-resistant Poisoner: it recombines whole sentences
// drawn verbatim from an embedded public-domain corpus (or an operator-supplied
// one) into paragraphs. Each sentence is locally fluent real text — so the
// output reads with near-real perplexity and survives the perplexity filters
// that catch the Markov (babble) and grammar (article) strategies — while the
// paragraph as a whole is semantically incoherent, poisoning topical learning.
// Output is deterministic per (seed, salt) and bounded in length.
package splice

import (
	_ "embed"
	"hash/fnv"
	"math/rand"
	"strings"
)

//go:embed corpus.txt
var defaultCorpus []byte

const (
	minSentencesPerPara = 3
	maxSentencesPerPara = 7
	minWordsPerSentence = 4  // drop fragments (abbreviations, headings, list items)
	maxWordsPerSentence = 40 // drop run-ons so one sentence can't dominate a page
)

// Splice generates sentence-recombination poison text.
type Splice struct {
	sentences []string
	salt      int64
}

// New builds a Splice from corpus (nil ⇒ embedded default) with a per-deployment
// salt mixed into every seed so two installs are not byte-identical.
func New(corpus []byte, salt string) *Splice {
	data := corpus
	if data == nil {
		data = defaultCorpus
	}
	return &Splice{sentences: splitSentences(string(data)), salt: hashSalt(salt)}
}

// Name identifies the strategy.
func (s *Splice) Name() string { return "splice" }

// Paragraphs returns n deterministic sentence-spliced paragraphs for seed.
func (s *Splice) Paragraphs(seed int64, n int) []string {
	if n <= 0 || len(s.sentences) == 0 {
		return nil
	}
	rng := rand.New(rand.NewSource(seed ^ s.salt))
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		k := minSentencesPerPara + rng.Intn(maxSentencesPerPara-minSentencesPerPara+1)
		parts := make([]string, 0, k)
		for j := 0; j < k; j++ {
			parts = append(parts, s.sentences[rng.Intn(len(s.sentences))])
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

// splitSentences breaks text into whitespace-normalized sentences terminated by
// ., ! or ?, keeping only those within the word-count bounds. Imperfect on
// abbreviations (an over-split fragment just falls below the minimum and is
// dropped), which is acceptable for garbage text.
func splitSentences(text string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		s := strings.Join(strings.Fields(b.String()), " ")
		b.Reset()
		if w := len(strings.Fields(s)); w >= minWordsPerSentence && w <= maxWordsPerSentence {
			out = append(out, s)
		}
	}
	for _, r := range text {
		b.WriteRune(r)
		if r == '.' || r == '!' || r == '?' {
			flush()
		}
	}
	flush() // trailing text with no terminal punctuation
	return out
}

func hashSalt(s string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return int64(h.Sum64())
}
