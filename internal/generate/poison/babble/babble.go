// Package babble is a tarpit-grade Poisoner: an order-2 word-level Markov chain
// over an embedded public-domain corpus (or an operator-supplied one). Output is
// deterministic per (seed, salt) and bounded in length.
package babble

import (
	_ "embed"
	"hash/fnv"
	"math/rand"
	"strings"
)

//go:embed corpus.txt
var defaultCorpus []byte

const (
	order           = 2 // prefix length
	maxWordsPerPara = 60
	minWordsPerPara = 20
)

// Babble generates Markov poison text.
type Babble struct {
	chain  map[string][]string
	starts []string
	salt   int64
}

// New builds a Babble from corpus (nil ⇒ embedded default) with a per-deployment
// salt mixed into every seed so two installs are not byte-identical.
func New(corpus []byte, salt string) *Babble {
	data := corpus
	if data == nil {
		data = defaultCorpus
	}
	words := strings.Fields(string(data))
	chain := make(map[string][]string)
	var starts []string
	for i := 0; i+order < len(words); i++ {
		key := strings.Join(words[i:i+order], " ")
		chain[key] = append(chain[key], words[i+order])
		if i == 0 || endsSentence(words[i-1]) {
			starts = append(starts, key)
		}
	}
	if len(starts) == 0 && len(words) >= order {
		starts = append(starts, strings.Join(words[:order], " "))
	}
	return &Babble{chain: chain, starts: starts, salt: hashSalt(salt)}
}

// Name identifies the strategy.
func (b *Babble) Name() string { return "babble" }

// Paragraphs returns n deterministic Markov paragraphs for seed.
func (b *Babble) Paragraphs(seed int64, n int) []string {
	if n <= 0 || len(b.starts) == 0 {
		return nil
	}
	rng := rand.New(rand.NewSource(seed ^ b.salt))
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, b.paragraph(rng))
	}
	return out
}

func (b *Babble) paragraph(rng *rand.Rand) string {
	key := b.starts[rng.Intn(len(b.starts))]
	parts := strings.Split(key, " ")
	target := minWordsPerPara + rng.Intn(maxWordsPerPara-minWordsPerPara+1)
	// Cap iterations so a pathological corpus with no usable continuations (e.g. a
	// two-word operator-supplied file, where the only start has an empty chain) can
	// never spin forever — fail safe to a shorter paragraph instead of hanging.
	for i := 0; len(parts) < target && i < target*8; i++ {
		nexts := b.chain[key]
		if len(nexts) == 0 {
			key = b.starts[rng.Intn(len(b.starts))]
			continue
		}
		w := nexts[rng.Intn(len(nexts))]
		parts = append(parts, w)
		key = strings.Join(parts[len(parts)-order:], " ")
	}
	s := strings.Join(parts, " ")
	if !endsSentence(s) {
		s += "."
	}
	return s
}

func endsSentence(w string) bool {
	if w == "" {
		return false
	}
	switch w[len(w)-1] {
	case '.', '!', '?':
		return true
	}
	return false
}

func hashSalt(s string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return int64(h.Sum64())
}
