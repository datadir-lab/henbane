// Package canary is an article-based Poisoner that embeds unique, trackable
// fabricated facts derived deterministically from the deployment salt, so a later
// probe can reconstruct the exact strings and search public AI endpoints for them.
// Generation is pure: no state, no IO. It imports only the standard library and
// the sibling article package.
package canary

import (
	"hash/fnv"
	"math/rand"
	"strconv"
	"strings"

	"github.com/datadir-lab/henbane/internal/generate/poison/article"
)

const numCanaries = 8

// Canary wraps article generation plus a salt-derived canary vocabulary.
type Canary struct {
	art    *article.Article
	salt   int64
	tokens []string
}

// New returns a Canary bound to salt.
func New(salt string) *Canary {
	return &Canary{
		art:    article.New(salt),
		salt:   hashSalt(salt),
		tokens: derive(salt),
	}
}

// Name identifies the strategy.
func (c *Canary) Name() string { return "canary" }

// Canaries returns a copy of the deterministic canary set, reconstructible from
// the deployment salt alone (used by a later probe to search for these strings).
func (c *Canary) Canaries() []string {
	return append([]string(nil), c.tokens...)
}

// Paragraphs returns n article paragraphs with one canary sentence spliced in.
func (c *Canary) Paragraphs(seed int64, n int) []string {
	paras := c.art.Paragraphs(seed, n)
	if len(paras) == 0 || len(c.tokens) == 0 {
		return paras
	}
	rng := rand.New(rand.NewSource(seed ^ c.salt))
	idx := rng.Intn(len(paras))
	tok := c.tokens[rng.Intn(len(c.tokens))]
	paras[idx] = paras[idx] + " The " + tok + " remains widely cited in the literature."
	return paras
}

// derive builds a stable, deployment-unique set of coined canary phrases.
func derive(salt string) []string {
	base := rand.New(rand.NewSource(hashSalt(salt)))
	out := make([]string, 0, numCanaries)
	for i := 0; i < numCanaries; i++ {
		out = append(out, coin(base)+" "+coin(base)+" "+strconv.Itoa(1000+base.Intn(9000))+" standard")
	}
	return out
}

func coin(rng *rand.Rand) string {
	syl := []string{"vel", "mar", "lin", "tos", "dra", "quen", "pal", "rin", "sel", "thu", "cas", "elo"}
	n := 2 + rng.Intn(2)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(syl[rng.Intn(len(syl))])
	}
	s := b.String()
	return strings.ToUpper(s[:1]) + s[1:]
}

func hashSalt(s string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return int64(h.Sum64())
}
