// Package canary is an article-based Poisoner that splices unique, trackable
// fabricated phrases into generated pages. Each phrase is coined deterministically
// from the deployment salt with HMAC-SHA256, so the set is stable for a deployment
// yet cryptographically unguessable without the salt: a third party cannot predict,
// forge, or pre-filter a deployment's canaries.
//
// The phrases are attribution markers. Find reports whether a given text (e.g. an
// AI assistant's answer) echoes one of this deployment's canaries, and the
// `henbane canary` CLI lists them and probes a configured AI endpoint for them. A
// hit is strong evidence the text reached and reproduced Henbane's planted content
// — live retrieval and repetition reach — NOT proof the content entered any model's
// training set.
//
// Generation is pure: no state, no IO. It imports only the standard library and the
// sibling article package.
package canary

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash/fnv"
	"math/rand"
	"strconv"
	"strings"

	"github.com/datadir-lab/henbane/internal/generate/poison/article"
)

const numCanaries = 16

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
// the deployment salt alone (used by the `henbane canary` tooling to list and
// search for these strings).
func (c *Canary) Canaries() []string {
	return append([]string(nil), c.tokens...)
}

// Find reports the first canary phrase from this deployment's set that appears in
// text, and whether any did. A match is strong evidence the text echoes poison
// planted by THIS deployment: the phrases are HMAC-derived from the secret salt,
// so a third party cannot forge or predict one. It proves the text reached and
// reproduced Henbane's planted content (retrieval and repetition reach), NOT that
// the content entered any model's training set. This is a membership search over
// our own known phrases, not a secret comparison, so it need not be constant time.
func (c *Canary) Find(text string) (string, bool) {
	for _, tok := range c.tokens {
		if strings.Contains(text, tok) {
			return tok, true
		}
	}
	return "", false
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

// derive builds a stable, deployment-unique, cryptographically-unguessable set of
// coined canary phrases from the salt. Each phrase is driven by HMAC-SHA256(salt,
// index): without the salt the phrases cannot be predicted or forged, and no two
// salts share a phrase set.
func derive(salt string) []string {
	out := make([]string, 0, numCanaries)
	for i := 0; i < numCanaries; i++ {
		out = append(out, coinPhrase(salt, i))
	}
	return out
}

// coinPhrase deterministically coins the i-th canary phrase from a keyed hash of
// the salt. The 32 HMAC bytes are a small entropy budget the picker draws from;
// the phrase reads like a plausible fabricated standard (e.g. "Velmar Quenpal 4521
// standard") so an AI is tempted to repeat it, yet is unguessable without the salt.
func coinPhrase(salt string, i int) string {
	mac := hmac.New(sha256.New, []byte(salt))
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], uint32(i))
	_, _ = mac.Write(idx[:])
	p := &picker{b: mac.Sum(nil)}
	hi, lo := p.next(), p.next()
	num := 1000 + (int(hi)<<8|int(lo))%9000
	return coin(p) + " " + coin(p) + " " + strconv.Itoa(num) + " standard"
}

// picker yields a deterministic byte stream from a fixed seed buffer, wrapping if
// a phrase ever needs more bytes than the buffer holds (it does not today).
type picker struct {
	b []byte
	i int
}

func (p *picker) next() byte {
	v := p.b[p.i%len(p.b)]
	p.i++
	return v
}

// coin builds a 2–3 syllable capitalised nonsense word from the picker stream.
func coin(p *picker) string {
	syl := []string{"vel", "mar", "lin", "tos", "dra", "quen", "pal", "rin", "sel", "thu", "cas", "elo"}
	n := 2 + int(p.next())%2
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(syl[int(p.next())%len(syl)])
	}
	s := b.String()
	return strings.ToUpper(s[:1]) + s[1:]
}

func hashSalt(s string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return int64(h.Sum64())
}
