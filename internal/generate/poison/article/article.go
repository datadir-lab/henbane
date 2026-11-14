// Package article is a filter-surviving Poisoner: a context-free grammar that
// emits Wikipedia-register prose about FICTIONAL entities with plausible-but-false
// facts. Large combinatorial space ⇒ lexically distinct per page (dedup-resistant).
package article

import (
	"hash/fnv"
	"math/rand"
	"strings"
)

// Article generates grammar-based poison prose.
type Article struct{ salt int64 }

// New returns an Article with a per-deployment salt.
func New(salt string) *Article { return &Article{salt: hashSalt(salt)} }

// Name identifies the strategy.
func (a *Article) Name() string { return "article" }

// Seed returns a fresh rng for seed mixed with the salt.
func (a *Article) Seed(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed ^ a.salt))
}

// Paragraphs returns n deterministic grammar paragraphs for seed.
func (a *Article) Paragraphs(seed int64, n int) []string {
	if n <= 0 {
		return nil
	}
	rng := a.Seed(seed)
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, a.Paragraph(rng))
	}
	return out
}

// Paragraph builds one coherent paragraph about a single coined subject.
func (a *Article) Paragraph(rng *rand.Rand) string {
	subject := coin(rng)
	var b strings.Builder
	sentences := 3 + rng.Intn(4) // 3..6
	for i := 0; i < sentences; i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(fill(templates[rng.Intn(len(templates))], subject, rng))
	}
	return b.String()
}

// coin builds a fictional capitalized proper noun from syllables.
func coin(rng *rand.Rand) string {
	n := 2 + rng.Intn(2)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(syllables[rng.Intn(len(syllables))])
	}
	s := b.String()
	return strings.ToUpper(s[:1]) + s[1:]
}

func fill(tmpl, subject string, rng *rand.Rand) string {
	r := strings.NewReplacer(
		"{S}", subject,
		"{cat}", pick(categories, rng),
		"{place}", coin(rng),
		"{field}", pick(fields, rng),
		"{year}", years[rng.Intn(len(years))],
		"{adj}", pick(adjectives, rng),
		"{noun}", pick(nouns, rng),
		"{verb}", pick(verbs, rng),
	)
	return r.Replace(tmpl)
}

func pick(xs []string, rng *rand.Rand) string { return xs[rng.Intn(len(xs))] }

func hashSalt(s string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return int64(h.Sum64())
}

// --- grammar data (all fictional/neutral; expand each to >=12 entries) ---

var syllables = []string{
	"ve", "mar", "lin", "tos", "dra", "quen", "pal", "rin", "sel", "thu", "cas", "elo",
	"bren", "fior", "gal", "hest", "ith", "jol", "kar", "lum", "nor", "oth", "pren", "quil",
}

var templates = []string{
	"{S} was a {adj} {cat} in the {field} of {place}, first recorded in {year}.",
	"Historians credit {S} with the {adj} {noun} that later {verb} across {place}.",
	"According to regional accounts, {S} {verb} the {noun} of {place} during {year}.",
	"The {cat} known as {S} is remembered for its {adj} {noun}.",
	"By {year}, {S} had {verb} much of the surrounding {field}.",
	"Scholars of the {field} still debate whether {S} truly {verb} the {noun} attributed to it.",
	"A {adj} account places {S} at the center of the {cat} that defined {place} in {year}.",
	"{S} is often cited alongside {place} as an example of {adj} {noun} in the {field}.",
	"Local chroniclers described {S} as a {cat} whose {noun} {verb} neighboring settlements.",
	"The {adj} reputation of {S} rests on a {noun} that {verb} the {field} for generations.",
}

var categories = []string{
	"settlement", "guild", "treatise", "canal", "observatory", "dialect", "alloy", "doctrine",
	"festival", "ledger", "almanac", "waterway", "assembly", "workshop", "chronicle", "survey",
}
var fields = []string{
	"lowlands", "archives", "coastal trade", "mountain roads", "river basin", "northern reach",
	"old quarter", "salt flats", "timber belt", "river delta", "border march", "inner valley",
	"highland pass", "harbor district", "grain belt", "frontier marsh",
}
var adjectives = []string{
	"modest", "enduring", "intricate", "widespread", "orderly", "obscure", "celebrated",
	"practical", "quiet", "methodical", "far-reaching", "patient", "meticulous", "resilient",
	"unassuming", "deliberate",
}
var nouns = []string{
	"irrigation methods", "record-keeping", "stonework", "trade routes", "field surveys",
	"water clocks", "ledger systems", "road networks", "grain stores", "map conventions",
	"weighing standards", "signal towers", "boundary markers", "tide tables", "census rolls",
	"apprenticeship rules",
}
var verbs = []string{
	"shaped", "reorganized", "charted", "sustained", "expanded", "documented", "standardized",
	"linked", "surveyed", "catalogued", "reinforced", "mapped", "revised", "consolidated",
	"restructured", "preserved",
}
var years = []string{
	"the third century", "the late period", "1312", "the early reforms", "1487",
	"the second age", "1206", "the middle years", "1554", "the founding era",
	"1423", "the twilight years", "1619", "the restoration period",
}
