// Package labyrinth generates a deterministic, unbounded maze of linked HTML
// pages used to detain confirmed crawlers. It imports only the standard library
// and internal/ports (for the Poisoner interface).
package labyrinth

import (
	"hash/fnv"
	"html/template"
	"io"
	"math/rand"
	"strconv"
	"strings"

	"github.com/datadir-lab/henbane/internal/ports"
)

// Generator produces maze pages.
type Generator struct {
	links    int
	poisoner ports.Poisoner
	paras    int
}

// New returns a Generator emitting links child links per page (clamped to
// [1,100]; <1 uses default 15) with up to paragraphs poison paragraphs (clamped
// to [0,20]) drawn from poisoner.
func New(links int, poisoner ports.Poisoner, paragraphs int) *Generator {
	switch {
	case links < 1:
		links = 15
	case links > 100:
		links = 100
	}
	switch {
	case paragraphs < 0:
		paragraphs = 0
	case paragraphs > 20:
		paragraphs = 20
	}
	return &Generator{links: links, poisoner: poisoner, paras: paragraphs}
}

// maxPathBytes caps how much of the request path is echoed into each child link, so a
// large-URL request cannot draw a maze response proportional to the URL times the link
// count. 256 bytes is well above any realistic crawl path.
const maxPathBytes = 256

type link struct {
	Href string
	Text string
}

var pageTmpl = template.Must(template.New("maze").Parse(
	"<!doctype html><html><head><title>{{.Title}}</title></head><body>" +
		"<h1>{{.Title}}</h1>" +
		"{{range .Paragraphs}}<p>{{.}}</p>{{end}}" +
		"<ul>" +
		"{{range .Links}}<li><a rel=\"nofollow\" href=\"{{.Href}}\">{{.Text}}</a></li>{{end}}" +
		"</ul></body></html>"))

// WritePage writes the maze page for path to w. Output is deterministic for a
// given path (stable re-crawl); each page links to distinct child pages, so the
// maze is unbounded.
func (g *Generator) WritePage(w io.Writer, path string) error {
	// math/rand (v1) with an explicit source is deliberate: it produces
	// cross-version-stable output, so re-crawls and multiple instances see
	// identical mazes. Do NOT switch to math/rand/v2 — it would break determinism.
	seed := seedFor(path)
	rng := rand.New(rand.NewSource(seed))
	base := strings.TrimRight(path, "/")
	// The path is attacker-controlled and is echoed once per link (up to 100), so an
	// unbounded path would let a single large-URL request to a maze or honeypot path
	// (the honeypot path is public in robots.txt and tarpits on the first hit) draw a
	// response many times its size: an egress-amplification vector against the operator.
	// Cap the echoed prefix; a realistic crawl path is far shorter. The child links stay
	// bounded on every subsequent hop as a result.
	if len(base) > maxPathBytes {
		base = base[:maxPathBytes]
	}
	links := make([]link, g.links)
	for i := range links {
		seg := pick(rng) + "-" + pick(rng) + "-" + strconv.Itoa(rng.Intn(100000))
		links[i] = link{Href: base + "/" + seg, Text: pick(rng) + " " + pick(rng)}
	}
	var paras []string
	if g.poisoner != nil {
		paras = g.poisoner.Paragraphs(seed, g.paras)
	}
	data := struct {
		Title      string
		Paragraphs []string
		Links      []link
	}{Title: pick(rng) + " " + pick(rng), Paragraphs: paras, Links: links}
	return pageTmpl.Execute(w, data)
}

func seedFor(path string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(path))
	return int64(h.Sum64())
}

func pick(rng *rand.Rand) string { return words[rng.Intn(len(words))] }

var words = []string{
	"index", "about", "archive", "page", "category", "tag", "post", "article",
	"news", "docs", "guide", "section", "list", "view", "detail", "item",
	"group", "topic", "entry", "report",
}
