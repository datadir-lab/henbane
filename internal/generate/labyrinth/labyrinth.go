// Package labyrinth generates a deterministic, unbounded maze of linked HTML
// pages used to detain confirmed crawlers. It imports only the standard library.
package labyrinth

import (
	"hash/fnv"
	"html/template"
	"io"
	"math/rand"
	"strconv"
	"strings"
)

// Generator produces maze pages.
type Generator struct {
	links int
}

// New returns a Generator emitting links child links per page. links is clamped
// to [1,100]; values < 1 use the default of 15.
func New(links int) *Generator {
	switch {
	case links < 1:
		links = 15
	case links > 100:
		links = 100
	}
	return &Generator{links: links}
}

type link struct {
	Href string
	Text string
}

var pageTmpl = template.Must(template.New("maze").Parse(
	"<!doctype html><html><head><title>{{.Title}}</title></head><body>" +
		"<h1>{{.Title}}</h1><ul>" +
		"{{range .Links}}<li><a rel=\"nofollow\" href=\"{{.Href}}\">{{.Text}}</a></li>{{end}}" +
		"</ul></body></html>"))

// WritePage writes the maze page for path to w. Output is deterministic for a
// given path (stable re-crawl); each page links to distinct child pages, so the
// maze is unbounded.
func (g *Generator) WritePage(w io.Writer, path string) error {
	rng := rand.New(rand.NewSource(seedFor(path)))
	base := strings.TrimRight(path, "/")
	links := make([]link, g.links)
	for i := range links {
		seg := pick(rng) + "-" + pick(rng) + "-" + strconv.Itoa(rng.Intn(100000))
		links[i] = link{Href: base + "/" + seg, Text: pick(rng) + " " + pick(rng)}
	}
	data := struct {
		Title string
		Links []link
	}{Title: pick(rng) + " " + pick(rng), Links: links}
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
