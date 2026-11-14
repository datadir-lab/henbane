// Command emit generates sample documents for the poison-survival study: the real
// maze-page HTML that each poison strategy produces, plus a real-text baseline, as
// JSON Lines ({"strategy","id","html"}). It is research tooling, not part of the
// shipped gateway. Run from the repo root:
//
//	go run ./research/emit -n 300 -paragraphs 12 -reference research/data/reference.txt -out research/data/samples.jsonl
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/datadir-lab/henbane/internal/generate/labyrinth"
	"github.com/datadir-lab/henbane/internal/generate/poison/article"
	"github.com/datadir-lab/henbane/internal/generate/poison/babble"
	"github.com/datadir-lab/henbane/internal/generate/poison/canary"
	"github.com/datadir-lab/henbane/internal/ports"
)

type doc struct {
	Strategy string `json:"strategy"`
	ID       string `json:"id"`
	HTML     string `json:"html"`
}

func main() {
	n := flag.Int("n", 300, "documents per strategy")
	paragraphs := flag.Int("paragraphs", 12, "poison paragraphs per maze page")
	links := flag.Int("links", 15, "links per maze page")
	refPath := flag.String("reference", "research/data/reference.txt", "real-text baseline corpus")
	outPath := flag.String("out", "research/data/samples.jsonl", "output JSONL path")
	flag.Parse()

	out, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create out:", err)
		os.Exit(1)
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	defer w.Flush()
	enc := json.NewEncoder(w)

	const salt = "study"
	strategies := map[string]ports.Poisoner{
		"babble":  babble.New(nil, salt),
		"article": article.New(salt),
		"canary":  canary.New(salt),
	}
	// Deterministic order for reproducibility.
	for _, name := range []string{"babble", "article", "canary"} {
		gen := labyrinth.New(*links, strategies[name], *paragraphs)
		for i := 0; i < *n; i++ {
			var b strings.Builder
			if err := gen.WritePage(&b, fmt.Sprintf("/p/%d", i)); err != nil {
				fmt.Fprintln(os.Stderr, "write page:", err)
				os.Exit(1)
			}
			if err := enc.Encode(doc{Strategy: name, ID: fmt.Sprintf("%s-%d", name, i), HTML: b.String()}); err != nil {
				fmt.Fprintln(os.Stderr, "encode:", err)
				os.Exit(1)
			}
		}
	}

	if err := emitBaseline(enc, *refPath, *n, *paragraphs); err != nil {
		fmt.Fprintln(os.Stderr, "baseline:", err)
		os.Exit(1)
	}
}

// emitBaseline chunks the real-text reference into n article-sized documents,
// wrapped in minimal article HTML, labelled "baseline_real".
func emitBaseline(enc *json.Encoder, refPath string, n, paragraphs int) error {
	raw, err := os.ReadFile(refPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: no reference corpus at %s; skipping baseline (%v)\n", refPath, err)
		return nil
	}
	paras := splitParagraphs(string(raw))
	if len(paras) == 0 {
		return nil
	}
	perDoc := paragraphs
	for i := 0; i < n; i++ {
		start := (i * perDoc) % len(paras)
		var body strings.Builder
		body.WriteString("<!doctype html><html><head><title>Article</title></head><body><article>")
		body.WriteString("<h1>" + htmlEscape(firstWords(paras[start], 6)) + "</h1>")
		for j := 0; j < perDoc; j++ {
			p := paras[(start+j)%len(paras)]
			body.WriteString("<p>" + htmlEscape(p) + "</p>")
		}
		body.WriteString("</article></body></html>")
		if err := enc.Encode(doc{Strategy: "baseline_real", ID: fmt.Sprintf("baseline-%d", i), HTML: body.String()}); err != nil {
			return err
		}
	}
	return nil
}

// splitParagraphs splits on blank lines and keeps substantial paragraphs.
func splitParagraphs(s string) []string {
	var out []string
	for _, blk := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n\n") {
		p := strings.Join(strings.Fields(blk), " ")
		if len(strings.Fields(p)) >= 20 {
			out = append(out, p)
		}
	}
	return out
}

func firstWords(s string, n int) string {
	f := strings.Fields(s)
	if len(f) > n {
		f = f[:n]
	}
	return strings.Join(f, " ")
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
