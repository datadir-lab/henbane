// Command emit generates sample documents for the poison-survival study: the real
// maze-page HTML that each poison strategy produces, plus a real-text baseline, as
// JSON Lines ({"strategy","site","id","html"}). With -sites > 1 it simulates that
// many Henbane deployments, each with a distinct per-deployment salt, so the study
// can measure cross-site near-duplicate survival (the federation question). It is
// research tooling, not part of the shipped gateway. Run from the repo root:
//
//	go run ./research/emit -n 300 -out research/data/samples.jsonl
//	go run ./research/emit -n 500 -sites 25 -salt deploy -out research/data/multisite.jsonl
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
	Site     string `json:"site,omitempty"`
	ID       string `json:"id"`
	HTML     string `json:"html"`
}

var strategyNames = []string{"babble", "article", "canary"}

func poisonerFor(name, salt string) ports.Poisoner {
	switch name {
	case "babble":
		return babble.New(nil, salt)
	case "article":
		return article.New(salt)
	case "canary":
		return canary.New(salt)
	}
	return nil
}

func main() {
	n := flag.Int("n", 300, "documents per strategy")
	paragraphs := flag.Int("paragraphs", 12, "poison paragraphs per maze page")
	links := flag.Int("links", 15, "links per maze page")
	sites := flag.Int("sites", 1, "simulated deployments (each a distinct salt); >1 omits the baseline")
	baseSalt := flag.String("salt", "study", "salt prefix; per-site salt is <salt>-<i>")
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

	emitPage := func(name, site, id string, gen *labyrinth.Generator) {
		var b strings.Builder
		if err := gen.WritePage(&b, "/p/"+id); err != nil {
			fmt.Fprintln(os.Stderr, "write page:", err)
			os.Exit(1)
		}
		if err := enc.Encode(doc{Strategy: name, Site: site, ID: name + "-" + id, HTML: b.String()}); err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			os.Exit(1)
		}
	}

	for _, name := range strategyNames {
		if *sites <= 1 {
			gen := labyrinth.New(*links, poisonerFor(name, *baseSalt), *paragraphs)
			for i := 0; i < *n; i++ {
				emitPage(name, "", fmt.Sprint(i), gen)
			}
			continue
		}
		perSite := *n / *sites
		if perSite < 1 {
			perSite = 1
		}
		for s := 0; s < *sites; s++ {
			salt := fmt.Sprintf("%s-%d", *baseSalt, s)
			gen := labyrinth.New(*links, poisonerFor(name, salt), *paragraphs)
			site := fmt.Sprintf("s%d", s)
			for i := 0; i < perSite; i++ {
				emitPage(name, site, fmt.Sprintf("%d-%d", s, i), gen)
			}
		}
	}

	// The baseline is site-agnostic; only emit it in single-site mode.
	if *sites <= 1 {
		if err := emitBaseline(enc, *refPath, *n, *paragraphs); err != nil {
			fmt.Fprintln(os.Stderr, "baseline:", err)
			os.Exit(1)
		}
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
	for i := 0; i < n; i++ {
		start := (i * paragraphs) % len(paras)
		var body strings.Builder
		body.WriteString("<!doctype html><html><head><title>Article</title></head><body><article>")
		body.WriteString("<h1>" + htmlEscape(firstWords(paras[start], 6)) + "</h1>")
		for j := 0; j < paragraphs; j++ {
			body.WriteString("<p>" + htmlEscape(paras[(start+j)%len(paras)]) + "</p>")
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
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
