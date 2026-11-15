// Package benchmark measures the two cost dimensions that are honestly
// quantifiable: the per-request cost Henbane adds for the operator (decision
// latency) and the cost it imposes on a crawler (poison/maze generation
// throughput and the decompression-bomb amplification). Run with:
//
//	go test -bench=. -benchmem ./research/benchmark
//
// The numbers it prints are transcribed into research/benchmarks.md and the
// README's effectiveness section.
package benchmark

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/netip"
	"testing"

	"github.com/datadir-lab/henbane/internal/assembly"
	"github.com/datadir-lab/henbane/internal/config"
	"github.com/datadir-lab/henbane/internal/generate/bomb"
	"github.com/datadir-lab/henbane/internal/generate/labyrinth"
	"github.com/datadir-lab/henbane/internal/generate/poison/article"
	"github.com/datadir-lab/henbane/internal/generate/poison/babble"
	"github.com/datadir-lab/henbane/internal/generate/poison/canary"
	"github.com/datadir-lab/henbane/internal/generate/poison/splice"
	"github.com/datadir-lab/henbane/internal/ports"
)

// --- operator cost: full-stack decision latency ---

type benchView struct {
	ua      string
	headers map[string]string
}

func (v benchView) IP() netip.Addr         { return netip.MustParseAddr("203.0.113.10") }
func (v benchView) UserAgent() string      { return v.ua }
func (v benchView) Method() string         { return "GET" }
func (v benchView) Path() string           { return "/articles/the-quick-brown-fox" }
func (v benchView) Header(n string) string { return v.headers[n] }
func (v benchView) HTTPMajorVersion() int  { return 2 }

// fullStackEngine builds an engine with every zero-cost-to-enable layer on:
// IP/UA denylists, honeypot, velocity, both good-bot verifiers, and scoring.
func fullStackEngine(b *testing.B) ports.Engine {
	b.Helper()
	cfg := config.Config{}
	cfg.Deny.CIDRs = []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"}
	cfg.Deny.UserAgents = []string{"badbot", "evilscraper", "masscan"}
	cfg.Honeypot.Enabled = true
	cfg.Honeypot.Path = "/trap"
	cfg.Velocity.Enabled = true
	cfg.VerifiedBots.Enabled = true
	cfg.AICrawlers.Enabled = true
	cfg.PoW.Mode = "suspect"
	cfg.Scoring.Enabled = true
	comps, err := assembly.Build(cfg)
	if err != nil {
		b.Fatalf("assembly.Build: %v", err)
	}
	return comps.Engine
}

func BenchmarkEngineDecide(b *testing.B) {
	engine := fullStackEngine(b)
	// A realistic, well-formed browser request — the common case, which must
	// traverse every detector and scorer before being allowed.
	view := benchView{
		ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		headers: map[string]string{
			"Sec-Fetch-Site":  "none",
			"Accept":          "text/html,application/xhtml+xml",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
		},
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Decide(ctx, view)
	}
}

// --- crawler cost: poison generation throughput ---

// poisonBytes sums the bytes a Poisoner emits for one page (4 paragraphs), so the
// benchmark can report MB/s of garbage generated.
func poisonBytes(p ports.Poisoner) int64 {
	var n int64
	for _, para := range p.Paragraphs(1, 4) {
		n += int64(len(para))
	}
	return n
}

func benchPoison(b *testing.B, p ports.Poisoner) {
	b.SetBytes(poisonBytes(p))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Paragraphs(int64(i), 4)
	}
}

func BenchmarkPoisonBabble(b *testing.B)  { benchPoison(b, babble.New(nil, "bench")) }
func BenchmarkPoisonSplice(b *testing.B)  { benchPoison(b, splice.New(nil, "bench")) }
func BenchmarkPoisonArticle(b *testing.B) { benchPoison(b, article.New("bench")) }
func BenchmarkPoisonCanary(b *testing.B)  { benchPoison(b, canary.New("bench")) }

// --- crawler cost: a full maze page (links + poison) ---

type countWriter int64

func (c *countWriter) Write(p []byte) (int, error) { *c += countWriter(len(p)); return len(p), nil }

func BenchmarkMazePage(b *testing.B) {
	gen := labyrinth.New(32, babble.New(nil, "bench"), 4) // 32 links + 4 poison paragraphs
	var cw countWriter
	_ = gen.WritePage(&cw, "/maze/entry")
	b.SetBytes(int64(cw))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gen.WritePage(io.Discard, "/maze/entry")
	}
}

// --- crawler cost: decompression-bomb amplification ---

// TestBombAmplification reports the amplification ratio — how many bytes a crawler
// must decompress per byte Henbane sends. Not a benchmark (it measures a ratio,
// not time), but it belongs with the resource-cost story.
func TestBombAmplification(t *testing.T) {
	for _, decompCap := range []int64{10 << 20, 100 << 20, 1 << 30} { // 10MB, 100MB, 1GB decompressed
		var out bytes.Buffer
		bmb := bomb.New(babble.New(nil, "bench"), decompCap)
		if err := bmb.WriteGzip(&out, "/trap"); err != nil {
			t.Fatalf("WriteGzip: %v", err)
		}
		sent := int64(out.Len()) // capture before the reader drains the buffer
		if sent == 0 {
			t.Fatal("bomb produced no output")
		}
		// Sanity: the gzip really does expand to about the cap.
		zr, err := gzip.NewReader(bytes.NewReader(out.Bytes()))
		if err != nil {
			t.Fatalf("gzip: %v", err)
		}
		n, _ := io.Copy(io.Discard, zr)
		t.Logf("cap=%4dMB  sent=%7d bytes on the wire  ->  %11d bytes decompressed  (%.0fx amplification)",
			decompCap>>20, sent, n, float64(n)/float64(sent))
	}
}
