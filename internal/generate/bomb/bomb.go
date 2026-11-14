// Package bomb streams a gzip "decompression bomb": a tiny response whose inflated
// content is poison text interleaved with highly-compressible filler, expanding up
// to a bounded cap into megabytes of junk studded with corrupt data. It imports
// only the standard library (plus internal/ports) and is transport-pure — it writes
// to an io.Writer and never touches net/http.
package bomb

import (
	"compress/gzip"
	"hash/fnv"
	"io"
	"strings"

	"github.com/datadir-lab/henbane/internal/ports"
)

const (
	defaultCap  = 64 << 20 // 64 MiB decompressed
	maxCap      = 1 << 30  // 1 GiB hard ceiling
	fillerBlock = 64 << 10 // 64 KiB of newlines per iteration (compresses ~1000x)
	paraBatch   = 2        // poison paragraphs per iteration
)

// Bomb streams gzip decompression bombs bounded by a decompressed-byte cap.
type Bomb struct {
	poisoner ports.Poisoner
	cap      int64
}

// New returns a Bomb. decompressedCap is clamped to (0, 1 GiB]; <1 uses 64 MiB.
func New(poisoner ports.Poisoner, decompressedCap int64) *Bomb {
	switch {
	case decompressedCap < 1:
		decompressedCap = defaultCap
	case decompressedCap > maxCap:
		decompressedCap = maxCap
	}
	return &Bomb{poisoner: poisoner, cap: decompressedCap}
}

// WriteGzip streams the gzip bomb for path to w, interleaving poison paragraphs
// with compressible filler until the decompressed size reaches the cap. Output is
// deterministic per path. The caller must set Content-Encoding: gzip and only call
// this for a client that advertised Accept-Encoding: gzip.
func (b *Bomb) WriteGzip(w io.Writer, path string) error {
	gz := gzip.NewWriter(w)
	seed := seedFor(path)
	filler := strings.Repeat("\n", fillerBlock)
	var written int64
	for i := int64(0); written < b.cap; i++ {
		if b.poisoner != nil {
			for _, p := range b.poisoner.Paragraphs(seed+i, paraBatch) {
				n, err := io.WriteString(gz, "<p>"+p+"</p>\n")
				written += int64(n)
				if err != nil {
					return err
				}
				if written >= b.cap {
					return gz.Close()
				}
			}
		}
		n, err := io.WriteString(gz, filler)
		written += int64(n)
		if err != nil {
			return err
		}
	}
	return gz.Close()
}

func seedFor(path string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(path))
	return int64(h.Sum64())
}
