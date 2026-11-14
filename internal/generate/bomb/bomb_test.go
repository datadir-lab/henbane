package bomb

import (
	"bytes"
	"compress/gzip"
	"io"
	"strconv"
	"strings"
	"testing"
)

type stubPoisoner struct{}

func (stubPoisoner) Name() string { return "stub" }
func (stubPoisoner) Paragraphs(seed int64, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "POISON-TEXT-marker-" + strconv.FormatInt(seed, 10)
	}
	return out
}

func decompress(t *testing.T, g []byte) string {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(g))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	return string(b)
}

func TestWritesBoundedGzipBombWithPoison(t *testing.T) {
	cap := int64(2 << 20) // 2 MiB decompressed
	var buf bytes.Buffer
	if err := New(stubPoisoner{}, cap).WriteGzip(&buf, "/x"); err != nil {
		t.Fatal(err)
	}
	compressed := int64(buf.Len())
	out := decompress(t, buf.Bytes())
	decompressed := int64(len(out))

	if decompressed == 0 || decompressed > cap+(128<<10) {
		t.Errorf("decompressed = %d, want in (0, cap+128KiB] (cap=%d)", decompressed, cap)
	}
	if !strings.Contains(out, "POISON-TEXT-marker") {
		t.Error("the bomb must contain poison text")
	}
	// The asymmetry is the point: compressed must be far smaller than decompressed.
	if compressed*10 > decompressed {
		t.Errorf("ratio too low: %d compressed vs %d decompressed", compressed, decompressed)
	}
}

func TestDeterministicPerPath(t *testing.T) {
	b := New(stubPoisoner{}, 1<<20)
	var a, c bytes.Buffer
	_ = b.WriteGzip(&a, "/p")
	_ = b.WriteGzip(&c, "/p")
	if !bytes.Equal(a.Bytes(), c.Bytes()) {
		t.Error("same path must produce identical bytes")
	}
	var d bytes.Buffer
	_ = b.WriteGzip(&d, "/other")
	if bytes.Equal(a.Bytes(), d.Bytes()) {
		t.Error("different paths should differ")
	}
}

func TestNilPoisonerStillBombs(t *testing.T) {
	var buf bytes.Buffer
	if err := New(nil, 512<<10).WriteGzip(&buf, "/x"); err != nil {
		t.Fatal(err)
	}
	if len(decompress(t, buf.Bytes())) == 0 {
		t.Error("a nil poisoner should still produce a filler-only bomb")
	}
}

func TestCapClampAndDefault(t *testing.T) {
	if New(stubPoisoner{}, 0).cap <= 0 {
		t.Error("non-positive cap must fall back to a positive default")
	}
	if New(stubPoisoner{}, 1<<40).cap > maxCap {
		t.Error("cap must be clamped to the hard ceiling")
	}
}
