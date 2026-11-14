package labyrinth

import (
	"bytes"
	"strings"
	"testing"
)

func render(t *testing.T, g *Generator, path string) string {
	t.Helper()
	var b bytes.Buffer
	if err := g.WritePage(&b, path); err != nil {
		t.Fatalf("WritePage: %v", err)
	}
	return b.String()
}

func TestDeterministic(t *testing.T) {
	g := New(10)
	a := render(t, g, "/x/y")
	if a != render(t, g, "/x/y") {
		t.Error("same path must produce identical bytes")
	}
	if a == render(t, g, "/x/z") {
		t.Error("different paths should differ")
	}
}

func TestLinkCountAndClamp(t *testing.T) {
	for in, want := range map[int]int{0: 15, 5: 5, 200: 100} {
		if got := strings.Count(render(t, New(in), "/p"), "<a "); got != want {
			t.Errorf("New(%d) produced %d links, want %d", in, got, want)
		}
	}
}

func TestChildHrefsUnderParent(t *testing.T) {
	page := render(t, New(5), "/parent")
	if n := strings.Count(page, `href="/parent/`); n != 5 {
		t.Errorf("child hrefs under /parent/ = %d, want 5\n%s", n, page)
	}
}
