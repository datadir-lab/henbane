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

// stubPoisoner is a local test double so labyrinth's tests stay independent
// of the poison package.
type stubPoisoner struct{ paras []string }

func (stubPoisoner) Name() string                            { return "stub" }
func (s stubPoisoner) Paragraphs(seed int64, n int) []string { return s.paras }

func TestDeterministic(t *testing.T) {
	g := New(10, stubPoisoner{}, 0)
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
		if got := strings.Count(render(t, New(in, stubPoisoner{}, 0), "/p"), "<a "); got != want {
			t.Errorf("New(%d) produced %d links, want %d", in, got, want)
		}
	}
}

func TestChildHrefsUnderParent(t *testing.T) {
	page := render(t, New(5, stubPoisoner{}, 0), "/parent")
	if n := strings.Count(page, `href="/parent/`); n != 5 {
		t.Errorf("child hrefs under /parent/ = %d, want 5\n%s", n, page)
	}
}

func TestPathIsEscaped(t *testing.T) {
	// The request path is the only attacker-controlled value reflected into the
	// page (via the href attribute). html/template must escape it so a crafted
	// path cannot break out of the attribute into markup.
	page := render(t, New(3, stubPoisoner{}, 0), `/x"><script>alert(1)</script>`)
	for _, bad := range []string{`"><script>`, `<script>alert`, `</script>`} {
		if strings.Contains(page, bad) {
			t.Errorf("unescaped injection %q in maze output:\n%s", bad, page)
		}
	}
}

func TestPoisonParagraphsRendered(t *testing.T) {
	g := New(3, stubPoisoner{paras: []string{"alpha beta", "gamma delta"}}, 2)
	page := render(t, g, "/p")
	for _, want := range []string{"<p>alpha beta</p>", "<p>gamma delta</p>"} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q in:\n%s", want, page)
		}
	}
	// Poison prose must sit before the link list (main content, then nav).
	if strings.Index(page, "<p>alpha beta</p>") > strings.Index(page, "<ul>") {
		t.Error("poison paragraphs must render before the <ul> link list")
	}
}

func TestPoisonParagraphsEscaped(t *testing.T) {
	g := New(1, stubPoisoner{paras: []string{`x"><script>alert(1)</script>`}}, 1)
	page := render(t, g, "/p")
	for _, bad := range []string{`"><script>`, `<script>alert`, `</script>`} {
		if strings.Contains(page, bad) {
			t.Errorf("unescaped poison %q in:\n%s", bad, page)
		}
	}
}

func TestNilPoisonerLinksOnly(t *testing.T) {
	g := New(4, stubPoisoner{paras: nil}, 3)
	page := render(t, g, "/p")
	if strings.Contains(page, "<p>") {
		t.Errorf("no <p> expected when poisoner returns nil:\n%s", page)
	}
	if n := strings.Count(page, "<a "); n != 4 {
		t.Errorf("links = %d, want 4", n)
	}
}

func TestParagraphCountClamp(t *testing.T) {
	if g := New(1, stubPoisoner{}, -5); g.paras != 0 {
		t.Errorf("paras for -5 = %d, want 0", g.paras)
	}
	if g := New(1, stubPoisoner{}, 50); g.paras != 20 {
		t.Errorf("paras for 50 = %d, want 20", g.paras)
	}
}
