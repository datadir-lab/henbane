package challenge

import (
	"crypto/sha256"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/datadir-lab/henbane/internal/pow"
)

var ip = netip.MustParseAddr("203.0.113.9")

func newHandler() (*Handler, *pow.Gate) {
	g := pow.New([]byte("0123456789abcdef0123456789abcdef"), 8, 5*time.Minute, time.Hour)
	return New(g, false), g
}

func solve(difficulty int, challenge string) string {
	for i := 0; ; i++ {
		s := strconv.Itoa(i)
		d := sha256.Sum256([]byte(challenge + s))
		n := 0
		for _, c := range d {
			if c == 0 {
				n += 8
				continue
			}
			n += bits.LeadingZeros8(c)
			break
		}
		if n >= difficulty {
			return s
		}
	}
}

func TestServeChallengeRendersPageAndParams(t *testing.T) {
	h, g := newHandler()
	g.Issue(ip, time.Now()) // warm (no-op); page issues its own
	w := httptest.NewRecorder()
	h.ServeChallenge(w, httptest.NewRequest("GET", "/some/page", nil), ip)
	res := w.Result()
	body := w.Body.String()
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Error("challenge must be uncacheable")
	}
	if !strings.Contains(res.Header.Get("X-Robots-Tag"), "noindex") {
		t.Error("challenge must be noindex")
	}
	for _, want := range []string{`data-challenge="`, `data-bits="8"`, `data-verify="` + VerifyPath + `"`, "sha256 self-test", "one anonymous session cookie"} {
		if !strings.Contains(body, want) {
			t.Errorf("challenge page missing %q", want)
		}
	}
}

func TestVerifyAcceptsCorrectSolution(t *testing.T) {
	h, g := newHandler()
	ch := g.Issue(ip, time.Now())
	sol := solve(g.DifficultyBits(), ch)
	req := httptest.NewRequest("POST", VerifyPath, strings.NewReader(`{"challenge":"`+ch+`","solution":"`+sol+`"}`))
	w := httptest.NewRecorder()
	h.Verify(w, req, ip)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != CookieName {
		t.Fatalf("expected an %s cookie, got %v", CookieName, cookies)
	}
	if !g.ValidAccess(cookies[0].Value, ip, time.Now()) {
		t.Error("issued cookie is not a valid access token")
	}
	if cookies[0].HttpOnly != true || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Error("cookie must be HttpOnly + SameSite=Lax")
	}
}

func TestVerifyRejectsBadInput(t *testing.T) {
	h, g := newHandler()
	ch := g.Issue(ip, time.Now())

	// Wrong solution.
	w := httptest.NewRecorder()
	h.Verify(w, httptest.NewRequest("POST", VerifyPath, strings.NewReader(`{"challenge":"`+ch+`","solution":"1"}`)), ip)
	if w.Code != http.StatusForbidden {
		t.Errorf("wrong solution status = %d, want 403", w.Code)
	}
	// Wrong method.
	w = httptest.NewRecorder()
	h.Verify(w, httptest.NewRequest("GET", VerifyPath, nil), ip)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", w.Code)
	}
	// Garbage body.
	w = httptest.NewRecorder()
	h.Verify(w, httptest.NewRequest("POST", VerifyPath, strings.NewReader(`}{not json`)), ip)
	if w.Code != http.StatusBadRequest {
		t.Errorf("garbage body status = %d, want 400", w.Code)
	}
}

func TestHasValidToken(t *testing.T) {
	h, g := newHandler()
	// No cookie.
	if h.HasValidToken(httptest.NewRequest("GET", "/", nil), ip) {
		t.Error("no cookie should be invalid")
	}
	// Valid cookie.
	ch := g.Issue(ip, time.Now())
	tok, _ := g.VerifySolution(ch, solve(g.DifficultyBits(), ch), ip, time.Now())
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	if !h.HasValidToken(req, ip) {
		t.Error("valid token cookie should pass")
	}
	// Wrong IP.
	if h.HasValidToken(req, netip.MustParseAddr("203.0.113.10")) {
		t.Error("token must be IP-bound")
	}
	// Garbage cookie.
	bad := httptest.NewRequest("GET", "/", nil)
	bad.AddCookie(&http.Cookie{Name: CookieName, Value: "garbage"})
	if h.HasValidToken(bad, ip) {
		t.Error("garbage cookie should be invalid")
	}
}
