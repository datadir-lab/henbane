// Package challenge is the HTTP adapter for the proof-of-work gate: it renders the
// interstitial page, verifies submitted solutions, and checks the access cookie.
// All crypto is delegated to the transport-pure internal/pow package.
package challenge

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/datadir-lab/henbane/internal/pow"
)

// CookieName is the opaque HMAC access token; VerifyPath is the solution endpoint.
const (
	CookieName = "hb_pow"
	VerifyPath = "/.well-known/henbane/verify"
	maxBody    = 4096
)

//go:embed challenge.tmpl.html
var pageTmplRaw string

var pageTmpl = template.Must(template.New("challenge").Parse(pageTmplRaw))

// Handler renders challenges and verifies solutions using a pow.Gate.
type Handler struct {
	gate   *pow.Gate
	now    func() time.Time
	secure bool // set the Secure attribute on the cookie (deployments behind TLS)
}

// New returns a Handler. secure sets the Secure cookie attribute.
func New(gate *pow.Gate, secure bool) *Handler {
	return &Handler{gate: gate, now: time.Now, secure: secure}
}

// HasValidToken reports whether r carries a valid, unexpired access cookie for ip.
func (h *Handler) HasValidToken(r *http.Request, ip netip.Addr) bool {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return false
	}
	return h.gate.ValidAccess(c.Value, ip, h.now())
}

// ServeChallenge issues a challenge for ip and renders the interstitial page
// (HTTP 200, uncacheable, noindex). The page is served at the original URL, so
// the solver reloads it once the access cookie is set.
func (h *Handler) ServeChallenge(w http.ResponseWriter, _ *http.Request, ip netip.Addr) {
	ch := h.gate.Issue(ip, h.now())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	_ = pageTmpl.Execute(w, struct {
		Challenge      string
		DifficultyBits int
		VerifyPath     string
	}{ch, h.gate.DifficultyBits(), VerifyPath})
}

// Verify handles POST VerifyPath: on a correct solution it sets the access cookie
// (204). Bad method, oversized/garbage body, or wrong solution are rejected.
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Challenge string `json:"challenge"`
		Solution  string `json:"solution"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tok, ok := h.gate.VerifySolution(body.Challenge, body.Solution, ip, h.now())
	if !ok {
		http.Error(w, "invalid solution", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}
