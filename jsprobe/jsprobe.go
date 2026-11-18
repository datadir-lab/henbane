// Package jsprobe is the optional, opt-in device/behavioural fingerprinting module for
// Henbane. It is a SEPARATE module, never imported by the zero-dependency core, because
// what it does, fingerprinting a visitor's browser, is exactly the surveillance the core
// refuses. An operator who accepts that tradeoff runs the henbane-surveil binary, which
// plugs this Gate in as the challenge for Suspect clients (via henbane.WithChallenger).
//
// The probe runs ONLY on the challenge an already-Suspect client receives, so a reader
// the classifier never flagged is never fingerprinted. A client whose browser looks
// automated (the probe reports navigator.webdriver, a software WebGL renderer, no
// human-like input, or a denylisted device fingerprint) is not issued a pass token and
// stays at the interstitial; a client that looks human passes through. See the design
// doc for the honest ceiling: this does not beat a source-modified browser on a
// residential IP.
//
// It imports only the standard library.
package jsprobe

import (
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

//go:embed probe.js
var probeJS string

// Tier selects how invasive the probe is. Each tier includes the ones before it.
type Tier int

const (
	// Passive collects automation tells on load, with no interaction and nothing
	// user-identifying: navigator.webdriver and a software WebGL renderer.
	Passive Tier = iota
	// Behavioural additionally requires human-like input (pointer/scroll/key) before a
	// client passes, catching automation that presents a clean static fingerprint.
	Behavioural
	// Device additionally computes a canvas/WebGL device fingerprint that an operator can
	// denylist. This is the most invasive tier and the most clearly "surveillance".
	Device
)

const cookieName = "hb_probe"

// Gate is the probe challenge. It satisfies the henbane.Challenger interface
// structurally (HasValidToken / ServeChallenge / Verify), so it needs no import of the
// core.
type Gate struct {
	secret     []byte
	tier       Tier
	ttl        time.Duration
	verifyPath string
	secure     bool
	deviceDeny map[string]bool
	now        func() time.Time
}

// New returns a Gate. secret keys the pass token; tier selects invasiveness; ttl is the
// pass lifetime (<=0 uses 1h); verifyPath is where the probe POSTs; secure sets the
// cookie Secure flag (set it when TLS terminates here); deviceDeny lists device
// fingerprints to reject outright.
func New(secret []byte, tier Tier, ttl time.Duration, verifyPath string, secure bool, deviceDeny []string) *Gate {
	if ttl <= 0 {
		ttl = time.Hour
	}
	m := make(map[string]bool, len(deviceDeny))
	for _, d := range deviceDeny {
		if d != "" {
			m[d] = true
		}
	}
	return &Gate{secret: secret, tier: tier, ttl: ttl, verifyPath: verifyPath, secure: secure, deviceDeny: m, now: time.Now}
}

// VerifyPath is where the probe interstitial POSTs its report; pass it to
// henbane.WithChallenger.
func (g *Gate) VerifyPath() string { return g.verifyPath }

// --- henbane.Challenger ---

// HasValidToken reports whether r carries a valid, unexpired, IP-bound pass cookie.
func (g *Gate) HasValidToken(r *http.Request, ip netip.Addr) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return g.validToken(c.Value, ip, g.now())
}

// ServeChallenge serves the probe interstitial.
func (g *Gate) ServeChallenge(w http.ResponseWriter, _ *http.Request, _ netip.Addr) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, g.interstitial())
}

// Signals is the probe report a browser POSTs to the verify endpoint.
type Signals struct {
	Webdriver   bool   `json:"webdriver"`
	WebGLVendor string `json:"webglVendor"`
	HasChrome   bool   `json:"hasChrome"`
	HumanInput  bool   `json:"humanInput"`
	DeviceHash  string `json:"deviceHash"`
}

// Verify reads the probe report. A client that looks automated is refused a pass token
// (403) and stays at the interstitial; a client that looks human gets an IP-bound pass
// cookie and proceeds.
func (g *Gate) Verify(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	var s Signals
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&s); err != nil {
		http.Error(w, "bad probe report", http.StatusBadRequest)
		return
	}
	if bot, _ := g.Classify(s); bot {
		http.Error(w, "automation detected", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    g.issueToken(ip, g.now()),
		Path:     "/",
		HttpOnly: true,
		Secure:   g.secure,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// Classify reports whether the probe signals indicate automation, and why. The passive
// tells (webdriver, software renderer) are checked at every tier; the human-input and
// device-denylist checks apply at their tier and above.
func (g *Gate) Classify(s Signals) (bool, []string) {
	var reasons []string
	if s.Webdriver {
		reasons = append(reasons, "webdriver")
	}
	if isSoftwareRenderer(s.WebGLVendor) {
		reasons = append(reasons, "software_renderer")
	}
	if g.tier >= Behavioural && !s.HumanInput {
		reasons = append(reasons, "no_human_input")
	}
	if g.tier >= Device && s.DeviceHash != "" && g.deviceDeny[s.DeviceHash] {
		reasons = append(reasons, "device_denylisted")
	}
	return len(reasons) > 0, reasons
}

func isSoftwareRenderer(v string) bool {
	v = strings.ToLower(v)
	return strings.Contains(v, "swiftshader") || strings.Contains(v, "llvmpipe") ||
		strings.Contains(v, "software") || strings.Contains(v, "mesa offscreen")
}

// interstitial renders the challenge page with the probe script, templating the verify
// path and tier in as globals the script reads.
func (g *Gate) interstitial() string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	b.WriteString(`<meta name="robots" content="noindex, nofollow"><title>Checking your browser</title>`)
	b.WriteString(`</head><body><noscript>This check requires JavaScript.</noscript>`)
	b.WriteString(`<p id="hb-msg">Checking your browser, one moment.</p><script>`)
	b.WriteString("var HB_VERIFY=" + strconv.Quote(g.verifyPath) + ";var HB_TIER=" + strconv.Itoa(int(g.tier)) + ";\n")
	b.WriteString(probeJS)
	b.WriteString(`</script></body></html>`)
	return b.String()
}

// --- IP-bound, time-limited pass token (constant-time, mirrors the PoW token) ---

func (g *Gate) issueToken(ip netip.Addr, now time.Time) string {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(now.Add(g.ttl).Unix()))
	payload = append(payload, g.ipHash(ip)...)
	mac := g.mac(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac)
}

func (g *Gate) validToken(tok string, ip netip.Addr, now time.Time) bool {
	dot := strings.IndexByte(tok, '.')
	if dot < 0 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(tok[:dot])
	if err != nil || len(payload) != 8+sha256.Size {
		return false
	}
	mac, err := base64.RawURLEncoding.DecodeString(tok[dot+1:])
	if err != nil || !hmac.Equal(mac, g.mac(payload)) {
		return false
	}
	if now.Unix() >= int64(binary.BigEndian.Uint64(payload[:8])) {
		return false
	}
	return hmac.Equal(payload[8:], g.ipHash(ip))
}

func (g *Gate) mac(payload []byte) []byte {
	m := hmac.New(sha256.New, g.secret)
	m.Write(payload)
	return m.Sum(nil)
}

func (g *Gate) ipHash(ip netip.Addr) []byte {
	m := hmac.New(sha256.New, g.secret)
	a := ip.As16()
	m.Write(a[:])
	return m.Sum(nil)
}
