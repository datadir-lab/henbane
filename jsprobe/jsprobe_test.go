package jsprobe

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func testGate(tier Tier, deny []string) *Gate {
	return New([]byte("test-secret-key-for-jsprobe-unit"), tier, time.Hour, "/__v", false, deny)
}

func TestClassifyPassive(t *testing.T) {
	g := testGate(Passive, nil)
	if bot, _ := g.Classify(Signals{Webdriver: true}); !bot {
		t.Error("navigator.webdriver must be flagged")
	}
	if bot, _ := g.Classify(Signals{WebGLVendor: "Google SwiftShader"}); !bot {
		t.Error("a software WebGL renderer must be flagged")
	}
	if bot, _ := g.Classify(Signals{WebGLVendor: "Apple M2", HasChrome: true}); bot {
		t.Error("a real GPU must not be flagged at the passive tier")
	}
}

func TestClassifyBehavioural(t *testing.T) {
	g := testGate(Behavioural, nil)
	if bot, _ := g.Classify(Signals{HumanInput: false, WebGLVendor: "Apple M2"}); !bot {
		t.Error("no human input must be flagged at the behavioural tier")
	}
	if bot, _ := g.Classify(Signals{HumanInput: true, WebGLVendor: "Apple M2"}); bot {
		t.Error("human input + a real GPU must pass at the behavioural tier")
	}
	// The passive tier must not require human input.
	if bot, _ := testGate(Passive, nil).Classify(Signals{HumanInput: false, WebGLVendor: "Apple M2"}); bot {
		t.Error("the passive tier must not require human input")
	}
}

func TestClassifyDeviceDenylist(t *testing.T) {
	g := testGate(Device, []string{"deadbeef"})
	clean := Signals{HumanInput: true, WebGLVendor: "Apple M2"}
	denied := clean
	denied.DeviceHash = "deadbeef"
	if bot, _ := g.Classify(denied); !bot {
		t.Error("a denylisted device fingerprint must be flagged")
	}
	ok := clean
	ok.DeviceHash = "cafef00d"
	if bot, _ := g.Classify(ok); bot {
		t.Error("a non-denylisted device must pass")
	}
}

func TestTokenRoundTrip(t *testing.T) {
	g := testGate(Passive, nil)
	ip := netip.MustParseAddr("203.0.113.5")
	now := time.Unix(1_000_000, 0)
	tok := g.issueToken(ip, now)
	if !g.validToken(tok, ip, now.Add(time.Minute)) {
		t.Error("a fresh token must validate")
	}
	if g.validToken(tok, netip.MustParseAddr("203.0.113.6"), now.Add(time.Minute)) {
		t.Error("the token must be IP-bound")
	}
	if g.validToken(tok, ip, now.Add(2*time.Hour)) {
		t.Error("an expired token must fail")
	}
	if g.validToken(tok[:len(tok)-2]+"zz", ip, now.Add(time.Minute)) {
		t.Error("a tampered token must fail")
	}
	if g.validToken("garbage", ip, now) {
		t.Error("garbage must fail")
	}
}

func TestVerifyFlow(t *testing.T) {
	g := testGate(Passive, nil)
	ip := netip.MustParseAddr("203.0.113.5")

	// A clean report -> 204 + an IP-bound pass cookie that then validates.
	rec := httptest.NewRecorder()
	g.Verify(rec, httptest.NewRequest(http.MethodPost, "/__v", strings.NewReader(`{"webglVendor":"Apple M2"}`)), ip)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("clean report: code=%d, want 204", rec.Code)
	}
	cks := rec.Result().Cookies()
	if len(cks) == 0 || cks[0].Name != cookieName {
		t.Fatal("clean report must set a pass cookie")
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cks[0])
	if !g.HasValidToken(r2, ip) {
		t.Error("the issued cookie must pass HasValidToken for the same IP")
	}

	// A webdriver report -> 403 and no cookie.
	rec2 := httptest.NewRecorder()
	g.Verify(rec2, httptest.NewRequest(http.MethodPost, "/__v", strings.NewReader(`{"webdriver":true}`)), ip)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("webdriver report: code=%d, want 403", rec2.Code)
	}
	if len(rec2.Result().Cookies()) != 0 {
		t.Error("a failed probe must not set a pass cookie")
	}

	// Malformed body -> 400 (no panic).
	rec3 := httptest.NewRecorder()
	g.Verify(rec3, httptest.NewRequest(http.MethodPost, "/__v", strings.NewReader("not json")), ip)
	if rec3.Code != http.StatusBadRequest {
		t.Errorf("malformed report: code=%d, want 400", rec3.Code)
	}
}

func TestInterstitialCarriesProbe(t *testing.T) {
	g := testGate(Device, nil)
	rec := httptest.NewRecorder()
	g.ServeChallenge(rec, httptest.NewRequest(http.MethodGet, "/x", nil), netip.MustParseAddr("203.0.113.5"))
	body := rec.Body.String()
	for _, want := range []string{"HB_VERIFY", g.verifyPath, "navigator.webdriver", "HB_TIER=2"} {
		if !strings.Contains(body, want) {
			t.Errorf("interstitial is missing %q", want)
		}
	}
}
