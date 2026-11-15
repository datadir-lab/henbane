package webbotauth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/datadir-lab/henbane/internal/ports"
)

func TestFetchDirectory(t *testing.T) {
	f, _, _ := loadFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DirectoryPath {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"`+f.JWK.X+`"},{"kty":"RSA","n":"ignored"}]}`)
	}))
	defer srv.Close()

	keys, err := FetchDirectory(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("FetchDirectory: %v", err)
	}
	if len(keys) != 1 { // the RSA key is ignored (Ed25519 only)
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].Thumbprint != f.Thumbprint {
		t.Errorf("thumbprint = %q, want %q", keys[0].Thumbprint, f.Thumbprint)
	}
}

type stubView struct {
	method, path, host string
	headers            map[string]string
}

func (v stubView) IP() netip.Addr         { return netip.Addr{} }
func (v stubView) UserAgent() string      { return "" }
func (v stubView) Method() string         { return v.method }
func (v stubView) Path() string           { return v.path }
func (v stubView) Header(k string) string { return v.headers[k] }
func (v stubView) Host() string           { return v.host }

func TestDetectorFiresForVerifiedAgent(t *testing.T) {
	f, v, _ := loadFixture(t)
	d := NewDetector(v, ports.TierBlocked)
	d.now = func() time.Time { return time.Unix(f.NowUnix, 0) }
	u, _ := url.Parse(f.URL)
	signed := stubView{method: f.Method, path: u.Path, host: u.Host, headers: map[string]string{
		"Signature-Input": f.SignatureInput, "Signature": f.Signature, "Signature-Agent": f.SignatureAgent,
	}}
	res, ok := d.Inspect(signed)
	if !ok || res.Tier != ports.TierBlocked {
		t.Fatalf("verified agent = %+v, %v; want blocked", res, ok)
	}
	if res.Signal != ports.Signal("webbotauth:https://signature-agent.test") {
		t.Errorf("signal = %q", res.Signal)
	}
	// An unsigned request must not fire.
	if _, ok := d.Inspect(stubView{host: "example.com", headers: map[string]string{}}); ok {
		t.Error("an unsigned request must not fire")
	}
	// A tampered authority must not fire.
	bad := signed
	bad.host = "evil.example"
	if _, ok := d.Inspect(bad); ok {
		t.Error("a tampered authority must not fire")
	}
}

type fixture struct {
	Method         string `json:"method"`
	URL            string `json:"url"`
	SignatureInput string `json:"signatureInput"`
	Signature      string `json:"signature"`
	SignatureAgent string `json:"signatureAgent"`
	Thumbprint     string `json:"thumbprint"`
	NowUnix        int64  `json:"nowUnix"`
	JWK            struct {
		X string `json:"x"`
	} `json:"jwk"`
}

func loadFixture(t *testing.T) (fixture, *Verifier, Request) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "reference.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(f.JWK.X)
	if err != nil {
		t.Fatal(err)
	}
	// The keyid in the signature is the RFC 7638 thumbprint; our computation must
	// match what the reference signer produced.
	if got := Thumbprint(f.JWK.X); got != f.Thumbprint {
		t.Fatalf("thumbprint mismatch: got %q, fixture %q", got, f.Thumbprint)
	}
	v := NewVerifier([]Key{{Origin: "https://signature-agent.test", Thumbprint: f.Thumbprint, Public: ed25519.PublicKey(pub)}})
	u, _ := url.Parse(f.URL)
	req := Request{
		Method: f.Method, Authority: u.Host, Path: u.Path,
		SignatureInput: f.SignatureInput, Signature: f.Signature, SignatureAgent: f.SignatureAgent,
	}
	return f, v, req
}

// TestVerifiesReferenceSignature is the interoperability oracle: our verifier
// must accept a request signed by Cloudflare's reference web-bot-auth signer.
func TestVerifiesReferenceSignature(t *testing.T) {
	f, v, req := loadFixture(t)
	origin, ok := v.Verify(time.Unix(f.NowUnix, 0), req)
	if !ok {
		t.Fatal("must verify the reference signer's signature (interop)")
	}
	if origin != "https://signature-agent.test" {
		t.Errorf("origin = %q", origin)
	}
}

func TestRejectsTamperedAuthority(t *testing.T) {
	f, v, req := loadFixture(t)
	req.Authority = "evil.example" // @authority is covered → tamper must break it
	if _, ok := v.Verify(time.Unix(f.NowUnix, 0), req); ok {
		t.Error("a tampered authority must fail verification")
	}
}

func TestRejectsExpired(t *testing.T) {
	_, v, req := loadFixture(t)
	if _, ok := v.Verify(time.Unix(1700100000+1000, 0), req); ok {
		t.Error("an expired signature must be rejected")
	}
}

func TestRejectsUnknownKey(t *testing.T) {
	f, _, req := loadFixture(t)
	empty := NewVerifier(nil) // no keys configured
	if _, ok := empty.Verify(time.Unix(f.NowUnix, 0), req); ok {
		t.Error("a signature from an unknown key must be rejected")
	}
}

func TestUnsignedRequest(t *testing.T) {
	f, v, _ := loadFixture(t)
	if _, ok := v.Verify(time.Unix(f.NowUnix, 0), Request{Method: "GET", Authority: "example.com"}); ok {
		t.Error("an unsigned request must not verify")
	}
}

func TestWithinValidity(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name   string
		at     time.Time
		params map[string]string
		valid  bool
	}{
		{"no window at all", now, map[string]string{}, false},
		{"fresh created, no expires", now, map[string]string{"created": "1700000000"}, true},
		{"old created, no expires", now.Add(48 * time.Hour), map[string]string{"created": "1700000000"}, false},
		{"in window", now, map[string]string{"created": "1699999000", "expires": "1700100000"}, true},
		{"expired", time.Unix(1_700_200_000, 0), map[string]string{"created": "1700000000", "expires": "1700100000"}, false},
		{"created in the future", now, map[string]string{"created": "1700100000"}, false},
	}
	for _, c := range cases {
		if got := withinValidity(c.at, c.params); got != c.valid {
			t.Errorf("%s: withinValidity = %v, want %v", c.name, got, c.valid)
		}
	}
}
