package tlsfp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestFingerprintDeterministicAndDistinct(t *testing.T) {
	a := &tls.ClientHelloInfo{CipherSuites: []uint16{0x1301, 0x1302}, SupportedCurves: []tls.CurveID{tls.X25519}}
	f1, f2 := Fingerprint(a), Fingerprint(a)
	if f1 != f2 {
		t.Fatal("fingerprint must be deterministic")
	}
	if len(f1) != 16 {
		t.Errorf("fingerprint %q is not 16 hex chars", f1)
	}
	c := &tls.ClientHelloInfo{CipherSuites: []uint16{0x1303}, SupportedCurves: []tls.CurveID{tls.X25519}}
	if Fingerprint(a) == Fingerprint(c) {
		t.Error("different cipher suites must change the fingerprint")
	}
}

func TestFingerprintFiltersGREASE(t *testing.T) {
	plain := &tls.ClientHelloInfo{CipherSuites: []uint16{0x1301, 0x1302}, SupportedCurves: []tls.CurveID{tls.X25519}}
	greased := &tls.ClientHelloInfo{
		CipherSuites:    []uint16{0x0a0a, 0x1301, 0x1302},  // leading GREASE cipher
		SupportedCurves: []tls.CurveID{0x1a1a, tls.X25519}, // GREASE curve
	}
	if Fingerprint(plain) != Fingerprint(greased) {
		t.Error("GREASE values must not change the fingerprint")
	}
}

func TestFingerprintNil(t *testing.T) {
	if Fingerprint(nil) != "" {
		t.Error("nil ClientHelloInfo must yield an empty fingerprint")
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("%#x should be GREASE", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x0a0b, 0x1a2a, 0xc02b} {
		if isGREASE(v) {
			t.Errorf("%#x should not be GREASE", v)
		}
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestCaptureEndToEnd drives a real TLS handshake through the wrapped listener,
// decorated config, and ConnContext hook, and confirms the HTTP handler sees the
// client's fingerprint.
func TestCaptureEndToEnd(t *testing.T) {
	got := make(chan string, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := DecorateConfig(&tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, MinVersion: tls.VersionTLS12})
	srv := &http.Server{
		Handler:     http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- FromContext(r.Context()) }),
		ConnContext: ConnContext,
	}
	go srv.Serve(tls.NewListener(WrapListener(ln), tlsCfg))
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	select {
	case fp := <-got:
		// A live handshake must yield a well-formed JA4: t<9-char a>_<12 hex>_<12 hex>.
		parts := strings.Split(fp, "_")
		if len(parts) != 3 || len(parts[0]) != 10 || parts[0][0] != 't' ||
			len(parts[1]) != 12 || len(parts[2]) != 12 {
			t.Errorf("captured fingerprint = %q, want a JA4 string (t<a>_<12hex>_<12hex>)", fp)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never ran")
	}
}
