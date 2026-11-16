package h2capture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/datadir-lab/henbane/h2fp"
	"golang.org/x/net/http2"
)

// selfSignedCert builds an in-memory self-signed cert valid for 127.0.0.1 so the
// test can terminate TLS without touching the filesystem.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// startServer runs an Enable'd HTTP/2 server on a random port and returns its
// address plus a function returning the fingerprint the handler last observed.
func startServer(t *testing.T) (addr string, lastFP func() string) {
	t.Helper()
	var mu sync.Mutex
	var fp string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fp = h2fp.FromContext(r.Context())
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{
		Handler:   handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}},
	}
	Enable(srv)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	return ln.Addr().String(), func() string {
		mu.Lock()
		defer mu.Unlock()
		return fp
	}
}

func h2Client() *http.Client {
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
	}
	return &http.Client{Transport: tr}
}

func TestCapturesGoClientFingerprint(t *testing.T) {
	addr, lastFP := startServer(t)
	client := h2Client()
	defer client.CloseIdleConnections()

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("h2 GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %d.%d", resp.ProtoMajor, resp.ProtoMinor)
	}

	fp := lastFP()
	t.Logf("captured Go x/net http2 client fingerprint: %q", fp)
	if fp == "" {
		t.Fatal("no fingerprint captured for an HTTP/2 request")
	}

	parts := strings.Split(fp, "|")
	if len(parts) != 4 {
		t.Fatalf("fingerprint %q is not 4 pipe-separated fields", fp)
	}
	if parts[0] == "" {
		t.Error("SETTINGS section is empty; a real client always sends SETTINGS")
	}
	// Pseudo-header order: exactly the four request pseudo-headers, each once.
	order := strings.Split(parts[3], ",")
	seen := map[string]bool{}
	for _, l := range order {
		switch l {
		case "m", "a", "s", "p":
			if seen[l] {
				t.Errorf("pseudo-header %q repeated in %q", l, parts[3])
			}
			seen[l] = true
		default:
			t.Errorf("unexpected pseudo-header letter %q in %q", l, parts[3])
		}
	}
	if len(seen) != 4 {
		t.Errorf("expected all 4 pseudo-headers, got %q", parts[3])
	}
	// The Go/x-net HTTP/2 client is the canonical bot tell: its pseudo-header order
	// is :authority,:method,:path,:scheme — no mainstream browser leads with
	// :authority. This order is hardcoded in x/net/http2 and stable across versions
	// (the SETTINGS values may drift, so we pin only the order, not the whole string).
	if parts[3] != "a,m,p,s" {
		t.Errorf("Go x/net client pseudo-order = %q, want %q", parts[3], "a,m,p,s")
	}
}

func TestHTTP11RequestHasNoFingerprint(t *testing.T) {
	addr, lastFP := startServer(t)

	// An HTTP/1.1 client over TLS: ALPN negotiates http/1.1, so the h2 capture hook
	// never runs and no fingerprint is attached.
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}},
		ForceAttemptHTTP2: false,
	}
	client := &http.Client{Transport: tr}
	defer client.CloseIdleConnections()

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("h1 GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 1 {
		t.Fatalf("expected HTTP/1.1, got %d.%d", resp.ProtoMajor, resp.ProtoMinor)
	}
	if fp := lastFP(); fp != "" {
		t.Errorf("HTTP/1.1 request should have no h2 fingerprint, got %q", fp)
	}
}
