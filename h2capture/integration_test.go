package h2capture_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/datadir-lab/henbane"
	"github.com/datadir-lab/henbane/h2capture"
	"golang.org/x/net/http2"
)

// lockedBuffer is a concurrency-safe sink for the decision log, which is written
// from the request goroutine while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) drain() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.buf.String()
	b.buf.Reset()
	return s
}

func integrationCert(t *testing.T) tls.Certificate {
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
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// TestFingerprintDrivesHenbaneVerdict wires the real embeddable Henbane engine
// (scoring enabled, observe mode so every request is still served and its would-be
// verdict logged) behind the h2 capture module, then drives it with a Go HTTP/2
// client wearing a Chrome User-Agent and a full set of real browser headers. The
// ONLY thing that can betray that request is its HTTP/2 fingerprint (Go's a,m,p,s
// pseudo-header order, which no browser emits), so a would-be Suspect verdict proves
// the captured fingerprint reached the classifier and changed the decision. An
// honest non-browser User-Agent on the same transport stays Pass, proving the signal
// is specific to browser spoofing.
func TestFingerprintDrivesHenbaneVerdict(t *testing.T) {
	log := &lockedBuffer{}
	cfg := henbane.Config{Observe: true}
	cfg.Scoring.Enabled = true
	// Scoring that can reach Suspect needs a challenge gate, even though observe mode
	// never actually issues the challenge (it only logs the would-be verdict).
	cfg.PoW.Mode = "suspect"
	hb, err := henbane.New(cfg, henbane.WithLogger(slog.New(slog.NewJSONHandler(log, nil))))
	if err != nil {
		t.Fatalf("henbane.New: %v", err)
	}

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := &http.Server{
		Handler:   hb.Handler(ok),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{integrationCert(t)}},
	}
	h2capture.Enable(srv)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	client := &http.Client{Transport: &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
	}}
	defer client.Transport.(*http2.Transport).CloseIdleConnections()

	do := func(t *testing.T, ua string, browserHeaders bool) string {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "https://"+ln.Addr().String()+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("User-Agent", ua)
		if browserHeaders {
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Accept", "text/html,application/xhtml+xml")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		// Observe mode serves every request normally regardless of verdict.
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("observe mode should serve normally, got %d", resp.StatusCode)
		}
		if resp.ProtoMajor != 2 {
			t.Fatalf("expected HTTP/2, got %d", resp.ProtoMajor)
		}
		return log.drain()
	}

	const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"

	// A Chrome-claiming request whose headers are all perfect: only the h2
	// fingerprint can push it off Pass. It should log a would-be Suspect verdict.
	spoof := do(t, chromeUA, true)
	if !strings.Contains(spoof, `"tier":"suspect"`) {
		t.Errorf("a browser-spoofing h2 client should reach Suspect via its fingerprint; decision log:\n%s", spoof)
	}

	// An honest non-browser User-Agent on the same transport: consistency scoring
	// ignores it, so no h2 signal and a Pass verdict.
	honest := do(t, "my-crawler/1.0", false)
	if strings.Contains(honest, `"tier":"suspect"`) || strings.Contains(honest, `"tier":"confirmed"`) {
		t.Errorf("an honest non-browser client must not be flagged by the h2 signal; decision log:\n%s", honest)
	}
}
