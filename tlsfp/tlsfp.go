// Package tlsfp computes a stable TLS client fingerprint during the handshake and
// carries it to the HTTP request on the same connection.
//
// It produces a FoxIO JA4 fingerprint, the industry-standard format, so the value is
// comparable with other tools' output (an operator can denylist a JA4 string from a
// threat feed). The standard library hides the raw ClientHello, which JA4 needs for the
// exact extension list, so the fingerprint-capturing listener buffers the opening
// ClientHello and clienthello.go recovers the extension types from it; everything else
// (ciphers, ALPN, signature schemes, versions) comes from the ClientHelloInfo. When the
// raw ClientHello cannot be parsed (a fragmented or malformed record), it falls back to
// a coarse GREASE-filtered hash of the ClientHelloInfo fields, so there is always a
// stable fingerprint. Either way it is captured only when Henbane terminates TLS itself;
// behind a TLS-terminating proxy or CDN the fingerprint is empty.
package tlsfp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
)

// Fingerprint returns a short, stable hex fingerprint for chi, or "" if chi is
// nil. GREASE values are dropped so the result is deterministic for a client.
func Fingerprint(chi *tls.ClientHelloInfo) string {
	if chi == nil {
		return ""
	}
	h := sha256.New()
	sep := func() { h.Write([]byte{'|'}) }
	putU16s(h, chi.SupportedVersions)
	sep()
	putU16s(h, chi.CipherSuites)
	sep()
	curves := make([]uint16, len(chi.SupportedCurves))
	for i, c := range chi.SupportedCurves {
		curves[i] = uint16(c)
	}
	putU16s(h, curves)
	sep()
	h.Write(chi.SupportedPoints) // single-byte point formats; GREASE is u16-only
	sep()
	for _, p := range chi.SupportedProtos {
		h.Write([]byte(p))
		h.Write([]byte{','})
	}
	sep()
	sigs := make([]uint16, len(chi.SignatureSchemes))
	for i, s := range chi.SignatureSchemes {
		sigs[i] = uint16(s)
	}
	putU16s(h, sigs)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8]) // 16 hex chars
}

// putU16s writes each non-GREASE value as big-endian into h.
func putU16s(h interface{ Write([]byte) (int, error) }, vs []uint16) {
	var buf [2]byte
	for _, v := range vs {
		if isGREASE(v) {
			continue
		}
		binary.BigEndian.PutUint16(buf[:], v)
		_, _ = h.Write(buf[:])
	}
}

// isGREASE reports whether v is one of the 16 GREASE values (RFC 8701):
// 0x0a0a, 0x1a1a, … 0xfafa — both bytes equal with low nibble 0xa.
func isGREASE(v uint16) bool {
	hi, lo := byte(v>>8), byte(v)
	return hi == lo && lo&0x0f == 0x0a
}

// --- capture: handshake -> request on the same connection ---

type ctxKey struct{}

// holder carries the fingerprint from the handshake to the request. It is
// written in GetConfigForClient and read while serving the request — the same
// connection goroutine, so no synchronization is needed.
type holder struct{ fp string }

// maxCapture bounds how many bytes of the opening handshake are buffered for JA4
// parsing. A ClientHello is far smaller; the cap keeps a hostile oversized record from
// growing the buffer without bound.
const maxCapture = 16 << 10

type fpConn struct {
	net.Conn
	h           *holder
	capture     []byte // the ClientHello bytes, buffered until the fingerprint is computed
	captureDone bool
}

// Read passes bytes through unchanged (the return value is never modified, so the TLS
// handshake is unaffected) while buffering the opening ClientHello for JA4 parsing. It
// runs on the connection's own goroutine, the same one that reads the fingerprint, so
// no synchronization is needed.
func (c *fpConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.captureDone && len(c.capture) < maxCapture {
		if room := maxCapture - len(c.capture); n > room {
			c.capture = append(c.capture, p[:room]...)
		} else {
			c.capture = append(c.capture, p[:n]...)
		}
	}
	return n, err
}

type listener struct{ net.Listener }

func (l listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &fpConn{Conn: c, h: &holder{}}, nil
}

// WrapListener wraps l so each connection carries a fingerprint holder. Wrap the
// raw TCP listener with this, then with tls.NewListener.
func WrapListener(l net.Listener) net.Listener { return listener{l} }

// DecorateConfig installs a GetConfigForClient on cfg (chaining any existing
// one) that computes and stores the client's fingerprint on the connection.
func DecorateConfig(cfg *tls.Config) *tls.Config {
	prev := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		if fc, ok := chi.Conn.(*fpConn); ok {
			// The ClientHello has now been read; stop buffering and compute the JA4
			// fingerprint from the captured bytes, falling back to the coarse
			// fingerprint if the raw ClientHello could not be parsed.
			fc.captureDone = true
			fp := ""
			if exts, parsed := parseClientHelloExtensions(fc.capture); parsed {
				fp = JA4(chi, exts)
			}
			if fp == "" {
				fp = Fingerprint(chi)
			}
			fc.h.fp = fp
			fc.capture = nil // release the buffer
		}
		if prev != nil {
			return prev(chi)
		}
		return nil, nil
	}
	return cfg
}

// ConnContext is the http.Server.ConnContext hook: it stashes the connection's
// fingerprint holder in the request base context.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		if fc, ok := tc.NetConn().(*fpConn); ok {
			return context.WithValue(ctx, ctxKey{}, fc.h)
		}
	}
	return ctx
}

// strKey carries a pre-computed fingerprint string, as opposed to the holder that
// the ConnContext path stashes.
type strKey struct{}

// WithFingerprint carries an already-computed TLS fingerprint in ctx. The ConnContext
// holder path does not reach a connection that http.Server hands off via TLSNextProto
// (an HTTP/2 connection taken over by golang.org/x/net/http2), because that server
// builds request contexts itself. The h2capture module reads the fingerprint off the
// connection with FromConn and re-attaches it here so FromContext still resolves it.
func WithFingerprint(ctx context.Context, fp string) context.Context {
	if fp == "" {
		return ctx
	}
	return context.WithValue(ctx, strKey{}, fp)
}

// FromConn returns the TLS fingerprint already captured for c, or "" if c did not come
// through WrapListener. The TLS handshake has completed by the time ALPN dispatch runs,
// so the fingerprint is populated and can be read directly off the connection.
func FromConn(c net.Conn) string {
	if tc, ok := c.(*tls.Conn); ok {
		if fc, ok := tc.NetConn().(*fpConn); ok {
			return fc.h.fp
		}
	}
	return ""
}

// FromContext returns the TLS fingerprint captured for the request's connection,
// or "" if TLS was not terminated here (or capture is not wired).
func FromContext(ctx context.Context) string {
	if s, ok := ctx.Value(strKey{}).(string); ok && s != "" {
		return s
	}
	if h, ok := ctx.Value(ctxKey{}).(*holder); ok {
		return h.fp
	}
	return ""
}
