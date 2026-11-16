// Package h2capture is the optional HTTP/2 fingerprint-capture module for Henbane.
// It serves HTTP/2 while recording each client's Akamai-style h2 fingerprint and
// attaching it to every request's context, where Henbane's engine reads it (via
// the core h2fp package) as a strong anti-spoofing signal.
//
// It lives in a separate Go module because capturing the fingerprint requires
// reading the raw HTTP/2 preface frames, which Go's standard library hides: the
// only way to see them is to drive the connection with golang.org/x/net/http2's
// Framer and serve it with that package's http2.Server — a third-party dependency
// the zero-dependency core must not take. Keeping it here means those dependencies
// never touch the core (the same pattern as the Caddy plugin module).
//
// Integration is a one-liner: build your *http.Server as usual (with Henbane's
// handler and, ideally, TLS termination) and call Enable(srv). Enable installs a
// TLSNextProto["h2"] hook that sniffs the connection preface, computes the
// fingerprint, and serves the rest of the connection with x/net/http2 — so
// HTTP/1.1 is still served by the standard server untouched, and only the h2 path
// is intercepted.
package h2capture

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/datadir-lab/henbane/h2fp"
	"github.com/datadir-lab/henbane/tlsfp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// defaultSniffTimeout bounds how long Enable waits to read a connection's preface
// frames before giving up and serving the connection anyway (with whatever partial
// fingerprint was captured). The replay is byte-exact regardless of where sniffing
// stopped, so a slow client is served correctly — it just may not be fingerprinted.
const defaultSniffTimeout = 5 * time.Second

// initialHeaderTableSize is the HPACK dynamic-table size the sniffing decoder
// assumes before the client's SETTINGS are applied (the HTTP/2 default, RFC 7540).
const initialHeaderTableSize = 4096

// Enable configures srv to serve HTTP/2 with Akamai fingerprint capture. It ensures
// srv.TLSConfig advertises "h2" (and "http/1.1") via ALPN and installs a
// TLSNextProto["h2"] hook that, for each new HTTP/2 connection, reads the preface
// frames, computes the fingerprint, and serves the connection with the fingerprint
// attached to every request's context (read it with h2fp.FromContext). HTTP/1.1
// connections are served by srv normally. Call Enable once, before serving.
func Enable(srv *http.Server) {
	if srv.TLSConfig == nil {
		srv.TLSConfig = &tls.Config{}
	}
	srv.TLSConfig.NextProtos = ensureALPN(srv.TLSConfig.NextProtos)

	h2s := &http2.Server{}
	if srv.TLSNextProto == nil {
		srv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}
	srv.TLSNextProto["h2"] = func(hs *http.Server, c *tls.Conn, h http.Handler) {
		serveH2(hs, h2s, c, h)
	}
}

// ensureALPN returns protos with "h2" first and "http/1.1" present, preserving any
// other protocols, so the server offers HTTP/2 while still accepting HTTP/1.1.
func ensureALPN(protos []string) []string {
	has := func(p string) bool {
		for _, x := range protos {
			if x == p {
				return true
			}
		}
		return false
	}
	out := []string{"h2"}
	for _, p := range protos {
		if p != "h2" {
			out = append(out, p)
		}
	}
	if !has("http/1.1") {
		out = append(out, "http/1.1")
	}
	return out
}

// serveH2 sniffs the fingerprint from c's preface, then serves the whole connection
// with x/net/http2, replaying the sniffed bytes so the server sees an untouched
// stream. Both the HTTP/2 fingerprint and (when c came through tlsfp.WrapListener)
// the client's TLS fingerprint are attached to every request's context.
func serveH2(srv *http.Server, h2s *http2.Server, c *tls.Conn, handler http.Handler) {
	fp, buffered := sniff(c, defaultSniffTimeout)

	// x/net/http2 builds its own request contexts, so net/http's ConnContext (the
	// path that normally carries the TLS fingerprint) never runs for this connection.
	// Read the fingerprint — already computed during the handshake — straight off the
	// connection and re-attach it below so the engine still sees it on HTTP/2 requests.
	tlsFP := tlsfp.FromConn(c)

	// Replay: the server re-reads the exact original byte stream (the bytes we
	// buffered during sniffing, then the live connection). MultiReader reconstructs
	// the stream byte-for-byte regardless of where sniffing stopped, so this is
	// always safe — even on a sniff timeout mid-frame.
	replay := &replayConn{Conn: c, r: io.MultiReader(bytes.NewReader(buffered), c)}

	h2s.ServeConn(replay, &http2.ServeConnOpts{
		BaseConfig: srv,
		Handler:    withFingerprints(handler, fp, tlsFP),
	})
}

// withFingerprints wraps h so every request it serves carries the HTTP/2 fingerprint
// (h2FP) and, when non-empty, the TLS fingerprint (tlsFP) in its context. Empty
// fingerprints are not attached, so a client that was not fingerprinted is unaffected.
func withFingerprints(h http.Handler, h2FP, tlsFP string) http.Handler {
	if h2FP == "" && tlsFP == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = h2fp.WithFingerprint(ctx, h2FP)
		ctx = tlsfp.WithFingerprint(ctx, tlsFP)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sniff reads the HTTP/2 connection preface and the client's opening frames
// (SETTINGS, connection WINDOW_UPDATE, PRIORITY, and the first HEADERS), computing
// the Akamai fingerprint. It returns the fingerprint string and every byte it
// consumed, so the caller can replay them. It is best-effort: on any read error or
// timeout it returns whatever it captured so far (possibly an empty fingerprint),
// never blocking the connection beyond timeout.
func sniff(c net.Conn, timeout time.Duration) (fingerprint string, buffered []byte) {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer c.SetReadDeadline(time.Time{})

	var buf bytes.Buffer
	tee := io.TeeReader(c, &buf)

	// Consume and verify the 24-byte client preface so the Framer starts on a frame
	// boundary. The bytes are tee'd into buf for replay regardless.
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(tee, preface); err != nil || string(preface) != http2.ClientPreface {
		return "", buf.Bytes()
	}

	fr := http2.NewFramer(io.Discard, tee)
	fr.ReadMetaHeaders = hpack.NewDecoder(initialHeaderTableSize, nil)

	var f h2fp.Fingerprint
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return f.String(), buf.Bytes()
		}
		switch ff := frame.(type) {
		case *http2.SettingsFrame:
			if ff.IsAck() {
				continue
			}
			_ = ff.ForeachSetting(func(s http2.Setting) error {
				f.Settings = append(f.Settings, h2fp.Setting{ID: uint16(s.ID), Val: s.Val})
				return nil
			})
		case *http2.WindowUpdateFrame:
			// Connection-level (stream 0) increment only, and only the first one.
			if ff.StreamID == 0 && f.WindowUpdate == 0 {
				f.WindowUpdate = ff.Increment
			}
		case *http2.PriorityFrame:
			f.Priorities = append(f.Priorities, h2fp.Priority{
				StreamID:  ff.StreamID,
				Exclusive: ff.PriorityParam.Exclusive,
				DependsOn: ff.PriorityParam.StreamDep,
				Weight:    uint32(ff.PriorityParam.Weight) + 1, // wire octet + 1 (RFC 7540 §6.3)
			})
		case *http2.MetaHeadersFrame:
			for _, hf := range ff.Fields {
				if len(hf.Name) >= 2 && hf.Name[0] == ':' {
					f.PseudoOrder = append(f.PseudoOrder, hf.Name[1:2])
				}
			}
			// The first HEADERS frame completes the fingerprint; stop sniffing.
			return f.String(), buf.Bytes()
		}
	}
}

// replayConn serves the original byte stream to the HTTP/2 server: it reads from a
// MultiReader of the sniffed bytes followed by the live connection, while every
// other method (Write, Close, deadlines, addresses) passes through to the embedded
// connection unchanged.
type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }
