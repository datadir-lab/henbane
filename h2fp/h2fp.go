// Package h2fp computes and carries the Akamai-style HTTP/2 client fingerprint —
// a short, stable string summarising the first frames a client sends when it opens
// an HTTP/2 connection. Those frames (SETTINGS values and order, the connection
// WINDOW_UPDATE increment, any PRIORITY frames, and the request pseudo-header
// order) are emitted deep in a client's HTTP/2 engine and are not request-level
// options, so a scraper cannot mimic a real browser's h2 fingerprint without
// replacing its whole transport. That makes it the strongest single anti-spoof
// signal: a client whose User-Agent claims Chrome but whose h2 fingerprint is the
// Go standard library's is provably not Chrome.
//
// This package is pure (standard library only, no HTTP/2 machinery): it holds the
// decoded pieces, renders the canonical string, classifies a string against a seed
// dataset of known clients, and carries a captured fingerprint from a connection to
// the request on it. The byte-level frame capture that produces the pieces needs a
// real HTTP/2 framer (golang.org/x/net/http2), which the zero-dependency core must
// not import, so it lives in the separate optional h2capture module; that module
// feeds the pieces here. Format reference: Akamai, "Passive Fingerprinting of
// HTTP/2 Clients" (Black Hat EU 2017), as implemented byte-for-byte by
// wi1dcard/fingerproxy.
package h2fp

import (
	"context"
	"strconv"
	"strings"
)

// Setting is one HTTP/2 SETTINGS parameter as the client sent it: a 16-bit
// identifier and its 32-bit value. Identifiers are kept in wire order and not
// deduplicated — the order and any repeats are part of the fingerprint.
type Setting struct {
	ID  uint16
	Val uint32
}

// Priority is one client PRIORITY frame. Weight is the RFC 7540 logical weight
// (the wire octet plus one, so 1–256), matching the Akamai convention.
type Priority struct {
	StreamID  uint32
	Exclusive bool
	DependsOn uint32
	Weight    uint32
}

// Fingerprint holds the decoded preface pieces of one client's HTTP/2 connection.
// The zero value renders to the canonical "nothing seen" string ("|00|0|").
type Fingerprint struct {
	Settings []Setting
	// WindowUpdate is the stream-0 (connection-level) WINDOW_UPDATE increment, or 0
	// when the client sent none; either way it renders as a zero-padded decimal, so
	// an absent increment is "00" (a real increment is never 0 — RFC 7540 §6.9).
	WindowUpdate uint32
	Priorities   []Priority
	// PseudoOrder is the request pseudo-headers in HPACK-decode order, each a single
	// letter: "m" (:method), "a" (:authority), "s" (:scheme), "p" (:path).
	PseudoOrder []string
}

// String renders the canonical Akamai fingerprint:
//
//	SETTINGS | WINDOW_UPDATE | PRIORITY | PSEUDO_HEADER_ORDER
//
// with SETTINGS as "id:val" joined by ";" (empty when none), WINDOW_UPDATE as a
// zero-padded decimal ("00" when absent), PRIORITY as "stream:excl:dep:weight"
// joined by "," ("0" when none), and PSEUDO_HEADER_ORDER as the letters joined by
// ",". For example Firefox renders "1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s".
func (f Fingerprint) String() string {
	var b strings.Builder

	for i, s := range f.Settings {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(strconv.FormatUint(uint64(s.ID), 10))
		b.WriteByte(':')
		b.WriteString(strconv.FormatUint(uint64(s.Val), 10))
	}
	b.WriteByte('|')

	// Zero-pad to two digits so an absent increment (value 0) renders "00"; real
	// increments are many digits and unaffected by the padding.
	if f.WindowUpdate < 10 {
		b.WriteByte('0')
	}
	b.WriteString(strconv.FormatUint(uint64(f.WindowUpdate), 10))
	b.WriteByte('|')

	if len(f.Priorities) == 0 {
		b.WriteByte('0')
	} else {
		for i, p := range f.Priorities {
			if i > 0 {
				b.WriteByte(',')
			}
			excl := "0"
			if p.Exclusive {
				excl = "1"
			}
			b.WriteString(strconv.FormatUint(uint64(p.StreamID), 10))
			b.WriteByte(':')
			b.WriteString(excl)
			b.WriteByte(':')
			b.WriteString(strconv.FormatUint(uint64(p.DependsOn), 10))
			b.WriteByte(':')
			b.WriteString(strconv.FormatUint(uint64(p.Weight), 10))
		}
	}
	b.WriteByte('|')

	b.WriteString(strings.Join(f.PseudoOrder, ","))
	return b.String()
}

// --- classification ---

// knownBrowserOrders is the set of request pseudo-header orders mainstream browsers
// emit over HTTP/2 (measured, Nov 2026). A browser engine has one canonical order
// that rarely changes across versions, so this set is small and slow-drifting —
// which is what makes "the order is not in this set" a low-false-positive spoofing
// signal. It is the primary discriminator precisely because it drifts far less than
// the SETTINGS values. Extend it when a new mainstream engine ships a different order.
var knownBrowserOrders = map[string]bool{
	"m,a,s,p": true, // Chrome, Chromium, Edge, Opera
	"m,p,a,s": true, // Firefox
	"m,s,p,a": true, // Safari / WebKit (macOS and iOS)
}

// libraryHeaderTableSize is the bare RFC 7540 default HPACK dynamic-table size
// (SETTINGS id 1). Mainstream browsers never send it — Chrome, Edge, and Firefox
// send 65536, Safari omits id 1 — but the Python `h2` library (httpx, Scrapy, and
// others built on it) defaults to exactly 4096. It is the tell that catches those
// clients even when they copy a browser's pseudo-header order, which httpx does
// (m,a,s,p, identical to Chrome). Only this specific value is flagged, not "anything
// but 65536", to avoid false-positiving a future browser that tweaks its table size.
const libraryHeaderTableSize = 4096

// PseudoOrder returns the pseudo-header-order field (the 4th, pipe-separated field)
// of an Akamai fingerprint string, or "" if fp is empty or malformed.
func PseudoOrder(fp string) string {
	parts := strings.Split(fp, "|")
	if len(parts) != 4 {
		return ""
	}
	return parts[3]
}

// IsBrowserPseudoOrder reports whether order is a pseudo-header order a mainstream
// browser emits over HTTP/2.
func IsBrowserPseudoOrder(order string) bool { return knownBrowserOrders[order] }

// ContradictsBrowser reports whether fp is a usable HTTP/2 fingerprint that no
// mainstream browser would produce — strong evidence a client carrying it is not the
// browser it claims to be. Two independent tells, either sufficient:
//
//   - a pseudo-header order no browser emits (e.g. the Go standard library leads with
//     :authority, "a,m,p,s", which no browser does; curl and Java use "m,s,a,p"); or
//   - an HPACK table size (SETTINGS id 1) equal to the bare RFC default 4096 —
//     catching h2-library clients (httpx, Scrapy) that default to it even while
//     copying Chrome's pseudo-header order.
//
// An empty or malformed fingerprint, or one with a browser pseudo-header order and
// no library table size, returns false: unknown is never treated as a contradiction.
func ContradictsBrowser(fp string) bool {
	parts := strings.Split(fp, "|")
	if len(parts) != 4 {
		return false
	}
	if order := parts[3]; order != "" && !knownBrowserOrders[order] {
		return true
	}
	if ts, ok := settingValue(parts[0], 1); ok && ts == libraryHeaderTableSize {
		return true
	}
	return false
}

// settingValue returns the value of SETTINGS parameter id in a fingerprint's
// SETTINGS field ("id:val;id:val;…"), and whether it was present.
func settingValue(settings string, id uint16) (uint32, bool) {
	if settings == "" {
		return 0, false
	}
	for _, pair := range strings.Split(settings, ";") {
		k, v, ok := strings.Cut(pair, ":")
		if !ok {
			continue
		}
		pid, err := strconv.ParseUint(k, 10, 16)
		if err != nil || uint16(pid) != id {
			continue
		}
		val, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(val), true
	}
	return 0, false
}

// --- carry: connection capture -> request ---

type ctxKey struct{}

// WithFingerprint returns a copy of ctx carrying the HTTP/2 fingerprint string fp.
// The h2capture module calls this when it dispatches a request so the engine's
// RequestView can read the fingerprint back with FromContext.
func WithFingerprint(ctx context.Context, fp string) context.Context {
	return context.WithValue(ctx, ctxKey{}, fp)
}

// FromContext returns the HTTP/2 fingerprint captured for the request's connection,
// or "" if HTTP/2 fingerprinting was not wired (e.g. the zero-dep core on its own,
// a plain-HTTP or HTTP/1.1 request, or Henbane behind a protocol-terminating proxy).
func FromContext(ctx context.Context) string {
	fp, _ := ctx.Value(ctxKey{}).(string)
	return fp
}
