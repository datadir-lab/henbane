package tlsfp

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// JA4 computes the FoxIO JA4 TLS client fingerprint from the ClientHelloInfo that Go
// exposes plus the raw extension-type list (which the standard library hides and
// clienthello.go recovers). The format is `JA4_a_JA4_b_JA4_c`, e.g.
// `t13d1516h2_8daaf6152771_e5627efa2ab1`. It follows the published specification; the
// common case (a real browser or client, which always has ciphers, extensions, and
// signature algorithms) is exercised by the vector tests. Returns "" if chi is nil.
//
// JA4 is the industry-standard format, so a fingerprint produced here is comparable
// with other tools' JA4 output: an operator can denylist a JA4 string from a threat
// feed. Like every fingerprint it is forgeable by a dedicated impersonation toolkit
// (uTLS, curl-impersonate), so it feeds the fusion score, never an outright block.
func JA4(chi *tls.ClientHelloInfo, extensions []uint16) string {
	if chi == nil {
		return ""
	}

	// --- JA4_a: t <version> <d|i> <cipher count> <ext count> <alpn> ---
	// Counts exclude GREASE but not SNI/ALPN; only the JA4_c hash drops SNI/ALPN.
	ciphers := nonGREASE(chi.CipherSuites, nil)
	extsAll := nonGREASE(extensions, nil)
	sni := "i"
	for _, e := range extensions {
		if e == 0x0000 { // server_name
			sni = "d"
			break
		}
	}
	a := "t" + ja4Version(chi.SupportedVersions) + sni +
		twoDigit(len(ciphers)) + twoDigit(len(extsAll)) + ja4ALPN(chi.SupportedProtos)

	// --- JA4_b: sha256(sorted ciphers)[:12], or the zero placeholder when none ---
	b := "000000000000"
	if len(ciphers) > 0 {
		b = hash12(hexOf(sortU16(ciphers)))
	}

	// --- JA4_c: sha256(sorted extensions (SNI+ALPN dropped) "_" sig algs in order)[:12] ---
	extsForHash := nonGREASE(extensions, map[uint16]bool{0x0000: true, 0x0010: true})
	c := "000000000000"
	if len(extsForHash) > 0 {
		var sigs []uint16
		for _, s := range chi.SignatureSchemes {
			if !isGREASE(uint16(s)) {
				sigs = append(sigs, uint16(s))
			}
		}
		c = hash12(hexOf(sortU16(extsForHash)) + "_" + hexOf(sigs))
	}

	return a + "_" + b + "_" + c
}

// ja4Version maps the highest non-GREASE supported version to its JA4 token.
func ja4Version(versions []uint16) string {
	best := uint16(0)
	for _, v := range versions {
		if !isGREASE(v) && v > best {
			best = v
		}
	}
	switch best {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	default:
		return "00"
	}
}

// ja4ALPN returns the first and last character of the first ALPN value, using the hex
// of the first/last byte when either is not ASCII-alphanumeric, or "00" if there is
// no ALPN.
func ja4ALPN(protos []string) string {
	if len(protos) == 0 || protos[0] == "" {
		return "00"
	}
	p := protos[0]
	first, last := p[0], p[len(p)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	h := hex.EncodeToString([]byte{first, last}) // 4 hex chars
	return string([]byte{h[0], h[3]})
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// nonGREASE returns the values with GREASE (and any in drop) removed, preserving order.
func nonGREASE(vs []uint16, drop map[uint16]bool) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		if isGREASE(v) || drop[v] {
			continue
		}
		out = append(out, v)
	}
	return out
}

func sortU16(vs []uint16) []uint16 {
	out := append([]uint16(nil), vs...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func hexOf(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

// twoDigit renders n as a 2-digit decimal string, capped at 99 per the JA4 spec.
func twoDigit(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

// hash12 returns the first 12 lowercase hex characters of sha256(s).
func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
