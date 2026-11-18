package tlsfp

import (
	"crypto/tls"
	"testing"
)

// TestJA4SpecAssembly pins the JA4 assembly against a hand-computed vector: the
// GREASE filtering, the SNI/ALPN exclusion from the JA4_c hash, the sorting of ciphers
// and extensions, the signature algorithms kept in order, the counts, and the ALPN
// characters. The hashes are built here from the expected sorted strings, so a change
// to how any list is filtered, sorted, or joined breaks the test.
func TestJA4SpecAssembly(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		// 0x0a0a is GREASE and must be dropped from every list and count.
		CipherSuites:      []uint16{0x1302, 0x1301, 0x0a0a, 0x1303},
		SupportedVersions: []uint16{0x0a0a, 0x0304, 0x0303}, // highest non-GREASE = TLS 1.3
		SignatureSchemes:  []tls.SignatureScheme{0x0403, 0x0804},
		SupportedProtos:   []string{"h2", "http/1.1"},
	}
	// Raw extension list: SNI (0000), GREASE (0a0a), ALPN (0010), then three more.
	exts := []uint16{0x0000, 0x0a0a, 0x0010, 0x002b, 0x000d, 0x0005}

	// JA4_a: t | 13 | d (SNI present) | 03 ciphers | 05 extensions | h2.
	wantA := "t13d0305h2"
	// JA4_b: sorted non-GREASE ciphers.
	wantB := hash12("1301,1302,1303")
	// JA4_c: sorted non-GREASE extensions minus SNI+ALPN, "_", sig algs in order.
	wantC := hash12("0005,000d,002b_0403,0804")
	want := wantA + "_" + wantB + "_" + wantC

	if got := JA4(chi, exts); got != want {
		t.Errorf("JA4 =\n  %q\nwant\n  %q", got, want)
	}
}

func TestJA4NoSNINoALPN(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x1301},
		SupportedVersions: []uint16{0x0303}, // TLS 1.2
	}
	exts := []uint16{0x002b} // no SNI, no ALPN
	got := JA4(chi, exts)
	// t | 12 | i (no SNI) | 01 cipher | 01 ext | 00 (no ALPN).
	wantA := "t12i0101" + "00"
	if want := wantA + "_" + hash12("1301") + "_" + hash12("002b_"); got != want {
		t.Errorf("JA4 = %q, want %q", got, want)
	}
}

func TestJA4ALPNHTTP11(t *testing.T) {
	// "http/1.1" -> first 'h', last '1' -> "h1".
	if got := ja4ALPN([]string{"http/1.1"}); got != "h1" {
		t.Errorf("ALPN http/1.1 = %q, want h1", got)
	}
	if got := ja4ALPN(nil); got != "00" {
		t.Errorf("no ALPN = %q, want 00", got)
	}
}

func TestJA4EmptyListsUsePlaceholder(t *testing.T) {
	chi := &tls.ClientHelloInfo{} // no ciphers, no versions, no sigs
	got := JA4(chi, nil)          // no extensions
	// t | 00 (unknown version) | i | 00 ciphers | 00 exts | 00 alpn, both hashes zero.
	if want := "t00i0000" + "00" + "_000000000000_000000000000"; got != want {
		t.Errorf("empty JA4 = %q, want %q", got, want)
	}
}

func TestJA4NilChi(t *testing.T) {
	if got := JA4(nil, nil); got != "" {
		t.Errorf("nil chi = %q, want empty", got)
	}
}
