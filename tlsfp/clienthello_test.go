package tlsfp

import "testing"

// buildClientHello assembles a minimal but well-formed TLS ClientHello record carrying
// the given ciphers and extension types (empty extension data), for parser testing.
func buildClientHello(ciphers []uint16, extTypes []uint16) []byte {
	body := []byte{0x03, 0x03} // legacy_version TLS 1.2
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00) // session_id: length 0

	cs := make([]byte, 0, len(ciphers)*2)
	for _, c := range ciphers {
		cs = append(cs, byte(c>>8), byte(c))
	}
	body = append(body, byte(len(cs)>>8), byte(len(cs)))
	body = append(body, cs...)

	body = append(body, 0x01, 0x00) // compression_methods: length 1, null

	exts := make([]byte, 0, len(extTypes)*4)
	for _, e := range extTypes {
		exts = append(exts, byte(e>>8), byte(e), 0x00, 0x00) // type, length 0
	}
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func TestParseClientHelloExtensions(t *testing.T) {
	rec := buildClientHello([]uint16{0x1301, 0x1302}, []uint16{0x002b, 0x0000, 0x0010, 0x000d})
	got, ok := parseClientHelloExtensions(rec)
	if !ok {
		t.Fatal("a valid ClientHello must parse")
	}
	want := []uint16{0x002b, 0x0000, 0x0010, 0x000d}
	if len(got) != len(want) {
		t.Fatalf("extensions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("extensions = %v, want %v", got, want)
		}
	}
}

func TestParseClientHelloMalformed(t *testing.T) {
	rec := buildClientHello([]uint16{0x1301}, []uint16{0x002b})

	// Every truncation must return ok=false and must never panic.
	for i := 0; i < len(rec); i++ {
		if _, ok := parseClientHelloExtensions(rec[:i]); ok {
			t.Errorf("truncated to %d bytes must not parse", i)
		}
	}

	// Non-handshake record type, empty input, and a corrupted inner length.
	if _, ok := parseClientHelloExtensions(nil); ok {
		t.Error("nil must not parse")
	}
	if _, ok := parseClientHelloExtensions([]byte{0x15, 0x03, 0x01, 0x00, 0x00}); ok {
		t.Error("an alert record (not handshake) must not parse")
	}
	bad := append([]byte(nil), rec...)
	bad[len(bad)-1] ^= 0xff // corrupt the last extension's declared length
	if _, ok := parseClientHelloExtensions(bad); ok {
		t.Error("a corrupted extension length must not parse")
	}
}
