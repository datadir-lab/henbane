package tlsfp

// parseClientHelloExtensions recovers the extension-type list from a raw TLS
// ClientHello, which crypto/tls parses but does not expose. JA4 needs it (for the
// extension count and the JA4_c hash); everything else comes from ClientHelloInfo.
//
// The input is the raw bytes read from the connection, starting at the TLS record
// header. Parsing is strictly bounds-checked: any truncation or malformed length
// returns ok=false, never a panic, so a hostile or unusual ClientHello degrades to no
// JA4 (the coarse fingerprint is used instead) rather than crashing the handshake
// goroutine. A ClientHello fragmented across multiple TLS records is not reassembled
// (rare in practice); it simply yields ok=false.
func parseClientHelloExtensions(b []byte) (exts []uint16, ok bool) {
	// TLS record header: type(1)=0x16 handshake, version(2), length(2).
	if len(b) < 5 || b[0] != 0x16 {
		return nil, false
	}
	b = b[5:]

	// Handshake header: type(1)=0x01 client_hello, length(3).
	if len(b) < 4 || b[0] != 0x01 {
		return nil, false
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	if len(b) < hsLen {
		return nil, false // ClientHello spans multiple records; not handled
	}
	b = b[:hsLen]

	// legacy_version(2) + random(32)
	if len(b) < 34 {
		return nil, false
	}
	b = b[34:]

	// legacy_session_id: 1-byte length vector.
	if b, ok = skipVec(b, 1); !ok {
		return nil, false
	}
	// cipher_suites: 2-byte length vector.
	if b, ok = skipVec(b, 2); !ok {
		return nil, false
	}
	// legacy_compression_methods: 1-byte length vector.
	if b, ok = skipVec(b, 1); !ok {
		return nil, false
	}

	// extensions: optional 2-byte length vector, then {type(2), len(2), data} entries.
	if len(b) == 0 {
		return nil, true // no extensions block is valid (empty list)
	}
	if len(b) < 2 {
		return nil, false
	}
	extTotal := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < extTotal {
		return nil, false
	}
	b = b[:extTotal]
	for len(b) >= 4 {
		etype := uint16(b[0])<<8 | uint16(b[1])
		elen := int(b[2])<<8 | int(b[3])
		if len(b) < 4+elen {
			return nil, false
		}
		exts = append(exts, etype)
		b = b[4+elen:]
	}
	if len(b) != 0 {
		return nil, false // trailing bytes inside the extensions block: malformed
	}
	return exts, true
}

// skipVec consumes a length-prefixed vector whose length field is lenBytes (1 or 2)
// wide, returning the remaining bytes. ok is false on truncation.
func skipVec(b []byte, lenBytes int) ([]byte, bool) {
	if len(b) < lenBytes {
		return nil, false
	}
	n := 0
	for i := 0; i < lenBytes; i++ {
		n = n<<8 | int(b[i])
	}
	b = b[lenBytes:]
	if len(b) < n {
		return nil, false
	}
	return b[n:], true
}
