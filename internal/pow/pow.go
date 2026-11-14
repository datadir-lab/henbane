// Package pow implements a stateless, Hashcash-style proof-of-work gate. Both the
// challenge and the access token are HMAC-signed, IP-bound, and self-expiring, so
// no server-side state is kept. It imports only the standard library and stays
// transport-pure. Pass the current time in explicitly for deterministic testing.
package pow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math/bits"
	"net/netip"
	"time"
)

const (
	domainChallenge = "c"
	domainAccess    = "a"
	nonceLen        = 8
)

var enc = base64.RawURLEncoding

// Gate issues and verifies proof-of-work challenges and access tokens.
type Gate struct {
	secret     []byte
	difficulty int // required leading zero bits
	challTTL   time.Duration
	accessTTL  time.Duration
}

// New returns a Gate. difficultyBits (leading zero bits of the solution hash) is
// clamped to [8, 32].
func New(secret []byte, difficultyBits int, challengeTTL, accessTTL time.Duration) *Gate {
	switch {
	case difficultyBits < 8:
		difficultyBits = 8
	case difficultyBits > 32:
		difficultyBits = 32
	}
	return &Gate{secret: secret, difficulty: difficultyBits, challTTL: challengeTTL, accessTTL: accessTTL}
}

// DifficultyBits is the required number of leading zero bits (for the solver page).
func (g *Gate) DifficultyBits() int { return g.difficulty }

// Issue returns a challenge token bound to ip and expiring at now+challengeTTL.
func (g *Gate) Issue(ip netip.Addr, now time.Time) string {
	payload := make([]byte, nonceLen+16)
	_, _ = rand.Read(payload[:nonceLen])
	binary.BigEndian.PutUint64(payload[nonceLen:], uint64(now.Add(g.challTTL).Unix()))
	copy(payload[nonceLen+8:], g.ipHash(ip))
	return g.sign(domainChallenge, payload)
}

// VerifySolution checks that solution solves challenge (for this ip, before expiry)
// and, if so, returns a fresh access token. ok is false on any failure.
func (g *Gate) VerifySolution(challenge, solution string, ip netip.Addr, now time.Time) (string, bool) {
	payload, ok := g.open(domainChallenge, challenge)
	if !ok || len(payload) != nonceLen+16 {
		return "", false
	}
	if now.Unix() >= int64(binary.BigEndian.Uint64(payload[nonceLen:])) {
		return "", false
	}
	if !hmac.Equal(payload[nonceLen+8:], g.ipHash(ip)) {
		return "", false
	}
	d := sha256.Sum256([]byte(challenge + solution))
	if leadingZeroBits(d[:]) < g.difficulty {
		return "", false
	}
	return g.issueAccess(ip, now), true
}

// ValidAccess reports whether token is a valid, unexpired access token for ip.
func (g *Gate) ValidAccess(token string, ip netip.Addr, now time.Time) bool {
	payload, ok := g.open(domainAccess, token)
	if !ok || len(payload) != 16 {
		return false
	}
	if now.Unix() >= int64(binary.BigEndian.Uint64(payload[:8])) {
		return false
	}
	return hmac.Equal(payload[8:], g.ipHash(ip))
}

func (g *Gate) issueAccess(ip netip.Addr, now time.Time) string {
	payload := make([]byte, 16)
	binary.BigEndian.PutUint64(payload, uint64(now.Add(g.accessTTL).Unix()))
	copy(payload[8:], g.ipHash(ip))
	return g.sign(domainAccess, payload)
}

func (g *Gate) sign(domain string, payload []byte) string {
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(g.mac(domain, payload))
}

// open verifies the token's HMAC (constant time) under domain and returns its payload.
func (g *Gate) open(domain, token string) ([]byte, bool) {
	dot := -1
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return nil, false
	}
	payload, err := enc.DecodeString(token[:dot])
	if err != nil {
		return nil, false
	}
	mac, err := enc.DecodeString(token[dot+1:])
	if err != nil {
		return nil, false
	}
	if !hmac.Equal(mac, g.mac(domain, payload)) {
		return nil, false
	}
	return payload, true
}

func (g *Gate) mac(domain string, payload []byte) []byte {
	h := hmac.New(sha256.New, g.secret)
	h.Write([]byte(domain))
	h.Write(payload)
	return h.Sum(nil)
}

// ipHash binds a token to a client IP without storing the raw address.
func (g *Gate) ipHash(ip netip.Addr) []byte {
	a := ip.As16()
	h := hmac.New(sha256.New, g.secret)
	h.Write([]byte("ip"))
	h.Write(a[:])
	return h.Sum(nil)[:8]
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, c := range b {
		if c == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(c)
	}
	return n
}
