package pow

import (
	"crypto/sha256"
	"math/bits"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

var (
	ip1 = netip.MustParseAddr("203.0.113.7")
	ip2 = netip.MustParseAddr("203.0.113.8")
	t0  = time.Unix(1_700_000_000, 0)
)

func testGate() *Gate {
	return New([]byte("0123456789abcdef0123456789abcdef"), 12, 5*time.Minute, time.Hour)
}

// solve independently reproduces the client's work: find a decimal solution
// whose sha256(challenge+solution) has >= difficulty leading zero bits.
func solve(t *testing.T, g *Gate, challenge string) string {
	t.Helper()
	for i := 0; i < 1<<24; i++ {
		sol := strconv.Itoa(i)
		d := sha256.Sum256([]byte(challenge + sol))
		if leadingZeros(d[:]) >= g.DifficultyBits() {
			return sol
		}
	}
	t.Fatalf("no solution found under difficulty %d", g.DifficultyBits())
	return ""
}

func leadingZeros(b []byte) int {
	n := 0
	for _, c := range b {
		if c == 0 {
			n += 8
			continue
		}
		n += bits.LeadingZeros8(c)
		break
	}
	return n
}

func TestIssueSolveVerifyRoundTrip(t *testing.T) {
	g := testGate()
	ch := g.Issue(ip1, t0)
	sol := solve(t, g, ch)
	tok, ok := g.VerifySolution(ch, sol, ip1, t0)
	if !ok {
		t.Fatal("valid solution rejected")
	}
	if !g.ValidAccess(tok, ip1, t0) {
		t.Fatal("issued access token not accepted")
	}
}

func TestWrongSolutionRejected(t *testing.T) {
	g := testGate()
	ch := g.Issue(ip1, t0)
	if _, ok := g.VerifySolution(ch, "0", ip1, t0); ok {
		// "0" is overwhelmingly unlikely to meet difficulty 12
		t.Error("solution below difficulty accepted")
	}
}

func TestForgedChallengeRejected(t *testing.T) {
	g := testGate()
	ch := g.Issue(ip1, t0)
	sol := solve(t, g, ch)
	// Tamper with the signed challenge.
	forged := ch[:len(ch)-2] + "AA"
	if _, ok := g.VerifySolution(forged, sol, ip1, t0); ok {
		t.Error("forged challenge accepted")
	}
	// Garbage.
	if _, ok := g.VerifySolution("not-a-token", "1", ip1, t0); ok {
		t.Error("garbage challenge accepted")
	}
}

func TestExpiredChallengeRejected(t *testing.T) {
	g := testGate()
	ch := g.Issue(ip1, t0)
	sol := solve(t, g, ch)
	later := t0.Add(6 * time.Minute) // > challengeTTL
	if _, ok := g.VerifySolution(ch, sol, ip1, later); ok {
		t.Error("expired challenge accepted")
	}
}

func TestIPBoundChallenge(t *testing.T) {
	g := testGate()
	ch := g.Issue(ip1, t0)
	sol := solve(t, g, ch)
	if _, ok := g.VerifySolution(ch, sol, ip2, t0); ok {
		t.Error("challenge solved from a different IP accepted")
	}
}

func TestAccessTokenExpiryAndIP(t *testing.T) {
	g := testGate()
	ch := g.Issue(ip1, t0)
	tok, _ := g.VerifySolution(ch, solve(t, g, ch), ip1, t0)
	if g.ValidAccess(tok, ip2, t0) {
		t.Error("access token accepted from a different IP")
	}
	if g.ValidAccess(tok, ip1, t0.Add(2*time.Hour)) {
		t.Error("expired access token accepted")
	}
	if g.ValidAccess("garbage", ip1, t0) {
		t.Error("garbage access token accepted")
	}
	// A challenge token must not be usable as an access token (domain separation).
	if g.ValidAccess(ch, ip1, t0) {
		t.Error("challenge token accepted as access token")
	}
}

func TestDifficultyClamp(t *testing.T) {
	if New(nil, 2, time.Minute, time.Hour).DifficultyBits() != 8 {
		t.Error("difficulty < 8 not clamped to 8")
	}
	if New(nil, 99, time.Minute, time.Hour).DifficultyBits() != 32 {
		t.Error("difficulty > 32 not clamped to 32")
	}
}

func TestDifferentSecretsReject(t *testing.T) {
	g := testGate()
	other := New([]byte("ffffffffffffffffffffffffffffffff"), 12, 5*time.Minute, time.Hour)
	ch := g.Issue(ip1, t0)
	sol := solve(t, g, ch)
	if _, ok := other.VerifySolution(ch, sol, ip1, t0); ok {
		t.Error("challenge signed by a different secret accepted")
	}
}
