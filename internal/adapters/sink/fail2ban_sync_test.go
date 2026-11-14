package sink

import (
	"bytes"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/datadir-lab/henbane/internal/ports"
)

// TestFail2banFilterMatchesSinkOutput keeps deploy/fail2ban/henbane.conf in sync
// with the line the sink emits: it extracts the shipped failregex, substitutes
// fail2ban's <HOST> token with an IP-capturing group, and asserts it matches a
// real ban line and captures the IP.
func TestFail2banFilterMatchesSinkOutput(t *testing.T) {
	data, err := os.ReadFile("../../../deploy/fail2ban/henbane.conf")
	if err != nil {
		t.Fatalf("read filter: %v", err)
	}
	var failregex string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "failregex") {
			_, v, _ := strings.Cut(line, "=")
			failregex = strings.TrimSpace(v)
			break
		}
	}
	if failregex == "" {
		t.Fatal("no failregex found in henbane.conf")
	}
	// fail2ban's <HOST> matches an IP (or host); approximate with an IP capture.
	goRe := strings.ReplaceAll(failregex, "<HOST>", `(?P<host>[0-9A-Fa-f:.]+)`)
	re, err := regexp.Compile(goRe)
	if err != nil {
		t.Fatalf("compile translated failregex %q: %v", goRe, err)
	}

	var buf bytes.Buffer
	NewFail2banSink(&buf).Emit(ports.Event{
		IP: netip.MustParseAddr("203.0.113.9"), Action: ports.ActionBlock,
		Tier: ports.TierBlocked, Signals: []ports.Signal{"denylist_ua"}, UserAgent: "GPTBot/1.1",
	})
	line := strings.TrimRight(buf.String(), "\n")

	m := re.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("shipped failregex does not match sink line\nregex: %s\nline:  %s", goRe, line)
	}
	if host := m[re.SubexpIndex("host")]; host != "203.0.113.9" {
		t.Errorf("captured host = %q, want 203.0.113.9", host)
	}
}
