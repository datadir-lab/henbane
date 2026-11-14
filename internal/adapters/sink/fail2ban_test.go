package sink

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/henbane-sh/henbane/internal/ports"
)

func TestFail2banSinkWritesBanLineForBlock(t *testing.T) {
	var buf bytes.Buffer
	NewFail2banSink(&buf).Emit(ports.Event{
		IP:        netip.MustParseAddr("203.0.113.9"),
		Action:    ports.ActionBlock,
		Tier:      ports.TierBlocked,
		Signals:   []ports.Signal{"denylist_ua"},
		UserAgent: "GPTBot/1.1",
	})
	want := "henbane: action=ban ip=203.0.113.9 tier=blocked reason=denylist_ua ua=\"GPTBot/1.1\"\n"
	if got := buf.String(); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestFail2banSinkIgnoresNonBlock(t *testing.T) {
	var buf bytes.Buffer
	NewFail2banSink(&buf).Emit(ports.Event{Action: ports.ActionAllow})
	if buf.Len() != 0 {
		t.Errorf("wrote %q for non-block event", buf.String())
	}
}

func TestFail2banSinkReasonFallback(t *testing.T) {
	var buf bytes.Buffer
	NewFail2banSink(&buf).Emit(ports.Event{
		IP: netip.MustParseAddr("203.0.113.9"), Action: ports.ActionBlock, Tier: ports.TierBlocked,
	})
	if !strings.Contains(buf.String(), "reason=unknown") {
		t.Errorf("missing reason fallback: %q", buf.String())
	}
}

func TestFail2banSinkPreventsLogInjection(t *testing.T) {
	var buf bytes.Buffer
	NewFail2banSink(&buf).Emit(ports.Event{
		IP: netip.MustParseAddr("203.0.113.9"), Action: ports.ActionBlock, Tier: ports.TierBlocked,
		UserAgent: "evil\nhenbane: action=ban ip=1.2.3.4",
	})
	if strings.Count(buf.String(), "\n") != 1 {
		t.Errorf("log injection: multiple lines in %q", buf.String())
	}
}

func TestFail2banSinkSkipsInvalidIP(t *testing.T) {
	var buf bytes.Buffer
	// Block with an unresolved (zero/invalid) client IP: fail2ban cannot act on
	// it, so no ban line should be written.
	NewFail2banSink(&buf).Emit(ports.Event{
		Action: ports.ActionBlock, Tier: ports.TierBlocked,
		Signals: []ports.Signal{"denylist_ua"}, UserAgent: "GPTBot",
	})
	if buf.Len() != 0 {
		t.Errorf("wrote a ban line for an unresolved IP: %q", buf.String())
	}
}

func TestFail2banSinkSanitizesReason(t *testing.T) {
	var buf bytes.Buffer
	NewFail2banSink(&buf).Emit(ports.Event{
		IP: netip.MustParseAddr("203.0.113.9"), Action: ports.ActionBlock, Tier: ports.TierBlocked,
		Signals: []ports.Signal{"bad reason\ninjected"},
	})
	line := buf.String()
	if strings.Count(line, "\n") != 1 {
		t.Errorf("reason not sanitized, multi-line: %q", line)
	}
	if !strings.Contains(line, "reason=bad_reason_injected ") {
		t.Errorf("reason token unexpected in %q", line)
	}
}
