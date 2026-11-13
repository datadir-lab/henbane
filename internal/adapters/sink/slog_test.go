package sink

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/henbane-sh/henbane/internal/ports"
)

func TestSlogSinkEmitsJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	s := NewSlogSink(logger)

	s.Emit(ports.Event{
		IP:        netip.MustParseAddr("203.0.113.9"),
		UserAgent: "GPTBot/1.1",
		Path:      "/secret",
		Action:    ports.ActionAllow,
		Tier:      ports.TierPass,
	})

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("log line is not valid JSON: %v\n%s", err, buf.String())
	}
	if got["action"] != "allow" {
		t.Errorf("action = %v, want allow", got["action"])
	}
	if got["tier"] != "pass" {
		t.Errorf("tier = %v, want pass", got["tier"])
	}
	if got["ip"] != "203.0.113.9" {
		t.Errorf("ip = %v, want 203.0.113.9", got["ip"])
	}
	if got["path"] != "/secret" {
		t.Errorf("path = %v, want /secret", got["path"])
	}
}
