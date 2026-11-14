package sink

import (
	"fmt"
	"io"
	"strings"

	"github.com/datadir-lab/henbane/internal/ports"
)

// Fail2banSink writes a stable one-line record for each blocked request, in the
// format the shipped fail2ban filter (deploy/fail2ban/henbane.conf) matches.
type Fail2banSink struct {
	w io.Writer
}

// NewFail2banSink returns a sink writing ban lines to w.
func NewFail2banSink(w io.Writer) *Fail2banSink { return &Fail2banSink{w: w} }

// Emit writes a ban line only for block verdicts with a resolved client IP;
// other events are ignored (fail2ban cannot act on an unknown IP). The
// user-agent is %q-quoted and the reason is reduced to a safe token, so neither
// a crafted UA nor a future non-constant signal can forge extra log lines.
func (s *Fail2banSink) Emit(e ports.Event) {
	if e.Action != ports.ActionBlock || !e.IP.IsValid() {
		return
	}
	reason := "unknown"
	if len(e.Signals) > 0 && e.Signals[0] != "" {
		reason = safeToken(string(e.Signals[0]))
	}
	fmt.Fprintf(s.w, "henbane: action=ban ip=%s tier=%s reason=%s ua=%q\n",
		e.IP, e.Tier, reason, e.UserAgent)
}

// safeToken maps anything outside [A-Za-z0-9_-] to '_', guaranteeing the reason
// field can never introduce whitespace or newlines into the ban line.
func safeToken(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, s)
}

var _ ports.Sink = (*Fail2banSink)(nil)
