package sink

import (
	"fmt"
	"io"

	"github.com/henbane-sh/henbane/internal/ports"
)

// Fail2banSink writes a stable one-line record for each blocked request, in the
// format the shipped fail2ban filter (deploy/fail2ban/henbane.conf) matches.
type Fail2banSink struct {
	w io.Writer
}

// NewFail2banSink returns a sink writing ban lines to w.
func NewFail2banSink(w io.Writer) *Fail2banSink { return &Fail2banSink{w: w} }

// Emit writes a ban line only for block verdicts; other events are ignored. The
// user-agent is %q-quoted, which escapes newlines/quotes and prevents a crafted
// UA from forging additional log lines.
func (s *Fail2banSink) Emit(e ports.Event) {
	if e.Action != ports.ActionBlock {
		return
	}
	reason := "unknown"
	if len(e.Signals) > 0 && e.Signals[0] != "" {
		reason = string(e.Signals[0])
	}
	fmt.Fprintf(s.w, "henbane: action=ban ip=%s tier=%s reason=%s ua=%q\n",
		e.IP, e.Tier, reason, e.UserAgent)
}

var _ ports.Sink = (*Fail2banSink)(nil)
