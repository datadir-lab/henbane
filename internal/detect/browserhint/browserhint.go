// Package browserhint flags requests whose User-Agent claims a mainstream browser
// but which omit the Sec-Fetch-Site metadata header that every modern browser
// sends on every request — a cheap, privacy-respecting signal that a non-browser
// client is wearing a browser User-Agent. It emits Suspect (→ a proof-of-work
// challenge), never a block, so a mislabelled real client pays only a brief toll.
package browserhint

import (
	"strings"

	"github.com/datadir-lab/henbane/internal/ports"
)

// Detector reports a browser-UA / fetch-metadata mismatch.
type Detector struct{}

// New returns a browser-hint detector.
func New() *Detector { return &Detector{} }

// Name identifies the detector.
func (d *Detector) Name() string { return "browser_hint" }

// Inspect fires Suspect when the UA claims a mainstream browser but the request
// lacks Sec-Fetch-Site.
func (d *Detector) Inspect(r ports.RequestView) (ports.Result, bool) {
	if !claimsBrowser(r.UserAgent()) {
		return ports.Result{}, false
	}
	if r.Header("Sec-Fetch-Site") != "" {
		return ports.Result{}, false // real browsers send fetch metadata
	}
	return ports.Result{Signal: "browser_hint", Tier: ports.TierSuspect}, true
}

// claimsBrowser reports whether ua looks like a mainstream graphical browser:
// a Mozilla-prefixed string carrying a known engine/product token. Bots that do
// not copy a full browser UA fall through (and are handled by other detectors).
func claimsBrowser(ua string) bool {
	if !strings.HasPrefix(ua, "Mozilla/") {
		return false
	}
	for _, tok := range []string{"Chrome/", "Firefox/", "Safari/", "Edg/", "OPR/"} {
		if strings.Contains(ua, tok) {
			return true
		}
	}
	return false
}

var _ ports.Detector = (*Detector)(nil)
