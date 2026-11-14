// Package core holds Henbane's decision engine: a composer over a list of
// detectors. It imports only the ports package and the standard library.
package core

import (
	"context"
	"time"

	"github.com/henbane-sh/henbane/internal/ports"
)

type clock func() time.Time

// Engine composes detectors into a decision.
type Engine struct {
	detectors []ports.Detector
	now       clock
}

// NewEngine builds an Engine running the given detectors in order. With no
// detectors it allows all traffic.
func NewEngine(detectors ...ports.Detector) *Engine {
	return &Engine{detectors: detectors, now: time.Now}
}

// Decide runs every detector, raising the tier to the highest that fired and
// collecting their signals, then maps the tier to an action.
func (e *Engine) Decide(ctx context.Context, r ports.RequestView) (ports.Verdict, []ports.Event) {
	tier := ports.TierPass
	var signals []ports.Signal
	for _, d := range e.detectors {
		if res, fired := d.Inspect(r); fired {
			signals = append(signals, res.Signal)
			if res.Tier > tier {
				tier = res.Tier
			}
		}
	}
	action := actionForTier(tier)
	v := ports.Verdict{Action: action, Tier: tier, Reasons: signals}
	ev := ports.Event{
		Time:      e.now(),
		IP:        r.IP(),
		UserAgent: r.UserAgent(),
		Path:      r.Path(),
		Action:    action,
		Tier:      tier,
		Signals:   signals,
	}
	return v, []ports.Event{ev}
}

// actionForTier maps a tier to its action. Interim: anything above Pass blocks,
// until later slices add challenge (Suspect) and tarpit/poison (Confirmed).
func actionForTier(t ports.Tier) ports.Action {
	if t == ports.TierPass {
		return ports.ActionAllow
	}
	return ports.ActionBlock
}

var _ ports.Engine = (*Engine)(nil)
