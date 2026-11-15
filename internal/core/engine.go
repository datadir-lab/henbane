// Package core holds Henbane's decision engine: a composer over a list of
// detectors. It imports only the ports package and the standard library.
package core

import (
	"context"
	"time"

	"github.com/datadir-lab/henbane/internal/ports"
)

type clock func() time.Time

// Engine composes verifiers and detectors into a decision.
type Engine struct {
	verifiers []ports.Verifier
	detectors []ports.Detector
	now       clock
}

// NewEngine builds an Engine running the given detectors in order. With no
// detectors it allows all traffic.
func NewEngine(detectors ...ports.Detector) *Engine {
	return &Engine{detectors: detectors, now: time.Now}
}

// WithVerifiers sets verifiers that run before the detectors; the first one to
// fire forces the verdict (allowing a proven good bot or blocking an impostor).
// It returns the engine for chaining.
func (e *Engine) WithVerifiers(verifiers ...ports.Verifier) *Engine {
	e.verifiers = verifiers
	return e
}

// Decide runs every detector, raising the tier to the highest that fired and
// collecting their signals, then maps the tier to an action.
func (e *Engine) Decide(ctx context.Context, r ports.RequestView) (ports.Verdict, []ports.Event) {
	// Verifiers run first and short-circuit: a proven good bot is allowed
	// (bypassing the detectors), a proven impostor is blocked.
	for _, vf := range e.verifiers {
		if sig, tier, ok := vf.Verify(r); ok {
			action := actionForTier(tier)
			v := ports.Verdict{Action: action, Tier: tier, Reasons: []ports.Signal{sig}, Allowlisted: tier == ports.TierPass}
			return v, []ports.Event{e.event(r, action, tier, []ports.Signal{sig})}
		}
	}

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
	return v, []ports.Event{e.event(r, action, tier, signals)}
}

// event builds the decision record, enriching it with the client's TLS
// fingerprint when the RequestView exposes one.
func (e *Engine) event(r ports.RequestView, action ports.Action, tier ports.Tier, signals []ports.Signal) ports.Event {
	ev := ports.Event{
		Time:      e.now(),
		IP:        r.IP(),
		UserAgent: r.UserAgent(),
		Path:      r.Path(),
		Action:    action,
		Tier:      tier,
		Signals:   signals,
	}
	if f, ok := r.(ports.TLSFingerprinter); ok {
		ev.TLSFingerprint = f.TLSFingerprint()
	}
	return ev
}

// actionForTier maps a tier to its action. Suspect clients get a proof-of-work
// Challenge; Confirmed clients are detained in the labyrinth (Tarpit);
// denylisted/blocked clients get a 403.
func actionForTier(t ports.Tier) ports.Action {
	switch t {
	case ports.TierPass:
		return ports.ActionAllow
	case ports.TierSuspect:
		return ports.ActionChallenge
	case ports.TierConfirmed:
		return ports.ActionTarpit
	default:
		return ports.ActionBlock
	}
}

var _ ports.Engine = (*Engine)(nil)
