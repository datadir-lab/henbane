// Package core holds Henbane's decision engine. It imports only the ports
// package and the standard library — never any adapter or transport package.
package core

import (
	"context"
	"time"

	"github.com/henbane-sh/henbane/internal/ports"
)

// clock returns the current time; overridable in tests.
type clock func() time.Time

// Engine is the decision engine. Slice 0: allow all traffic.
type Engine struct {
	now clock
}

// NewEngine builds an Engine using the real clock.
func NewEngine() *Engine {
	return &Engine{now: time.Now}
}

// Decide (Slice 0) allows every request and emits a single allow Event.
func (e *Engine) Decide(ctx context.Context, r ports.RequestView) (ports.Verdict, []ports.Event) {
	verdict := ports.Verdict{Action: ports.ActionAllow, Tier: ports.TierPass}
	ev := ports.Event{
		Time:      e.now(),
		IP:        r.IP(),
		UserAgent: r.UserAgent(),
		Path:      r.Path(),
		Action:    ports.ActionAllow,
		Tier:      ports.TierPass,
	}
	return verdict, []ports.Event{ev}
}

// Compile-time assertion that Engine satisfies ports.Engine.
var _ ports.Engine = (*Engine)(nil)
