// Package core holds Henbane's decision engine. It imports only the ports
// package and the standard library — never any adapter, config, or transport
// package.
package core

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/henbane-sh/henbane/internal/ports"
)

// Policy is the classifier configuration: the operator denylist.
type Policy struct {
	DenyCIDRs      []netip.Prefix
	DenyUserAgents []string // matched case-insensitively as substrings
}

type clock func() time.Time

// Engine is the decision engine.
type Engine struct {
	denyCIDRs   []netip.Prefix
	denyUALower []string // lowercased, non-empty deny user-agents (precomputed)
	now         clock
}

// NewEngine builds an Engine applying policy. A zero Policy allows all traffic.
// Deny user-agents are lowercased once here rather than per request.
func NewEngine(policy Policy) *Engine {
	lower := make([]string, 0, len(policy.DenyUserAgents))
	for _, ua := range policy.DenyUserAgents {
		if ua != "" {
			lower = append(lower, strings.ToLower(ua))
		}
	}
	return &Engine{denyCIDRs: policy.DenyCIDRs, denyUALower: lower, now: time.Now}
}

// Decide blocks denylisted clients (by IP/CIDR, then user-agent) and otherwise
// allows the request.
func (e *Engine) Decide(ctx context.Context, r ports.RequestView) (ports.Verdict, []ports.Event) {
	if ip := r.IP().Unmap(); ip.IsValid() {
		for _, p := range e.denyCIDRs {
			if p.Contains(ip) {
				return e.emit(r, ports.ActionBlock, ports.TierBlocked, []ports.Signal{"denylist_ip"})
			}
		}
	}
	if ua := r.UserAgent(); ua != "" {
		lower := strings.ToLower(ua)
		for _, deny := range e.denyUALower {
			if strings.Contains(lower, deny) {
				return e.emit(r, ports.ActionBlock, ports.TierBlocked, []ports.Signal{"denylist_ua"})
			}
		}
	}
	return e.emit(r, ports.ActionAllow, ports.TierPass, nil)
}

func (e *Engine) emit(r ports.RequestView, action ports.Action, tier ports.Tier, signals []ports.Signal) (ports.Verdict, []ports.Event) {
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

var _ ports.Engine = (*Engine)(nil)
