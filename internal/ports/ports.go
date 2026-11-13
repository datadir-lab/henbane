// Package ports defines Henbane's transport-agnostic domain types and
// interfaces. It imports only the standard library and must never import
// any adapter or transport package.
package ports

import (
	"context"
	"net/netip"
	"time"
)

type Action int

const (
	ActionAllow Action = iota
	ActionChallenge
	ActionTarpit
	ActionPoison
	ActionBlock
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionChallenge:
		return "challenge"
	case ActionTarpit:
		return "tarpit"
	case ActionPoison:
		return "poison"
	case ActionBlock:
		return "block"
	default:
		return "unknown"
	}
}

type Tier int

const (
	TierPass Tier = iota
	TierSuspect
	TierConfirmed
	TierBlocked
)

func (t Tier) String() string {
	switch t {
	case TierPass:
		return "pass"
	case TierSuspect:
		return "suspect"
	case TierConfirmed:
		return "confirmed"
	case TierBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

// Signal names a classifier signal that fired (e.g. "honeypot", "known_asn").
type Signal string

// Verdict is the engine's decision for a request.
type Verdict struct {
	Action  Action
	Tier    Tier
	Reasons []Signal
}

// Event is the structured record emitted for a decision and consumed by sinks.
type Event struct {
	Time        time.Time
	IP          netip.Addr
	UserAgent   string
	Path        string
	Action      Action
	Tier        Tier
	Signals     []Signal
	PoWMillis   int64
	PoisonBytes int64
}

// RequestView is a read-only, transport-agnostic view of an inbound request.
type RequestView interface {
	IP() netip.Addr
	UserAgent() string
	Method() string
	Path() string
	Header(name string) string
}

// Sink consumes decision Events. Implementations must never block the request
// path or return request-failing errors.
type Sink interface {
	Emit(Event)
}

// Engine decides what to do with a request.
type Engine interface {
	Decide(ctx context.Context, r RequestView) (Verdict, []Event)
}
