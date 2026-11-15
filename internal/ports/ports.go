// Package ports defines Henbane's transport-agnostic domain types and
// interfaces. It imports only the standard library and must never import
// any adapter or transport package.
package ports

import (
	"context"
	"net/netip"
	"time"
)

// Action is the disposition the engine assigns to a request.
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

// Tier is the suspicion level the classifier assigns to a request.
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
	Time           time.Time
	IP             netip.Addr
	UserAgent      string
	Path           string
	Action         Action
	Tier           Tier
	Signals        []Signal
	PoWMillis      int64
	PoisonBytes    int64
	TLSFingerprint string
}

// RequestView is a read-only, transport-agnostic view of an inbound request.
type RequestView interface {
	IP() netip.Addr
	UserAgent() string
	Method() string
	Path() string
	Header(name string) string
}

// TLSFingerprinter is an optional RequestView capability: a coarse, stable TLS
// client fingerprint captured when Henbane terminates TLS itself. A RequestView
// may implement it; consumers type-assert for it and treat an absent or empty
// value as "unknown" (e.g. plain HTTP, or Henbane behind a TLS-terminating proxy).
type TLSFingerprinter interface {
	TLSFingerprint() string
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

// Result is what a Detector returns when it fires.
type Result struct {
	Signal Signal
	Tier   Tier
}

// Detector inspects a request and may fire with a Signal and the Tier it
// implies. Detectors may hold state and have side effects (e.g. a honeypot
// flagging a client). Name identifies the detector for logging/config.
type Detector interface {
	Name() string
	Inspect(r RequestView) (Result, bool)
}

// Poisoner produces deterministic plain-text poison paragraphs for a maze page.
// Plain text ONLY: the maze template escapes it, so a Poisoner can never emit
// raw HTML (zero injection surface). Implementations must be deterministic for a
// given seed, concurrency-safe, and bounded in CPU and output size. n is the
// requested paragraph count, already clamped by the caller.
type Poisoner interface {
	Name() string
	Paragraphs(seed int64, n int) []string
}
