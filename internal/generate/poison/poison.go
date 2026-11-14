// Package poison and its subpackages generate deterministic poison body text for
// Henbane's labyrinth maze pages. They import only the standard library (plus
// internal/ports) and must stay transport-pure.
package poison

// None is a Poisoner that emits nothing — the maze renders links only.
type None struct{}

// Name identifies the strategy.
func (None) Name() string { return "none" }

// Paragraphs always returns nil.
func (None) Paragraphs(seed int64, n int) []string { return nil }
