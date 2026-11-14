package poison

import (
	"testing"

	"github.com/datadir-lab/henbane/internal/ports"
)

var _ ports.Poisoner = None{}

func TestNoneName(t *testing.T) {
	if got := (None{}).Name(); got != "none" {
		t.Errorf("Name() = %q, want none", got)
	}
}

func TestNoneParagraphsEmpty(t *testing.T) {
	if got := (None{}).Paragraphs(42, 5); got != nil {
		t.Errorf("Paragraphs(42,5) = %v, want nil", got)
	}
}
