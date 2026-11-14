package main

import (
	"strings"
	"testing"
)

func TestVersionStringIncludesAllFields(t *testing.T) {
	version, commit, date = "1.2.3", "abc1234", "2026-11-14"
	got := versionString()
	for _, want := range []string{"henbane", "1.2.3", "abc1234", "2026-11-14"} {
		if !strings.Contains(got, want) {
			t.Errorf("versionString()=%q, missing %q", got, want)
		}
	}
}

func TestMaybePrintVersionPrintsAndReports(t *testing.T) {
	version = "9.9.9"
	var buf strings.Builder
	if !maybePrintVersion([]string{"--version"}, &buf) {
		t.Fatal("maybePrintVersion(--version) = false, want true")
	}
	if !strings.Contains(buf.String(), "9.9.9") {
		t.Errorf("output %q does not contain version", buf.String())
	}
}

func TestMaybePrintVersionIgnoresOtherArgs(t *testing.T) {
	var buf strings.Builder
	if maybePrintVersion([]string{"--upstream", "http://x"}, &buf) {
		t.Fatal("maybePrintVersion(--upstream) = true, want false")
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected output %q", buf.String())
	}
}
