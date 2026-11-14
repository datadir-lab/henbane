package main

import (
	"fmt"
	"io"
)

// Build metadata, overridden at release time via -ldflags
// (-X main.version=... -X main.commit=... -X main.date=...).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// versionString is the one-line human-readable build identity.
func versionString() string {
	return fmt.Sprintf("henbane %s (%s, %s)", version, commit, date)
}

// maybePrintVersion prints the version to w and returns true if any arg
// requests it. Checked before config parsing so --version never requires
// --upstream.
func maybePrintVersion(args []string, w io.Writer) bool {
	for _, a := range args {
		if a == "--version" || a == "-version" {
			fmt.Fprintln(w, versionString())
			return true
		}
	}
	return false
}
