package main

import (
	"fmt"
	"io"
	"runtime/debug"
)

// Build metadata, overridden at release time via -ldflags
// (-X main.version=... -X main.commit=... -X main.date=...).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// versionString is the one-line human-readable build identity. A release
// binary carries the values injected by -ldflags. A binary built with
// `go install module@version` has no ldflags, so version stays "dev"; in
// that case it falls back to the module version and VCS stamp the Go
// toolchain embeds in the build info.
func versionString() string {
	v, c, d := version, commit, date
	if v == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
				v = bi.Main.Version
			}
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if c == "none" && len(s.Value) >= 7 {
						c = s.Value[:7]
					}
				case "vcs.time":
					if d == "unknown" {
						d = s.Value
					}
				}
			}
		}
	}
	return fmt.Sprintf("henbane %s (%s, %s)", v, c, d)
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
