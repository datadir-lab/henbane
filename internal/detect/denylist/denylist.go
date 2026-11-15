// Package denylist provides operator-denylist detectors (IP/CIDR and user-agent).
package denylist

import (
	"net/netip"
	"strings"

	"github.com/datadir-lab/henbane/internal/ports"
)

type ipDetector struct{ cidrs []netip.Prefix }

// NewIP returns a Detector that blocks clients whose IP is in any cidr.
func NewIP(cidrs []netip.Prefix) ports.Detector { return ipDetector{cidrs: cidrs} }

func (d ipDetector) Name() string { return "denylist_ip" }

func (d ipDetector) Inspect(r ports.RequestView) (ports.Result, bool) {
	ip := r.IP().Unmap()
	if !ip.IsValid() {
		return ports.Result{}, false
	}
	for _, p := range d.cidrs {
		if p.Contains(ip) {
			return ports.Result{Signal: "denylist_ip", Tier: ports.TierBlocked}, true
		}
	}
	return ports.Result{}, false
}

type uaDetector struct{ lower []string }

// NewUA returns a Detector that blocks clients whose user-agent contains any of
// the given substrings (case-insensitive). Empty entries are ignored.
func NewUA(uas []string) ports.Detector {
	lower := make([]string, 0, len(uas))
	for _, ua := range uas {
		if ua != "" {
			lower = append(lower, strings.ToLower(ua))
		}
	}
	return uaDetector{lower: lower}
}

func (d uaDetector) Name() string { return "denylist_ua" }

func (d uaDetector) Inspect(r ports.RequestView) (ports.Result, bool) {
	ua := r.UserAgent()
	if ua == "" {
		return ports.Result{}, false
	}
	lower := strings.ToLower(ua)
	for _, deny := range d.lower {
		if strings.Contains(lower, deny) {
			return ports.Result{Signal: "denylist_ua", Tier: ports.TierBlocked}, true
		}
	}
	return ports.Result{}, false
}

type tlsfpDetector struct{ set map[string]struct{} }

// NewTLSFP returns a Detector that blocks clients whose TLS fingerprint (see
// internal/tlsfp) matches any of fps. It only fires when Henbane terminates TLS
// itself — otherwise the fingerprint is empty. A coarse TLS fingerprint is shared
// by every client using the same TLS stack, so list only fingerprints confirmed
// to be automated clients, exactly as with the IP and user-agent denylists.
func NewTLSFP(fps []string) ports.Detector {
	set := make(map[string]struct{}, len(fps))
	for _, f := range fps {
		if f != "" {
			set[f] = struct{}{}
		}
	}
	return tlsfpDetector{set: set}
}

func (d tlsfpDetector) Name() string { return "denylist_tls" }

func (d tlsfpDetector) Inspect(r ports.RequestView) (ports.Result, bool) {
	f, ok := r.(ports.TLSFingerprinter)
	if !ok {
		return ports.Result{}, false
	}
	fp := f.TLSFingerprint()
	if fp == "" {
		return ports.Result{}, false
	}
	if _, bad := d.set[fp]; bad {
		return ports.Result{Signal: "denylist_tls", Tier: ports.TierBlocked}, true
	}
	return ports.Result{}, false
}
