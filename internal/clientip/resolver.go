// Package clientip resolves the real client IP from a connection address and
// X-Forwarded-For header using the security-grade "rightmost-non-trusted"
// algorithm. It imports only the standard library.
package clientip

import (
	"net"
	"net/netip"
	"strings"
)

// Resolver resolves client IPs given a set of trusted proxy CIDRs.
type Resolver struct {
	trusted []netip.Prefix
}

// NewResolver returns a Resolver trusting the given proxy CIDRs. Empty/nil means
// edge mode: forwarding headers are ignored entirely (they are attacker-controlled).
func NewResolver(trusted []netip.Prefix) *Resolver {
	return &Resolver{trusted: trusted}
}

// ClientIP returns the effective client IP. remoteAddr is the connection's
// RemoteAddr ("ip:port" or "ip"); xff is every X-Forwarded-For header value
// (use http.Header.Values, not Get). Returns an invalid netip.Addr if no
// trustworthy client IP can be determined.
func (r *Resolver) ClientIP(remoteAddr string, xff []string) netip.Addr {
	conn := parseAddr(remoteAddr)

	// Edge mode, or the connection is not itself a trusted proxy: only the
	// connection is trustworthy. Ignore forwarding headers.
	if len(r.trusted) == 0 || !r.isTrusted(conn) {
		return conn
	}

	// Trusted proxy connection: walk XFF right-to-left, skipping trusted hops,
	// and return the first untrusted valid IP.
	ips := splitXFF(xff)
	for i := len(ips) - 1; i >= 0; i-- {
		addr := parseAddr(ips[i])
		if !addr.IsValid() || r.isTrusted(addr) {
			continue
		}
		return addr
	}

	// All XFF entries trusted/invalid: fall back to the connection only if it is
	// itself untrusted; otherwise nothing is trustworthy.
	if conn.IsValid() && !r.isTrusted(conn) {
		return conn
	}
	return netip.Addr{}
}

func (r *Resolver) isTrusted(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// maxXFFEntries bounds how many X-Forwarded-For hops we parse, so a hostile
// multi-megabyte header cannot drive unbounded CPU/allocation. The rightmost
// entries (appended by trusted proxies) are the security-relevant ones, so the
// sliding window keeps those.
const maxXFFEntries = 50

func splitXFF(values []string) []string {
	out := make([]string, 0, maxXFFEntries)
	push := func(part string) {
		if part = strings.TrimSpace(part); part == "" {
			return
		}
		if len(out) == maxXFFEntries {
			copy(out, out[1:]) // drop the leftmost, keep the rightmost window
			out[len(out)-1] = part
		} else {
			out = append(out, part)
		}
	}
	for _, v := range values {
		for len(v) > 0 {
			if i := strings.IndexByte(v, ','); i >= 0 {
				push(v[:i])
				v = v[i+1:]
			} else {
				push(v)
				break
			}
		}
	}
	return out
}

// parseAddr parses one entry into a netip.Addr, tolerating quotes, IPv6
// brackets, and an appended :port. Returns an invalid Addr on failure.
func parseAddr(s string) netip.Addr {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"")
	switch {
	case strings.HasPrefix(s, "["):
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		} else {
			s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
		}
	case strings.Count(s, ":") == 1: // IPv4:port
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		}
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap().WithZone("")
}
