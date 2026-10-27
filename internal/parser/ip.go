package parser

import (
	"net/netip"
	"strings"
)

// CleanIP normalises an address captured from a log line.
//
// It preserves IPv6 (whose colons are part of the address) while still
// stripping an IPv4 ":port" suffix, which is the reason the original parser
// truncated at the first colon. Bracketed forms like "[::1]:443" are unwrapped.
// Unparseable values are returned unchanged and rejected later by the store.
func CleanIP(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}

	// Bracketed IPv6, optionally with a port: [::1] or [::1]:443
	if strings.HasPrefix(v, "[") {
		end := strings.IndexByte(v, ']')
		if end > 0 {
			inner := v[1:end]
			if _, err := netip.ParseAddr(inner); err == nil {
				return inner
			}
		}
	}

	colons := strings.Count(v, ":")

	// A single colon is the IPv4:port form (or host:port); strip the port.
	if colons == 1 {
		host, port, _ := strings.Cut(v, ":")
		if isAllDigits(port) && isDottedQuad(host) {
			return host
		}
	}

	// Bare IPv4 or IPv6.
	if addr, err := netip.ParseAddr(v); err == nil {
		return addr.String()
	}

	// IPv6 with a trailing port but no brackets: "2001:db8::1:443" is
	// ambiguous, so only strip when the remainder parses as IPv6.
	if colons >= 2 {
		if i := strings.LastIndexByte(v, ':'); i > 0 && isAllDigits(v[i+1:]) {
			if addr, err := netip.ParseAddr(v[:i]); err == nil && addr.Is6() {
				return addr.String()
			}
		}
	}

	return v
}

// ValidIP reports whether s is an address or prefix PostgreSQL's inet type
// accepts. It is used to null out malformed values before insert.
func ValidIP(s string) bool {
	if s == "" {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	return false
}

// IsIPv4 reports whether s is a plain dotted-quad address.
func IsIPv4(s string) bool {
	if !isDottedQuad(s) {
		return false
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// IsIPv6 reports whether s is a valid IPv6 address or prefix.
func IsIPv6(s string) bool {
	if s == "" || !strings.Contains(s, ":") {
		return false
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Is6()
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().Is6()
	}
	return false
}

// isDottedQuad is a cheap shape check; validity is confirmed by netip.
func isDottedQuad(s string) bool {
	if len(s) < 7 || len(s) > 15 {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for i := 0; i < len(p); i++ {
			if !isDigit(p[i]) {
				return false
			}
		}
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}
