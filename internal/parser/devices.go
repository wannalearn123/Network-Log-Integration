package parser

import (
	"net/netip"
	"strings"
)

// hostHasToken reports whether the lowercased hostname contains token,
// possibly followed by digits, as a delimiter-separated component.
func hostHasToken(hostLower, tok string) bool {
	tlen := len(tok)
	p := 0
	for p < len(hostLower) {
		for p < len(hostLower) && (hostLower[p] == '.' || hostLower[p] == '-' || hostLower[p] == '_') {
			p++
		}
		if p >= len(hostLower) {
			break
		}
		start := p
		for p < len(hostLower) && hostLower[p] != '.' && hostLower[p] != '-' && hostLower[p] != '_' {
			p++
		}
		seg := hostLower[start:p]
		if len(seg) >= tlen && seg[:tlen] == tok {
			ok := true
			for i := tlen; i < len(seg); i++ {
				if !isDigit(seg[i]) {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
	}
	return false
}

// detectDeviceType classifies the device from its hostname.
func detectDeviceType(e *Entry) {
	if e.Hostname == "" {
		e.DeviceType = "unknown"
		return
	}
	host := asciiLower(e.Hostname)
	switch {
	case strings.Contains(host, "router"):
		e.DeviceType = "router"
	case strings.Contains(host, "switch"):
		e.DeviceType = "switch"
	case hostHasToken(host, "ap"):
		e.DeviceType = "ap"
	case strings.Contains(host, "firewall") || strings.Contains(host, "fw"):
		e.DeviceType = "firewall"
	case strings.Contains(host, "syslog"):
		e.DeviceType = "syslog"
	default:
		e.DeviceType = "other"
	}
}

// findCI returns the index of needle in hay, case-insensitively.
func findCI(hay, needle string) (int, bool) {
	n := len(needle)
	if n == 0 {
		return 0, false
	}
	for i := 0; i+n <= len(hay); i++ {
		ok := true
		for j := 0; j < n; j++ {
			if toLowerB(hay[i+j]) != toLowerB(needle[j]) {
				ok = false
				break
			}
		}
		if ok {
			return i, true
		}
	}
	return 0, false
}

// validIPv4 normalizes a dotted-quad and reports success.
func validIPv4(s string) (string, bool) {
	if len(s) < 7 || len(s) > 15 {
		return "", false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return "", false
	}
	out := make([]int, 4)
	for i, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return "", false
		}
		for j := 0; j < len(part); j++ {
			if !isDigit(part[j]) {
				return "", false
			}
		}
		v := atoi(part)
		if v < 0 || v > 255 {
			return "", false
		}
		out[i] = v
	}
	return itoa(out[0]) + "." + itoa(out[1]) + "." + itoa(out[2]) + "." + itoa(out[3]), true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// collectIPs returns up to two addresses in message order, IPv4 or IPv6.
func collectIPs(msg string) []string {
	var found []string
	for p := 0; p < len(msg); p++ {
		// Try IPv6 first: a run of hex digits and colons.
		if isHex(msg[p]) {
			q := p
			for q < len(msg) && (isHex(msg[q]) || msg[q] == ':') && (q-p) < 45 {
				q++
			}
			if q-p >= 2 && strings.Contains(msg[p:q], ":") {
				before := byte(' ')
				if p > 0 {
					before = msg[p-1]
				}
				var after byte
				if q < len(msg) {
					after = msg[q]
				}
				if !isWordByte(before) && (after == 0 || !isHex(after) && after != ':') {
					cand := strings.Trim(msg[p:q], ":")
					if cand != "" {
						if addr, err := netip.ParseAddr(cand); err == nil && addr.Is6() {
							found = append(found, addr.String())
							if len(found) >= 2 {
								return found
							}
							p = q - 1
							continue
						}
					}
				}
			}
		}
		if !isDigit(msg[p]) {
			continue
		}
		q := p
		for q < len(msg) && (isDigit(msg[q]) || msg[q] == '.') && (q-p) < 15 {
			q++
		}
		if norm, ok := validIPv4(msg[p:q]); ok {
			found = append(found, norm)
			if len(found) >= 2 {
				return found
			}
			p = q - 1
		}
	}
	return found
}

// extractPortGeneric reads a destination or source port from well-known keys.
func extractPortGeneric(msg string, wantSrc bool) int {
	var keys []string
	if wantSrc {
		keys = []string{"SPT"}
	} else {
		keys = []string{"DPT", "DPORT", "DSTPORT", "DST-PORT"}
	}
	for _, k := range keys {
		port := extractKVInt(msg, k)
		if port > 0 && port <= 65535 {
			return port
		}
	}
	return -1
}

// extractProtoGeneric normalizes protocol names and numbers.
func extractProtoGeneric(msg, low string, e *Entry) {
	if buf, ok := extractKV(msg, "PROTO"); ok {
		switch {
		case strings.Contains(low, "proto=tcp") || buf == "6":
			e.Proto = "TCP"
		case strings.Contains(low, "proto=udp") || buf == "17":
			e.Proto = "UDP"
		case strings.Contains(low, "proto=icmp") || buf == "1":
			e.Proto = "ICMP"
		default:
			e.Proto = truncate(buf, 7)
		}
		return
	}
	for _, w := range []struct{ word, name string }{
		{"tcp", "TCP"}, {"udp", "UDP"}, {"icmp", "ICMP"},
	} {
		if containsWord(low, w.word) {
			e.Proto = w.name
			return
		}
	}
}

// extractAction normalizes firewall verbs.
func extractAction(low string, e *Entry) {
	if buf, ok := extractKV(low, "act"); ok {
		switch buf {
		case "accept", "allow":
			e.Action = "allow"
		case "drop", "deny":
			e.Action = "deny"
		case "reject":
			e.Action = "reject"
		case "close":
			e.Action = "close"
		default:
			e.Action = truncate(buf, 15)
		}
		return
	}
	switch {
	case strings.Contains(low, "[fw allow]"):
		e.Action = "allow"
	case strings.Contains(low, "[fw drop]") || strings.Contains(low, "[fw deny"):
		e.Action = "deny"
	case strings.Contains(low, "[fw reject"):
		e.Action = "reject"
	case containsWord(low, "drop") || containsWord(low, "deny"):
		e.Action = "deny"
	case containsWord(low, "reject"):
		e.Action = "reject"
	case containsWord(low, "allow") || containsWord(low, "accept"):
		e.Action = "allow"
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// --- MAC detection ---

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isMACColon(s string, i int) bool {
	for g := 0; g < 6; g++ {
		if i+1 >= len(s) || !isHex(s[i]) || !isHex(s[i+1]) {
			return false
		}
		if g < 5 {
			if i+2 >= len(s) || s[i+2] != ':' {
				return false
			}
			i += 3
		}
	}
	return true
}

func isMACDot(s string, i int) bool {
	for g := 0; g < 3; g++ {
		for k := 0; k < 4; k++ {
			if i+k >= len(s) || !isHex(s[i+k]) {
				return false
			}
		}
		if g < 2 {
			if i+4 >= len(s) || s[i+4] != '.' {
				return false
			}
			i += 5
		}
	}
	return true
}

// extractFirstMAC returns the first colon- or dot-form MAC in msg.
func extractFirstMAC(msg string) (string, bool) {
	for p := 0; p < len(msg); p++ {
		var before byte = ' '
		if p > 0 {
			before = msg[p-1]
		}
		if isMACColon(msg, p) && !isHex(before) && before != ':' {
			afterIdx := p + 17
			var after byte
			if afterIdx < len(msg) {
				after = msg[afterIdx]
			}
			if !isHex(after) && after != ':' {
				return msg[p : p+17], true
			}
		}
		if isMACDot(msg, p) && !isHex(before) && before != '.' {
			afterIdx := p + 14
			var after byte
			if afterIdx < len(msg) {
				after = msg[afterIdx]
			}
			if !isHex(after) && after != '.' {
				return msg[p : p+14], true
			}
		}
	}
	return "", false
}

// extractMAC routes the first MAC to the column implied by context.
func extractMAC(e *Entry, msg, low string) {
	mbuf, ok := extractFirstMAC(msg)
	if !ok {
		return
	}
	switch {
	case strings.Contains(low, "dhcpack") ||
		(strings.Contains(low, "dhcp") && strings.Contains(low, "assigned")):
		e.DHCPMAC = mbuf
	case e.DeviceType == "ap":
		e.ClientMAC = mbuf
	case e.DeviceType == "switch":
		e.MAC = mbuf
	}
}

// extractVLAN reads "vlan N", "VLAN1" or "in vlan 10".
func extractVLAN(msg string, e *Entry) {
	idx, ok := findCI(msg, "vlan")
	if !ok {
		return
	}
	p := idx + 4
	for p < len(msg) && (msg[p] == ' ' || msg[p] == '\t' || msg[p] == '=') {
		p++
	}
	vlan := atoi(msg[p:])
	if vlan > 0 && vlan <= 4094 {
		v := vlan
		e.VLANID = &v
	}
}

// copyToken copies an address-like token. Colons are kept so IPv6 survives;
// only genuinely non-address characters terminate the token.
func copyToken(src string) string {
	var b strings.Builder
	for i := 0; i < len(src); i++ {
		c := src[i]
		if isAlpha(c) || isDigit(c) || c == '/' || c == '.' || c == ':' {
			b.WriteByte(c)
			continue
		}
		break
	}
	out := b.String()
	// A trailing colon can appear from "addr: rest"; trim it before validating.
	if trimmed := strings.TrimRight(out, ":"); ValidIP(trimmed) {
		return trimmed
	}
	return strings.TrimRight(out, ":")
}

// findIfaceAt scans low for an interface-shaped token at or after fromOff and
// copies the original-case text from msg.
func findIfaceAt(msg, low string, fromOff int) (string, bool) {
	if fromOff < 0 {
		fromOff = 0
	}
	for p := fromOff; p < len(low); p++ {
		var before byte = ' '
		if p > 0 {
			before = low[p-1]
		}
		if isAlpha(before) || isDigit(before) || before == '-' || before == '_' {
			continue
		}
		n := -1
		switch {
		case strings.HasPrefix(low[p:], "gigabitethernet") && p+15 < len(low) && isDigit(low[p+15]):
			n = 15
		case low[p] == 'g' && p+2 < len(low) && low[p+1] == 'i' && isDigit(low[p+2]):
			n = 2
		case strings.HasPrefix(low[p:], "ether") && p+5 < len(low) && isDigit(low[p+5]):
			n = 5
		case strings.HasPrefix(low[p:], "eth") && p+3 < len(low) && isDigit(low[p+3]):
			n = 3
		case strings.HasPrefix(low[p:], "wlan") && p+4 < len(low) && isDigit(low[p+4]):
			n = 4
		case low[p] == 'b' && p+2 < len(low) && low[p+1] == 'r' && isDigit(low[p+2]):
			n = 2
		}
		if n < 0 {
			continue
		}
		_ = n
		tok := copyIfaceToken(msg[p:])
		if tok == "" {
			continue
		}
		return tok, true
	}
	return "", false
}

func copyIfaceToken(src string) string {
	var b strings.Builder
	for i := 0; i < len(src); i++ {
		c := src[i]
		if isAlpha(c) || isDigit(c) || c == '/' {
			b.WriteByte(c)
		} else {
			break
		}
	}
	return b.String()
}

// extractIface finds the primary interface, flap peer and STP root.
func extractIface(e *Entry, msg, low string) {
	if iface, ok := findIfaceAt(msg, low, 0); ok {
		e.IfName = iface
		off := -1
		if idx, ok := findCI(low, " and port "); ok {
			off = idx
		} else if idx, ok := findCI(low, " and "); ok {
			off = idx
		}
		if off >= 0 {
			if peer, ok := findIfaceAt(msg, low, off); ok {
				e.PeerIfName = peer
			}
		}
	}
	if idx, ok := findCI(low, "new root "); ok {
		start := idx + 9
		if start <= len(msg) {
			e.STPRoot = copyToken(msg[start:])
		}
	}
}

// extractRadio reads the AP radio name (wlan0/wlan1).
func extractRadio(msg, low string, e *Entry) {
	idx, ok := findCI(low, "wlan")
	if !ok || idx+4 >= len(low) || !isDigit(low[idx+4]) {
		return
	}
	var b strings.Builder
	for i := idx; i < len(msg); i++ {
		c := msg[i]
		if isAlpha(c) || isDigit(c) {
			b.WriteByte(c)
		} else {
			break
		}
	}
	e.Radio = b.String()
}

// extractSSID reads "(SSID Campus)" or "SSID=foo".
func extractSSID(msg string, e *Entry) {
	idx, ok := findCI(msg, "ssid")
	if !ok {
		return
	}
	p := idx + 4
	for p < len(msg) && (msg[p] == ' ' || msg[p] == '\t' || msg[p] == '=') {
		p++
	}
	end := p
	for end < len(msg) && msg[end] != ')' && msg[end] != '\n' && msg[end] != '\r' {
		end++
	}
	val := msg[p:end]
	val = strings.TrimRight(val, " \t")
	e.SSID = val
}

// extractReason reads reason=N.
func extractReason(msg string, e *Entry) {
	code := extractKVInt(msg, "reason")
	if code >= 0 {
		v := code
		e.Reason = &v
	}
}

// extractSignal reads signal=N and tx_rate=N.
func extractSignal(msg string, e *Entry) {
	if sig := extractKVInt(msg, "signal"); sig != -1 {
		v := sig
		e.SignalDBM = &v
	}
	if rate := extractKVInt(msg, "tx_rate"); rate > 0 {
		v := rate
		e.TxRateMbps = &v
	}
}

// extractEAP classifies AP authentication outcome.
func extractEAP(e *Entry, low string) {
	if e.DeviceType != "ap" {
		return
	}
	switch {
	case strings.Contains(low, "auth_failed") || containsWord(low, "failed") ||
		strings.Contains(low, "invalid credentials") ||
		strings.Contains(low, "authentication error") ||
		strings.Contains(low, "ap-sta-failed"):
		e.EAPStatus = "failed"
	case strings.Contains(low, "authentication success") ||
		strings.Contains(low, "handshake completed") ||
		strings.Contains(low, "auth success"):
		e.EAPStatus = "success"
	}
}

// extractOSPF reads "Nbr 172.20.0.9".
func extractOSPF(msg, low string, e *Entry) {
	idx, ok := findCI(low, "nbr ")
	if !ok {
		return
	}
	start := idx + 4
	if start <= len(msg) {
		e.OSPFNbr = copyToken(msg[start:])
	}
}

// extractGateway reads gateway= and dst-address=.
func extractGateway(msg string, e *Entry) {
	if v, ok := extractKV(msg, "gateway"); ok {
		e.Gateway = CleanIP(v)
	}
	if v, ok := extractKV(msg, "dst-address"); ok {
		e.RouteDst = truncate(v, 45)
	}
}

// extractConntrack reads "tracking: N entries" / "conntrack: N ...".
func extractConntrack(low string, e *Entry) {
	const needle = "tracking:"
	idx, ok := findCI(low, needle)
	if !ok {
		idx, ok = findCI(low, "conntrack:")
		if !ok {
			return
		}
		if c := atoi(low[idx+len("conntrack:"):]); c >= 0 {
			v := c
			e.ConntrackCount = &v
		}
		return
	}
	// Skip past the colon that belongs to the needle itself.
	if c := atoi(low[idx+len(needle):]); c >= 0 {
		v := c
		e.ConntrackCount = &v
	}
}
