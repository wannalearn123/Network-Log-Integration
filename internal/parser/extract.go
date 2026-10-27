package parser

import "strings"

// extractFields fills every structured column from the full raw line.
//
// Extraction intentionally runs over the whole line, not just the message
// body, to match the original C parser.
func extractFields(e *Entry, line string) {
	low := asciiLower(line)

	// Structured key=value source/destination, with vendor aliases.
	if v, ok := extractKV(line, "SRC"); ok {
		e.SrcIP = v
	}
	if v, ok := extractKV(line, "DST"); ok {
		e.DstIP = v
	}
	if e.SrcIP == "" {
		if v, ok := extractKV(line, "SRCIP"); ok {
			e.SrcIP = v
		}
	}
	if e.DstIP == "" {
		if v, ok := extractKV(line, "DSTIP"); ok {
			e.DstIP = v
		}
	}
	if e.SrcIP == "" {
		if v, ok := extractKV(line, "SRC-ADDRESS"); ok {
			e.SrcIP = v
		}
	}
	if e.DstIP == "" {
		if v, ok := extractKV(line, "DST-ADDRESS"); ok {
			e.DstIP = v
		}
	}
	// Strip ":port" suffixes.
	if i := strings.IndexByte(e.SrcIP, ':'); i >= 0 {
		e.SrcIP = e.SrcIP[:i]
	}
	if i := strings.IndexByte(e.DstIP, ':'); i >= 0 {
		e.DstIP = e.DstIP[:i]
	}

	extractProtoGeneric(line, low, e)
	if p := extractPortGeneric(line, false); p > 0 {
		v := p
		e.DstPort = &v
	}
	if p := extractPortGeneric(line, true); p > 0 {
		v := p
		e.SrcPort = &v
	}
	extractAction(low, e)
	extractMAC(e, line, low)
	extractVLAN(line, e)
	extractIface(e, line, low)
	extractRadio(line, low, e)
	extractSSID(line, e)
	extractReason(line, e)
	extractSignal(line, e)
	extractEAP(e, low)
	extractOSPF(line, low, e)
	extractGateway(line, e)
	extractConntrack(low, e)

	// Positional IP fallback when no explicit keys were present.
	if e.SrcIP == "" && e.DstIP == "" {
		ips := collectIPs(line)
		switch {
		case len(ips) == 1:
			if strings.Contains(low, "dhcpack") || strings.Contains(low, "dhcp") ||
				strings.Contains(low, "assigned") || strings.Contains(low, "lease") ||
				strings.Contains(low, "connected") || strings.Contains(low, "associated") ||
				strings.Contains(low, "authenticated") || strings.Contains(low, "learned") {
				e.DstIP = ips[0]
			} else {
				e.SrcIP = ips[0]
			}
		case len(ips) >= 2:
			e.SrcIP = ips[0]
			e.DstIP = ips[1]
		}
	} else if e.SrcIP != "" && e.DstIP == "" {
		if ips := collectIPs(line); len(ips) >= 2 {
			e.DstIP = ips[1]
		}
	}

	e.Event = classifyEvent(e, low)
}

// classifyEvent maps message keywords to a normalized event name.
func classifyEvent(e *Entry, low string) string {
	switch {
	case strings.Contains(low, "ap-sta-failed") || strings.Contains(low, "invalid_auth") ||
		strings.Contains(low, "authentication error") || strings.Contains(low, "handshake failed") ||
		(strings.Contains(low, "failed") && strings.Contains(low, "auth")):
		return "auth_failure"
	case strings.Contains(low, "ap-sta-deauth") || strings.Contains(low, "deauth"):
		return "deauth"
	case strings.Contains(low, "ap-sta-disconnected") || strings.Contains(low, "disassociated") ||
		strings.Contains(low, "disconnected"):
		return "client_disconnect"
	case strings.Contains(low, "ap-sta-connected") || strings.Contains(low, "associated") ||
		strings.Contains(low, "authenticated") || strings.Contains(low, "handshake completed") ||
		strings.Contains(low, "authentication success") || strings.Contains(low, "auth success"):
		return "client_connect"
	case strings.Contains(low, "dhcpack") ||
		(strings.Contains(low, "dhcp") && (strings.Contains(low, "assigned") ||
			strings.Contains(low, "lease") || strings.Contains(low, "ack"))):
		return "dhcp_ack"
	case strings.Contains(low, "mac flap") || strings.Contains(low, "macflap") ||
		strings.Contains(low, "flapping") || containsWord(low, "flap"):
		return "mac_flap"
	case strings.Contains(low, "mac learn") || strings.Contains(low, "learned"):
		return "mac_learn"
	// CEF action-based classification must precede generic keyword matches to
	// avoid false positives from headers like "cat=traffic:forward".
	case strings.Contains(low, "act=close") || strings.Contains(low, "act=accept"):
		return "fw_allow"
	case strings.Contains(low, "act=deny") || strings.Contains(low, "act=drop") ||
		strings.Contains(low, "act=reject"):
		return "fw_block"
	case strings.Contains(low, "block") || strings.Contains(low, "drop") ||
		strings.Contains(low, "deny"):
		return "fw_block"
	case strings.Contains(low, "reject"):
		return "fw_reject"
	case strings.Contains(low, "allow") || strings.Contains(low, "accept"):
		return "fw_allow"
	case strings.Contains(low, "signal="):
		return "signal_report"
	case strings.Contains(low, "stp") || strings.Contains(low, "spantree") ||
		strings.Contains(low, "root bridge"):
		return "stp_event"
	case strings.Contains(low, "lineproto") || containsWord(low, "link") ||
		strings.Contains(low, "updown") || containsWord(low, "port"):
		if e.DeviceType == "switch" {
			return "port_status"
		}
		return "interface_status"
	case strings.Contains(low, "routing table") || strings.Contains(low, "ospf") ||
		strings.Contains(low, "adjchg") || containsWord(low, "route"):
		if e.DeviceType == "router" {
			return "route_update"
		}
		return "route_change"
	case strings.Contains(low, "conntrack") || strings.Contains(low, "connection tracking"):
		return "nat_conntrack"
	case strings.Contains(low, "masquerad") ||
		(strings.Contains(low, "nat") && !strings.Contains(low, "donat")):
		return "nat_event"
	case strings.Contains(low, "router input") || strings.Contains(low, "router forward"):
		return "packet_log"
	}

	switch e.DeviceType {
	case "firewall":
		return "fw_event"
	case "router":
		return "router_event"
	case "switch":
		return "switch_event"
	case "ap":
		return "ap_event"
	default:
		return "unknown"
	}
}
