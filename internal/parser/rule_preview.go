package parser

import (
	"regexp"
	"strings"
)

// ApplyFieldRule applies one field rule to a raw line in isolation and
// returns the value it produced.
//
// The built-in extractors run first on every line and fill many columns on
// their own, so checking "is this column non-empty after parsing?" cannot
// tell a working rule from an inert one. This helper clears the target
// column before applying the rule, which is the only way to know whether
// the rule itself did anything. The TUI editor uses it to reject rules that
// validate against the schema but extract nothing from the file on screen.
func ApplyFieldRule(rule FieldRule, line string) (string, bool) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", false
	}
	e := Parse(line)
	if e == nil {
		return "", false
	}
	clearTarget(e, rule.Target)
	if rule.Strategy == "regex" {
		if rule.re == nil {
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return "", false
			}
			rule.re = re
		}
	}
	rule.apply(e, line, asciiLower(line))
	return readTarget(e, rule.Target)
}

// clearTarget resets one column so a rule's contribution can be measured.
func clearTarget(e *Entry, target string) {
	switch target {
	case "src_ip":
		e.SrcIP = ""
	case "dst_ip":
		e.DstIP = ""
	case "proto":
		e.Proto = ""
	case "action":
		e.Action = ""
	case "mac":
		e.MAC = ""
	case "client_mac":
		e.ClientMAC = ""
	case "dhcp_mac":
		e.DHCPMAC = ""
	case "ifname":
		e.IfName = ""
	case "peer_ifname":
		e.PeerIfName = ""
	case "stp_root":
		e.STPRoot = ""
	case "ssid":
		e.SSID = ""
	case "radio":
		e.Radio = ""
	case "eap_status":
		e.EAPStatus = ""
	case "ospf_nbr":
		e.OSPFNbr = ""
	case "gateway":
		e.Gateway = ""
	case "route_dst":
		e.RouteDst = ""
	case "event":
		e.Event = ""
	case "device_type":
		e.DeviceType = ""
	case "dst_port":
		e.DstPort = nil
	case "src_port":
		e.SrcPort = nil
	case "vlan_id":
		e.VLANID = nil
	case "reason":
		e.Reason = nil
	case "signal_dbm":
		e.SignalDBM = nil
	case "tx_rate_mbps":
		e.TxRateMbps = nil
	case "conntrack_count":
		e.ConntrackCount = nil
	}
}

// readTarget reads one column back as text.
func readTarget(e *Entry, target string) (string, bool) {
	if v := readStringField(e, target); v != "" {
		return v, true
	}
	var n *int
	switch target {
	case "dst_port":
		n = e.DstPort
	case "src_port":
		n = e.SrcPort
	case "vlan_id":
		n = e.VLANID
	case "reason":
		n = e.Reason
	case "signal_dbm":
		n = e.SignalDBM
	case "tx_rate_mbps":
		n = e.TxRateMbps
	case "conntrack_count":
		n = e.ConntrackCount
	}
	if n == nil {
		return "", false
	}
	return itoa(*n), true
}
