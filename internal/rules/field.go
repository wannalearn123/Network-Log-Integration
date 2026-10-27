package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"siskamlan/internal/parser"
)

// RowField reads a named field from a parsed entry. Unknown fields yield nil.
//
// "$identity" reproduces the original attribution rule: AP rows attribute to
// the client MAC, switch rows to the learned MAC, everything else to src_ip.
func RowField(e *parser.Entry, name string) any {
	switch name {
	case "$identity":
		return identity(e)
	case "$mac":
		switch {
		case e.ClientMAC != "":
			return e.ClientMAC
		case e.MAC != "":
			return e.MAC
		}
		return nil
	case "hostname":
		return strOrNil(e.Hostname)
	case "facility":
		return strOrNil(e.Facility)
	case "severity":
		return strOrNil(e.Severity)
	case "device_type":
		return strOrNil(e.DeviceType)
	case "event":
		return strOrNil(e.Event)
	case "src_ip":
		return strOrNil(e.SrcIP)
	case "dst_ip":
		return strOrNil(e.DstIP)
	case "proto":
		return strOrNil(e.Proto)
	case "dst_port":
		return e.DstPort
	case "src_port":
		return e.SrcPort
	case "action":
		return strOrNil(e.Action)
	case "mac":
		return strOrNil(e.MAC)
	case "vlan_id":
		return e.VLANID
	case "ifname":
		return strOrNil(e.IfName)
	case "peer_ifname":
		return strOrNil(e.PeerIfName)
	case "stp_root":
		return strOrNil(e.STPRoot)
	case "client_mac":
		return strOrNil(e.ClientMAC)
	case "ssid":
		return strOrNil(e.SSID)
	case "radio":
		return strOrNil(e.Radio)
	case "reason":
		return e.Reason
	case "signal_dbm":
		return e.SignalDBM
	case "tx_rate_mbps":
		return e.TxRateMbps
	case "eap_status":
		return strOrNil(e.EAPStatus)
	case "ospf_nbr":
		return strOrNil(e.OSPFNbr)
	case "gateway":
		return strOrNil(e.Gateway)
	case "route_dst":
		return strOrNil(e.RouteDst)
	case "dhcp_mac":
		return strOrNil(e.DHCPMAC)
	case "conntrack_count":
		return e.ConntrackCount
	}
	return nil
}

func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// identity mirrors the Python _identity(): AP -> client MAC, switch -> MAC,
// otherwise src_ip, with placeholder values treated as absent.
func identity(e *parser.Entry) any {
	switch e.DeviceType {
	case "ap":
		if e.ClientMAC != "" {
			return e.ClientMAC
		}
		return nil
	case "switch":
		if e.MAC != "" {
			return e.MAC
		}
		return nil
	}
	src := strings.ToLower(e.SrcIP)
	if e.SrcIP == "" || src == "unknown" || src == "none" {
		return nil
	}
	return e.SrcIP
}

// fieldString renders a field value for grouping, matching and messages.
func fieldString(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", false
	case string:
		if x == "" {
			return "", false
		}
		return x, true
	case int:
		return strconv.Itoa(x), true
	case *int:
		if x == nil {
			return "", false
		}
		return strconv.Itoa(*x), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(x), true
	}
	return fmt.Sprint(v), true
}

var ipv4Re = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

// Match evaluates a condition against a row.
func Match(c Condition, e *parser.Entry) bool {
	hasLeaf := c.Field != ""
	if len(c.All) > 0 {
		for _, sub := range c.All {
			if !Match(sub, e) {
				return false
			}
		}
	}
	if len(c.Any) > 0 {
		ok := false
		for _, sub := range c.Any {
			if Match(sub, e) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if c.Not != nil {
		if Match(*c.Not, e) {
			return false
		}
	}
	if !hasLeaf {
		return true
	}
	return compareLeaf(c, RowField(e, c.Field))
}

// compareLeaf applies Op to a field value.
func compareLeaf(c Condition, v any) bool {
	op := c.Op
	if op == "" {
		op = "eq"
	}

	switch op {
	case "exists":
		_, ok := fieldString(v)
		return ok
	case "not_exists":
		_, ok := fieldString(v)
		return !ok
	case "in":
		for _, want := range c.Values {
			if looseEquals(v, want) {
				return true
			}
		}
		return false
	case "not_in":
		for _, want := range c.Values {
			if looseEquals(v, want) {
				return false
			}
		}
		return true
	}

	s, ok := fieldString(v)
	if !ok {
		return false
	}

	switch op {
	case "eq":
		return looseEquals(v, c.Value)
	case "ne":
		return !looseEquals(v, c.Value)
	case "contains", "icontains", "contains_any":
		needle := strings.ToLower(fmt.Sprint(c.Value))
		hay := strings.ToLower(s)
		if op == "contains_any" {
			for _, want := range c.Values {
				if strings.Contains(hay, strings.ToLower(fmt.Sprint(want))) {
					return true
				}
			}
			return false
		}
		return strings.Contains(hay, needle)
	case "prefix", "iprefix":
		return strings.HasPrefix(strings.ToLower(s), strings.ToLower(fmt.Sprint(c.Value)))
	case "suffix", "isuffix":
		return strings.HasSuffix(strings.ToLower(s), strings.ToLower(fmt.Sprint(c.Value)))
	case "regex":
		re, err := regexp.Compile(fmt.Sprint(c.Value))
		return err == nil && re.MatchString(s)
	case "gt", "gte", "lt", "lte":
		a, ok1 := toFloat(v)
		b, ok2 := toFloat(c.Value)
		if !ok1 || !ok2 {
			return false
		}
		switch op {
		case "gt":
			return a > b
		case "gte":
			return a >= b
		case "lt":
			return a < b
		default:
			return a <= b
		}
	}
	return false
}

// looseEquals compares a field value with a YAML scalar, tolerating the
// string/number difference introduced by config round-tripping. String
// comparison is case-insensitive so "MAC_FLAP" matches the parsed "mac_flap".
func looseEquals(v, want any) bool {
	vs, ok1 := fieldString(v)
	if !ok1 {
		return false
	}
	ws := fmt.Sprint(want)
	if strings.EqualFold(vs, ws) {
		return true
	}
	a, okA := toFloat(v)
	b, okB := toFloat(want)
	return okA && okB && a == b
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case *int:
		if x == nil {
			return 0, false
		}
		return float64(*x), true
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	}
	return 0, false
}
