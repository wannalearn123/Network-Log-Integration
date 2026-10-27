package parser

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the user-editable parser definition (config/parsers.yaml).
//
// It lets new log sources be supported without touching code: a device
// profile maps keywords in the raw line onto the structured columns the rest
// of the system expects.
type Config struct {
	Version int      `yaml:"version" json:"version"`
	Devices []Device `yaml:"devices" json:"devices"`
}

// Device describes how to parse one class of log source.
type Device struct {
	Name string `yaml:"name" json:"name"`
	// HostnameMatch are regular expressions matched against the hostname.
	// The first matching device wins, so order matters.
	HostnameMatch []string `yaml:"hostname_match,omitempty" json:"hostname_match,omitempty"`
	// DeviceType overrides hostname-based detection when set.
	DeviceType string `yaml:"device_type,omitempty" json:"device_type,omitempty"`
	// Fields map raw-line tokens onto columns.
	Fields []FieldRule `yaml:"fields,omitempty" json:"fields,omitempty"`
	// Events map keywords onto normalized event names, first match wins.
	Events []EventRule `yaml:"events,omitempty" json:"events,omitempty"`
}

// FieldRule extracts one column from a raw line.
//
// Strategy determines how Target is filled:
//
//	kv        - find `key=` / key: value pairs (Key)
//	regex     - first capture group (or named `v`) of Pattern
//	word_map  - translate a Source column through Map (case-insensitive)
//	positional- first/last textual token per Pos ("first"|"last")
type FieldRule struct {
	Target   string            `yaml:"target" json:"target"`
	Strategy string            `yaml:"strategy" json:"strategy"`
	Key      string            `yaml:"key,omitempty" json:"key,omitempty"`
	Keys     []string          `yaml:"keys,omitempty" json:"keys,omitempty"`
	Pattern  string            `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Source   string            `yaml:"source,omitempty" json:"source,omitempty"`
	Map      map[string]string `yaml:"map,omitempty" json:"map,omitempty"`
	Pos      string            `yaml:"pos,omitempty" json:"pos,omitempty"`
	Type     string            `yaml:"type,omitempty" json:"type,omitempty"`

	re *regexp.Regexp
}

// EventRule assigns an event name when every condition matches.
//
//	{event: fw_drop, contains: ["FW DROP"]}
//	{event: auth_failure, regex: "(?i)auth.*fail"}
type EventRule struct {
	Event    string   `yaml:"event" json:"event"`
	Contains []string `yaml:"contains,omitempty" json:"contains,omitempty"`
	AnyOf    []string `yaml:"any_of,omitempty" json:"any_of,omitempty"`
	Regex    string   `yaml:"regex,omitempty" json:"regex,omitempty"`
	Field    string   `yaml:"field,omitempty" json:"field,omitempty"`
	Equals   string   `yaml:"equals,omitempty" json:"equals,omitempty"`

	re *regexp.Regexp
}

// Decode parses a parser config document.
func DecodeConfig(raw []byte) (Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// EncodeConfig serializes a parser config.
func EncodeConfig(c Config) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// fieldStrategies are the accepted strategy names.
var fieldStrategies = map[string]bool{
	"kv": true, "regex": true, "word_map": true, "positional": true,
}

// fieldTypes are the accepted target value types.
var fieldTypes = map[string]bool{
	"": true, "string": true, "int": true, "ip": true,
}

// Validate rejects documents the parser cannot compile or apply.
func ValidateConfig(c Config) error {
	if c.Version < 0 {
		return fmt.Errorf("parsers: version must be nonnegative")
	}
	seen := map[string]bool{}
	for i, d := range c.Devices {
		where := fmt.Sprintf("devices[%d]", i)
		if strings.TrimSpace(d.Name) == "" {
			return fmt.Errorf("%s: name is required", where)
		}
		where = fmt.Sprintf("device %q", d.Name)
		if seen[d.Name] {
			return fmt.Errorf("%s: duplicate name", where)
		}
		seen[d.Name] = true

		if d.DeviceType != "" && !validDeviceType(d.DeviceType) {
			return fmt.Errorf("%s: unknown device_type %q", where, d.DeviceType)
		}
		for _, expr := range d.HostnameMatch {
			if _, err := regexp.Compile(expr); err != nil {
				return fmt.Errorf("%s: bad hostname_match %q: %w", where, expr, err)
			}
		}
		for j, f := range d.Fields {
			fw := fmt.Sprintf("%s fields[%d]", where, j)
			if !validTarget(f.Target) {
				return fmt.Errorf("%s: unknown target column %q", fw, f.Target)
			}
			if !fieldStrategies[f.Strategy] {
				return fmt.Errorf("%s: unknown strategy %q", fw, f.Strategy)
			}
			if !fieldTypes[f.Type] {
				return fmt.Errorf("%s: unknown type %q", fw, f.Type)
			}
			switch f.Strategy {
			case "kv":
				if f.Key == "" && len(f.Keys) == 0 {
					return fmt.Errorf("%s: kv needs key or keys", fw)
				}
			case "regex":
				if f.Pattern == "" {
					return fmt.Errorf("%s: regex needs pattern", fw)
				}
				if _, err := regexp.Compile(f.Pattern); err != nil {
					return fmt.Errorf("%s: bad pattern: %w", fw, err)
				}
			case "word_map":
				if f.Source == "" {
					return fmt.Errorf("%s: word_map needs source", fw)
				}
				if !validTarget(f.Source) {
					return fmt.Errorf("%s: unknown source column %q", fw, f.Source)
				}
				if len(f.Map) == 0 {
					return fmt.Errorf("%s: word_map needs map", fw)
				}
			case "positional":
				if f.Pos != "" && f.Pos != "first" && f.Pos != "last" {
					return fmt.Errorf("%s: pos must be first or last", fw)
				}
			}
		}
		for j, ev := range d.Events {
			ew := fmt.Sprintf("%s events[%d]", where, j)
			if strings.TrimSpace(ev.Event) == "" {
				return fmt.Errorf("%s: event name is required", ew)
			}
			if ev.Regex != "" {
				if _, err := regexp.Compile(ev.Regex); err != nil {
					return fmt.Errorf("%s: bad regex: %w", ew, err)
				}
			}
			if len(ev.Contains) == 0 && len(ev.AnyOf) == 0 &&
				ev.Regex == "" && ev.Field == "" {
				return fmt.Errorf("%s: needs contains, any_of, regex or field", ew)
			}
			if ev.Field != "" && !validTarget(ev.Field) {
				return fmt.Errorf("%s: unknown field %q", ew, ev.Field)
			}
		}
	}
	return nil
}

func validDeviceType(t string) bool {
	switch t {
	case "router", "switch", "ap", "firewall", "syslog", "other", "unknown":
		return true
	}
	return false
}

// compile pre-compiles regexes so per-line parsing stays fast.
func (c *Config) compile() error {
	for di := range c.Devices {
		for fi := range c.Devices[di].Fields {
			f := &c.Devices[di].Fields[fi]
			if f.Strategy == "regex" {
				re, err := regexp.Compile(f.Pattern)
				if err != nil {
					return err
				}
				f.re = re
			}
		}
		for ei := range c.Devices[di].Events {
			ev := &c.Devices[di].Events[ei]
			if ev.Regex != "" {
				re, err := regexp.Compile(ev.Regex)
				if err != nil {
					return err
				}
				ev.re = re
			}
		}
	}
	return nil
}

// applyConfig runs the configured field and event rules for a matching device.
func (c *Config) applyConfig(e *Entry, line, low string) bool {
	if c == nil {
		return false
	}
	dev := c.match(e.Hostname)
	if dev == nil {
		return false
	}
	if dev.DeviceType != "" {
		e.DeviceType = dev.DeviceType
	}
	for i := range dev.Fields {
		dev.Fields[i].apply(e, line, low)
	}
	if ev := dev.matchEvent(e, low); ev != "" {
		e.Event = ev
		return true
	}
	return false
}

// match returns the first device whose hostname patterns match.
func (c *Config) match(hostname string) *Device {
	host := strings.ToLower(hostname)
	for i := range c.Devices {
		d := &c.Devices[i]
		if len(d.HostnameMatch) == 0 {
			continue
		}
		for _, expr := range d.HostnameMatch {
			re, err := regexp.Compile(expr)
			if err != nil {
				continue
			}
			if re.MatchString(host) {
				return d
			}
		}
	}
	return nil
}

// apply extracts one field into the entry.
func (f *FieldRule) apply(e *Entry, line, low string) {
	var raw string
	var ok bool

	switch f.Strategy {
	case "kv":
		keys := f.Keys
		if f.Key != "" {
			keys = append([]string{f.Key}, keys...)
		}
		for _, k := range keys {
			if raw, ok = extractKV(line, k); ok {
				break
			}
		}
	case "regex":
		if f.re == nil {
			return
		}
		m := f.re.FindStringSubmatch(line)
		if len(m) > 1 {
			raw, ok = m[1], true
		} else if len(m) == 1 {
			raw, ok = m[0], true
		}
	case "word_map":
		src := readStringField(e, f.Source)
		if src == "" {
			return
		}
		for k, v := range f.Map {
			if strings.EqualFold(src, k) {
				raw, ok = v, true
				break
			}
		}
	case "positional":
		raw, ok = positionalValue(line, f.Pos)
	}
	if !ok || raw == "" {
		return
	}
	writeField(e, f.Target, raw, f.Type)
}

// matchEvent returns the first event whose conditions all hold.
func (d *Device) matchEvent(e *Entry, low string) string {
	for i := range d.Events {
		ev := &d.Events[i]
		if ev.matches(e, low) {
			return ev.Event
		}
	}
	return ""
}

func (ev *EventRule) matches(e *Entry, low string) bool {
	if ev.Field != "" {
		if !strings.EqualFold(readStringField(e, ev.Field), ev.Equals) {
			return false
		}
	}
	for _, needle := range ev.Contains {
		if !strings.Contains(low, strings.ToLower(needle)) {
			return false
		}
	}
	if len(ev.AnyOf) > 0 {
		found := false
		for _, needle := range ev.AnyOf {
			if strings.Contains(low, strings.ToLower(needle)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if ev.re != nil && !ev.re.MatchString(low) {
		return false
	}
	return true
}

// positionalValue returns the first or last token that looks like a value.
func positionalValue(line, pos string) (string, bool) {
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return "", false
	}
	pick := func(t []string) (string, bool) {
		for _, tok := range t {
			if tok == "" || strings.Contains(tok, "=") {
				continue
			}
			return tok, true
		}
		return "", false
	}
	if pos == "last" {
		rev := make([]string, len(tokens))
		for i, tok := range tokens {
			rev[len(tokens)-1-i] = tok
		}
		return pick(rev)
	}
	return pick(tokens)
}

// readStringField reads a column as a string, for word_map sources.
func readStringField(e *Entry, name string) string {
	switch name {
	case "src_ip":
		return e.SrcIP
	case "dst_ip":
		return e.DstIP
	case "proto":
		return e.Proto
	case "action":
		return e.Action
	case "event":
		return e.Event
	case "mac":
		return e.MAC
	case "client_mac":
		return e.ClientMAC
	case "ifname":
		return e.IfName
	case "stp_root":
		return e.STPRoot
	case "ssid":
		return e.SSID
	case "radio":
		return e.Radio
	case "eap_status":
		return e.EAPStatus
	case "ospf_nbr":
		return e.OSPFNbr
	case "gateway":
		return e.Gateway
	case "route_dst":
		return e.RouteDst
	case "dhcp_mac":
		return e.DHCPMAC
	case "device_type":
		return e.DeviceType
	}
	return ""
}

// writeField stores a raw string into the named column, coercing by type.
func writeField(e *Entry, target, raw, typ string) {
	// Number-typed targets always coerce, so YAML/line differences do not matter.
	numeric := map[string]bool{
		"dst_port": true, "src_port": true, "vlan_id": true, "reason": true,
		"signal_dbm": true, "tx_rate_mbps": true, "conntrack_count": true,
	}
	if numeric[target] || typ == "int" {
		n, ok := parseIntLoose(raw)
		if !ok {
			return
		}
		v := n
		switch target {
		case "dst_port":
			if n >= 0 && n <= 65535 {
				e.DstPort = &v
			}
		case "src_port":
			if n >= 0 && n <= 65535 {
				e.SrcPort = &v
			}
		case "vlan_id":
			if n > 0 && n <= 4094 {
				e.VLANID = &v
			}
		case "reason":
			if n >= 0 {
				e.Reason = &v
			}
		case "signal_dbm":
			e.SignalDBM = &v
		case "tx_rate_mbps":
			if n > 0 {
				e.TxRateMbps = &v
			}
		case "conntrack_count":
			if n >= 0 {
				e.ConntrackCount = &v
			}
		}
		return
	}

	switch target {
	case "src_ip":
		e.SrcIP = raw
	case "dst_ip":
		e.DstIP = raw
	case "proto":
		e.Proto = truncate(raw, 7)
	case "action":
		e.Action = truncate(raw, 15)
	case "mac":
		e.MAC = truncate(raw, 23)
	case "client_mac":
		e.ClientMAC = truncate(raw, 23)
	case "dhcp_mac":
		e.DHCPMAC = truncate(raw, 23)
	case "ifname":
		e.IfName = truncate(raw, 39)
	case "peer_ifname":
		e.PeerIfName = truncate(raw, 39)
	case "stp_root":
		e.STPRoot = truncate(raw, 39)
	case "ssid":
		e.SSID = truncate(raw, 31)
	case "radio":
		e.Radio = truncate(raw, 15)
	case "eap_status":
		e.EAPStatus = truncate(raw, 15)
	case "ospf_nbr":
		e.OSPFNbr = truncate(raw, 45)
	case "gateway":
		e.Gateway = truncate(raw, 45)
	case "route_dst":
		e.RouteDst = truncate(raw, 45)
	case "event":
		e.Event = truncate(raw, 63)
	}
}

// parseIntLoose extracts an integer from a value that may carry units.
func parseIntLoose(raw string) (int, bool) {
	s := strings.TrimSpace(raw)
	i := 0
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		i++
	}
	start := i
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	if i == start {
		return 0, false
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, false
	}
	return n, true
}

// validTarget reports whether name is a writable entry column.
func validTarget(name string) bool {
	switch name {
	case "src_ip", "dst_ip", "proto", "dst_port", "src_port", "action",
		"mac", "client_mac", "dhcp_mac", "vlan_id", "ifname", "peer_ifname",
		"stp_root", "ssid", "radio", "reason", "signal_dbm", "tx_rate_mbps",
		"eap_status", "ospf_nbr", "gateway", "route_dst", "conntrack_count",
		"event", "device_type":
		return true
	}
	return false
}

// TargetColumns lists the columns a field rule may write, for the TUI editor.
var TargetColumns = []string{
	"src_ip", "dst_ip", "proto", "dst_port", "src_port", "action",
	"mac", "client_mac", "dhcp_mac", "vlan_id", "ifname", "peer_ifname",
	"stp_root", "ssid", "radio", "reason", "signal_dbm", "tx_rate_mbps",
	"eap_status", "ospf_nbr", "gateway", "route_dst", "conntrack_count",
	"event", "device_type",
}

// Strategies lists the extraction strategies, for the TUI editor.
var Strategies = []string{"kv", "regex", "word_map", "positional"}
