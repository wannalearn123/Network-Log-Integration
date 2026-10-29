package tui

import (
	"regexp"
	"strconv"
	"strings"

	"siskamlan/internal/parser"
)

// candidate is a field rule the editor can derive from a real log line.
//
// Unlike a raw keyword it carries everything needed to build a *valid*
// FieldRule: the strategy, the key or pattern to use, and a sample value
// pulled from the file so the operator can confirm it before saving.
type candidate struct {
	label    string // text shown in the picker
	target   string // column to write; empty when the operator must choose
	strategy string
	key      string
	pattern  string
	pos      string
	typ      string
	sample   string // concrete value found in the file
	origin   string // the part of the line the rule anchors on
	// needsTarget marks a fallback rule whose column could not be inferred
	// from the value. The editor then asks the operator to choose one
	// instead of guessing and writing the value somewhere unread.
	needsTarget bool
}

// candidateExtractor finds one kind of value in a raw syslog line.
//
// The regexes deliberately anchor on the words surrounding a value rather
// than matching the value shape alone: a bare `(\S+)` would happily capture
// the timestamp, which is exactly how a profile ends up "not doing shit".
type candidateExtractor struct {
	target  string
	label   string
	typ     string
	pattern string // must expose the value as capture group 1
	origin  string // human hint describing the anchor
}

var candidateExtractors = []candidateExtractor{
	{
		target: "mac", label: "mac (dotted aabb.ccdd.eeff)", typ: "string",
		pattern: `(?i)\b([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\b`,
		origin:  "aabb.ccdd.eeff token",
	},
	{
		target: "mac", label: "mac (colon aa:bb:cc:dd:ee:ff)", typ: "string",
		pattern: `(?i)\b((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\b`,
		origin:  "aa:bb:cc:dd:ee:ff token",
	},
	{
		target: "ifname", label: "ifname (after 'learned on')", typ: "string",
		pattern: `(?i)learned on\s+(\S+)`,
		origin:  "'learned on <if>'",
	},
	{
		target: "ifname", label: "ifname (after 'interface')", typ: "string",
		pattern: `(?i)interface\s+(\S+)`,
		origin:  "'interface <if>'",
	},
	{
		target: "ifname", label: "ifname (gi/fa/te/eth port)", typ: "string",
		pattern: `(?i)\b(connected|association|on)\s+((?:gi|fa|te|eth|po|vl)\d[\w/.:-]*)`,
		origin:  "vendor interface name",
	},
	{
		target: "vlan_id", label: "vlan_id (after 'vlan')", typ: "int",
		pattern: `(?i)\bvlan\s+(\d+)`,
		origin:  "'vlan <n>'",
	},
	{
		target: "src_ip", label: "src_ip (after SRC=)", typ: "ip",
		pattern: `(?i)\bSRC=([0-9]{1,3}(?:\.[0-9]{1,3}){3})`,
		origin:  "SRC=<ip>",
	},
	{
		target: "dst_ip", label: "dst_ip (after DST=)", typ: "ip",
		pattern: `(?i)\bDST=([0-9]{1,3}(?:\.[0-9]{1,3}){3})`,
		origin:  "DST=<ip>",
	},
	{
		target: "src_port", label: "src_port (after SPT=)", typ: "int",
		pattern: `(?i)\bSPT=(\d+)`,
		origin:  "SPT=<port>",
	},
	{
		target: "dst_port", label: "dst_port (after DPT=)", typ: "int",
		pattern: `(?i)\bDPT=(\d+)`,
		origin:  "DPT=<port>",
	},
	{
		target: "proto", label: "proto (after PROTO=)", typ: "string",
		pattern: `(?i)\bPROTO=(\S+)`,
		origin:  "PROTO=<proto>",
	},
	{
		target: "action", label: "action (FW ALLOW/DROP)", typ: "string",
		pattern: `\[FW\s+(ALLOW|DROP|REJECT|DENY)\]`,
		origin:  "[FW <action>]",
	},
	{
		target: "ssid", label: "ssid (after SSID)", typ: "string",
		pattern: `(?i)SSID[=:\s]+([^\s,;)]+)`,
		origin:  "SSID <name>",
	},
	{
		target: "signal_dbm", label: "signal_dbm", typ: "int",
		pattern: `(?i)(?:signal|rssi)[=:\s]+(-?\d+)`,
		origin:  "signal=<dbm>",
	},
	{
		target: "gateway", label: "gateway", typ: "ip",
		pattern: `(?i)gateway[=:\s]+([0-9]{1,3}(?:\.[0-9]{1,3}){3})`,
		origin:  "gateway=<ip>",
	},
}

// domainWords are tokens that look like values but are really protocol,
// hostname, or log-noise words. They are rejected as positional candidates
// because anchoring on them produces useless rules.
var domainWords = map[string]bool{
	"hostapd": true, "wpa_supplicant": true, "kernel": true, "systemd": true,
	"kernel:": true, "daemon": true, "connected": true, "associated": true,
	"deauthenticated": true, "disassociated": true, "success": true,
	"failed": true, "failure": true, "info": true, "error": true,
	"warning": true, "notice": true, "debug": true, "user": true,
	"learned": true, "moved": true, "changed": true, "removed": true,
	"added": true, "from": true, "on": true, "to": true, "and": true,
	"with": true, "for": true, "the": true, "via": true, "vlan": true,
}

// buildCandidates scans the sample lines and returns every rule the editor
// can offer. kv rules come from `KEY=value` pairs, regex tricks come from
// the anchor table, and a few positional picks are offered for prose-style
// vendor logs that have neither.
func buildCandidates(lines []string) []candidate {
	var out []candidate
	seen := map[string]bool{}
	add := func(c candidate) {
		// A candidate with no plausible column is noise: accepting it would
		// write a value nowhere. Drop it instead of showing a blank target,
		// unless the rule is an explicit "pick the column yourself" fallback.
		if strings.TrimSpace(c.target) == "" && !c.needsTarget {
			return
		}
		id := c.target + "|" + c.strategy + "|" + c.key + "|" + c.pattern
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, c)
	}

	// 1. kv pairs: the cheapest rule when the vendor uses KEY=value.
	for _, line := range lines {
		for _, m := range kvTokenRe.FindAllStringSubmatch(line, -1) {
			key, value := m[1], m[2]
			add(candidate{
				label:    key + "=" + truncateWidth(value, 20),
				target:   guessTarget(key, value),
				strategy: "kv",
				key:      key,
				typ:      guessType(value),
				sample:   value,
				origin:   key + "=",
			})
		}
	}

	// 2. anchored regex patterns: required for vendors with no key=value.
	for _, ex := range candidateExtractors {
		re, err := regexp.Compile(ex.pattern)
		if err != nil {
			continue
		}
		for _, line := range lines {
			m := re.FindStringSubmatch(line)
			if len(m) < 2 {
				continue
			}
			value := m[len(m)-1] // last group is the value in every entry above
			if value == "" {
				continue
			}
			add(candidate{
				label:    ex.label + " → " + truncateWidth(value, 18),
				target:   ex.target,
				strategy: "regex",
				pattern:  ex.pattern,
				typ:      ex.typ,
				sample:   value,
				origin:   ex.origin,
			})
			break // one sample per pattern is enough
		}
	}

	// 3. positional fallback: first/last value-shaped token in the message.
	//
	// This is a last resort. It proposes a target guessed from the token
	// itself, so it is only offered when nothing better was found, and only
	// for tokens that are not already captured by an anchored extractor —
	// otherwise it suggests nonsense like writing a MAC into `action`.
	if len(out) == 0 {
		for _, line := range lines {
			toks := positionalTokens(line)
			if len(toks) == 0 {
				continue
			}
			for _, pick := range []struct{ pos string; val string }{
				{"first", toks[0]},
				{"last", toks[len(toks)-1]},
			} {
				// Skip tokens that an anchored extractor already covers.
				if coveredByExtractor(pick.val) {
					continue
				}
				target := guessTarget(pick.val, pick.val)
				add(candidate{
					label:       pick.pos + " value → " + truncateWidth(pick.val, 18),
					target:      target,
					strategy:    "positional",
					pos:         pick.pos,
					typ:         guessType(pick.val),
					sample:      pick.val,
					origin:      pick.pos + " token",
					needsTarget: target == "",
				})
			}
		}
	}
	return out
}

// coveredByExtractor reports whether an anchored extractor already finds this
// value, which makes a positional rule for it both redundant and unreliable.
func coveredByExtractor(value string) bool {
	for _, ex := range candidateExtractors {
		re, err := regexp.Compile(ex.pattern)
		if err != nil {
			continue
		}
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// messageBody strips the syslog envelope so positional picks look at the
// vendor message rather than the timestamp and hostname.
func messageBody(line string) string {
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return ""
	}
	// Drop timestamp, hostname, and the `tag:` that follows them.
	start := 0
	if len(tokens) > 3 {
		start = 3
	}
	return strings.Join(tokens[start:], " ")
}

// positionalTokens returns value-shaped tokens from the message body.
func positionalTokens(line string) []string {
	var out []string
	for _, tok := range strings.Fields(messageBody(line)) {
		clean := strings.Trim(tok, `,;()[]"'`)
		if clean == "" || strings.Contains(clean, "=") {
			continue
		}
		if domainWords[strings.ToLower(clean)] {
			continue
		}
		if !looksLikeValue(clean) {
			continue
		}
		out = append(out, clean)
	}
	return out
}

// looksLikeValue keeps identifiers that plausibly hold network data.
func looksLikeValue(s string) bool {
	if len(s) < 3 || len(s) > 40 {
		return false
	}
	hasDigit := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c == '.', c == '-', c == ':', c == '/':
		default:
			return false
		}
	}
	return hasDigit
}

func reverseStrings(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[len(in)-1-i] = s
	}
	return out
}

// guessType picks a value type from the token shape.
func guessType(v string) string {
	if isIPv4(v) {
		return "ip"
	}
	if _, err := strconv.Atoi(v); err == nil {
		return "int"
	}
	return "string"
}

// rule turns a candidate into a field rule ready to append to a device.
func (c candidate) rule() parser.FieldRule {
	return parser.FieldRule{
		Target:   c.target,
		Strategy: c.strategy,
		Key:      c.key,
		Pattern:  c.pattern,
		Pos:      c.pos,
		Type:     c.typ,
	}
}

// preview shows what this single rule extracts from the line, so the
// operator sees the value before committing the rule to the config.
func (c candidate) preview() string {
	if c.sample == "" {
		return "(no match)"
	}
	return c.sample
}
