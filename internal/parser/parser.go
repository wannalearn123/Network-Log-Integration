// Package parser turns a raw syslog line into a structured Entry.
//
// This is a faithful port of the original C parser (collector/src). To keep
// the migration honest, tests/parser_parity_test.go replays every captured
// sample through this package and compares the result field-for-field with
// the JSON the C collector produced.
package parser

import (
	"strings"
	"time"
)

// Entry is a parsed syslog line. Optional fields are pointers or empty
// strings and are omitted from JSON when unset, matching the C output.
type Entry struct {
	Timestamp  string `json:"timestamp"`
	Hostname   string `json:"hostname"`
	Facility   string `json:"facility"`
	Severity   string `json:"severity"`
	DeviceType string `json:"device_type"`
	Event      string `json:"event"`

	SrcIP          string `json:"src_ip,omitempty"`
	DstIP          string `json:"dst_ip,omitempty"`
	Proto          string `json:"proto,omitempty"`
	DstPort        *int   `json:"dst_port,omitempty"`
	SrcPort        *int   `json:"src_port,omitempty"`
	Action         string `json:"action,omitempty"`
	MAC            string `json:"mac,omitempty"`
	VLANID         *int   `json:"vlan_id,omitempty"`
	IfName         string `json:"ifname,omitempty"`
	PeerIfName     string `json:"peer_ifname,omitempty"`
	STPRoot        string `json:"stp_root,omitempty"`
	ClientMAC      string `json:"client_mac,omitempty"`
	SSID           string `json:"ssid,omitempty"`
	Radio          string `json:"radio,omitempty"`
	Reason         *int   `json:"reason,omitempty"`
	SignalDBM      *int   `json:"signal_dbm,omitempty"`
	TxRateMbps     *int   `json:"tx_rate_mbps,omitempty"`
	EAPStatus      string `json:"eap_status,omitempty"`
	OSPFNbr        string `json:"ospf_nbr,omitempty"`
	Gateway        string `json:"gateway,omitempty"`
	RouteDst       string `json:"route_dst,omitempty"`
	DHCPMAC        string `json:"dhcp_mac,omitempty"`
	ConntrackCount *int   `json:"conntrack_count,omitempty"`

	RawLine string `json:"raw_line"`
}

// Parse extracts a structured entry from one raw syslog line.
func Parse(line string) *Entry {
	if line == "" {
		return nil
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil
	}

	e := &Entry{RawLine: line}
	p := 0
	p = parsePriority(e, line, p)
	p = parseTimestamp(e, line, p)
	p = parseHostname(e, line, p)
	p = skipTag(line, p)

	detectDeviceType(e)
	extractFields(e, line)
	return e
}

// ParseTime converts the entry timestamp to time.Time.
func (e *Entry) ParseTime() time.Time {
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05Z07:00",
	} {
		if t, err := time.Parse(layout, e.Timestamp); err == nil {
			return t
		}
	}
	return time.Now().UTC()
}

func facilityName(n int) string {
	names := []string{
		"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
		"uucp", "cron", "authpriv", "ftp", "ntp", "security", "console",
		"solaris-cron", "local0", "local1", "local2", "local3", "local4",
		"local5", "local6", "local7",
	}
	if n >= 0 && n < len(names) {
		return names[n]
	}
	return "unknown"
}

func severityName(n int) string {
	names := []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}
	if n >= 0 && n < len(names) {
		return names[n]
	}
	return "unknown"
}

// parsePriority reads the <PRI> prefix and returns the next cursor.
func parsePriority(e *Entry, line string, p int) int {
	if p < len(line) && line[p] == '<' {
		p++
		start := p
		for p < len(line) && isDigit(line[p]) {
			p++
		}
		pri := atoi(line[start:p])
		e.Facility = facilityName(pri / 8)
		e.Severity = severityName(pri % 8)

		for p < len(line) && line[p] != '>' {
			p++
		}
		if p < len(line) && line[p] == '>' {
			p++
		}
		// RFC 5424 version number.
		if p < len(line) && isDigit(line[p]) {
			for p < len(line) && isDigit(line[p]) {
				p++
			}
			for p < len(line) && line[p] == ' ' {
				p++
			}
		}
	} else {
		e.Facility = "user"
		e.Severity = "info"
	}
	for p < len(line) && line[p] == ' ' {
		p++
	}
	return p
}

var monthNames = []string{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
}

// parseTimestamp reads an ISO or traditional timestamp and returns the cursor.
func parseTimestamp(e *Entry, line string, p int) int {
	if p < len(line) && isDigit(line[p]) && p+4 < len(line) && line[p+4] == '-' {
		start := p
		for p < len(line) && line[p] != ' ' {
			p++
		}
		e.Timestamp = line[start:p]
		if len(e.Timestamp) > 63 {
			e.Timestamp = e.Timestamp[:63]
		}
		for p < len(line) && line[p] == ' ' {
			p++
		}
		return p
	}

	// Traditional "MMM DD HH:MM:SS" or MikroTik "MMM/DD HH:MM:SS".
	month, day, hh, mm, ss, end := parseTraditional(line, p)
	if month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
		hh >= 0 && hh <= 23 && mm >= 0 && mm <= 59 && ss >= 0 && ss <= 60 {
		year := time.Now().UTC().Year()
		e.Timestamp = sprintf4(year, month, day, hh, mm, ss)
		p = end
	} else {
		// Unparseable: use received time so the row stays insertable.
		e.Timestamp = time.Now().UTC().Format("2006-01-02T15:04:05+00:00")
	}

	for p < len(line) && line[p] == ' ' {
		p++
	}
	return p
}

// parseTraditional parses a traditional syslog timestamp starting at p and
// returns the components plus the index just past the consumed text.
func parseTraditional(line string, p int) (month, day, hh, mm, ss, end int) {
	end = p
	if p >= len(line) || !isAlpha(line[p]) {
		return 0, 0, 0, 0, 0, p
	}
	mon := take(line, p, 3)
	m := monthIndex(mon)
	if m == 0 {
		return 0, 0, 0, 0, 0, p
	}
	q := p + 3
	slashForm := q < len(line) && line[q] == '/'
	if slashForm {
		q++
	} else if q < len(line) && line[q] == ' ' {
		q++
	} else {
		return 0, 0, 0, 0, 0, p
	}

	d, q2, ok := takeInt(line, q)
	if !ok {
		return 0, 0, 0, 0, 0, p
	}
	if q2 >= len(line) || line[q2] != ' ' {
		return 0, 0, 0, 0, 0, p
	}
	q2++
	h, q3, ok := takeInt(line, q2)
	if !ok || q3 >= len(line) || line[q3] != ':' {
		return 0, 0, 0, 0, 0, p
	}
	q3++
	mi, q4, ok := takeInt(line, q3)
	if !ok || q4 >= len(line) || line[q4] != ':' {
		return 0, 0, 0, 0, 0, p
	}
	q4++
	s, q5, ok := takeInt(line, q4)
	if !ok {
		return 0, 0, 0, 0, 0, p
	}
	return m, d, h, mi, s, q5
}

func monthIndex(mon string) int {
	for i, name := range monthNames {
		if name == mon {
			return i + 1
		}
	}
	return 0
}

func sprintf4(year, month, day, hh, mm, ss int) string {
	return pad4(year) + "-" + pad2(month) + "-" + pad2(day) + "T" +
		pad2(hh) + ":" + pad2(mm) + ":" + pad2(ss) + "+00:00"
}

// parseHostname reads the hostname token and skips trailing separators.
func parseHostname(e *Entry, line string, p int) int {
	var b strings.Builder
	for p < len(line) && line[p] != ' ' && line[p] != ':' && b.Len() < 63 {
		b.WriteByte(line[p])
		p++
	}
	e.Hostname = b.String()
	for p < len(line) && (line[p] == ' ' || line[p] == ':') {
		p++
	}
	return p
}

// skipTag advances past the "tag: " separator to the message body.
func skipTag(line string, p int) int {
	for p < len(line) {
		if line[p] == ':' && p+1 < len(line) && line[p+1] == ' ' {
			p += 2
			break
		}
		if line[p] == ':' && (p+1 >= len(line) || line[p+1] != ' ') {
			p++
			continue
		}
		p++
	}
	for p < len(line) && line[p] == ' ' {
		p++
	}
	return p
}
