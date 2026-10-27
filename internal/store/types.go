// Package store owns the PostgreSQL schema and every query the pipeline and
// TUI issue. The schema is frozen to match the Python implementation so both
// versions can run against identical databases during the migration.
package store

import (
	"time"
)

// LogEntry is one parsed syslog row, mirroring the `logs` table.
//
// Pointer fields are nullable columns: a nil value is written as SQL NULL,
// which is how the parser expresses "not present in this line".
type LogEntry struct {
	Timestamp   time.Time
	Hostname    string
	Facility    string
	Severity    string
	DeviceType  string
	Event       string
	SrcIP       *string
	DstIP       *string
	Proto       string
	DstPort     *int
	SrcPort     *int
	Action      string
	MAC         string
	VLANID      *int
	IfName      string
	PeerIfName  string
	STPRoot     string
	ClientMAC   string
	SSID        string
	Radio       string
	Reason      *int
	SignalDBM   *int
	TxRateMbps  *int
	EAPStatus   string
	OSPFNbr     *string
	Gateway     *string
	RouteDst    string
	DHCPMAC     string
	ConntrackCt *int
	RawLine     string
}

// Anomaly is a detection row produced by the rules engine.
type Anomaly struct {
	Severity     string
	Description  string
	AnomalyScore *float64
	Features     []byte // JSON document
}

// Cooldown is the current merge state for a (type, entity) signature.
type Cooldown struct {
	AnomalyID   int
	RepeatCount int
	AgeSeconds  float64
}

// LogColumns is the canonical insert order. It must stay in sync with the
// `logs` schema; QueryWindow returns rows in this same layout.
var LogColumns = []string{
	"timestamp", "hostname", "facility", "severity",
	"device_type", "event", "src_ip", "dst_ip", "proto", "dst_port",
	"src_port", "action",
	"mac", "vlan_id", "ifname", "peer_ifname", "stp_root",
	"client_mac", "ssid", "radio", "reason", "signal_dbm",
	"tx_rate_mbps", "eap_status",
	"ospf_nbr", "gateway", "route_dst", "dhcp_mac", "conntrack_count",
	"raw_line",
}

// values returns the entry in LogColumns order for pgx parameter binding.
func (e *LogEntry) values() []any {
	str := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	ptrInt := func(p *int) any { return p }
	ptrStr := func(p *string) any { return p }

	return []any{
		e.Timestamp, str(e.Hostname), str(e.Facility), str(e.Severity),
		str(e.DeviceType), str(e.Event), ptrStr(e.SrcIP), ptrStr(e.DstIP),
		str(e.Proto), ptrInt(e.DstPort),
		ptrInt(e.SrcPort), str(e.Action),
		str(e.MAC), ptrInt(e.VLANID), str(e.IfName), str(e.PeerIfName),
		str(e.STPRoot),
		str(e.ClientMAC), str(e.SSID), str(e.Radio), ptrInt(e.Reason),
		ptrInt(e.SignalDBM),
		ptrInt(e.TxRateMbps), str(e.EAPStatus),
		ptrStr(e.OSPFNbr), ptrStr(e.Gateway), str(e.RouteDst), str(e.DHCPMAC),
		ptrInt(e.ConntrackCt),
		e.RawLine,
	}
}
