// Package pipeline wires the parser to PostgreSQL and runs detection.
package pipeline

import (
	"siskamlan/internal/parser"
	"siskamlan/internal/store"
)

// ToStore converts a parsed entry into a database row.
func ToStore(e *parser.Entry) *store.LogEntry {
	if e == nil {
		return nil
	}
	return &store.LogEntry{
		Timestamp:   e.ParseTime(),
		Hostname:    e.Hostname,
		Facility:    e.Facility,
		Severity:    e.Severity,
		DeviceType:  e.DeviceType,
		Event:       e.Event,
		SrcIP:       strPtr(e.SrcIP),
		DstIP:       strPtr(e.DstIP),
		Proto:       e.Proto,
		DstPort:     e.DstPort,
		SrcPort:     e.SrcPort,
		Action:      e.Action,
		MAC:         e.MAC,
		VLANID:      e.VLANID,
		IfName:      e.IfName,
		PeerIfName:  e.PeerIfName,
		STPRoot:     e.STPRoot,
		ClientMAC:   e.ClientMAC,
		SSID:        e.SSID,
		Radio:       e.Radio,
		Reason:      e.Reason,
		SignalDBM:   e.SignalDBM,
		TxRateMbps:  e.TxRateMbps,
		EAPStatus:   e.EAPStatus,
		OSPFNbr:     strPtr(e.OSPFNbr),
		Gateway:     strPtr(e.Gateway),
		RouteDst:    e.RouteDst,
		DHCPMAC:     e.DHCPMAC,
		ConntrackCt: e.ConntrackCount,
		RawLine:     e.RawLine,
	}
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
