package tui

import (
	"fmt"
	"strconv"
	"strings"

	"siskamlan/internal/parser"
)

// previewRow is one structured column produced by the current profile.
type previewRow struct {
	column string
	value  string
}

// previewLine parses one raw line with the editor's *unsaved* config and
// returns the columns it fills.
//
// Running the real parser.Parser (rather than re-implementing the rules in
// the TUI) is deliberate: the preview then cannot drift from what the
// ingester will actually store.
func previewLine(cfg parser.Config, line string) ([]previewRow, error) {
	if strings.TrimSpace(line) == "" {
		return nil, fmt.Errorf("no sample line to preview")
	}
	p, err := parser.NewParser(&cfg)
	if err != nil {
		return nil, err
	}
	e := p.Parse(line)
	if e == nil {
		return nil, fmt.Errorf("line could not be parsed")
	}
	return entryRows(e), nil
}

// entryRows flattens an entry into the columns worth showing.
func entryRows(e *parser.Entry) []previewRow {
	var rows []previewRow
	add := func(col, val string) {
		if strings.TrimSpace(val) == "" {
			return
		}
		rows = append(rows, previewRow{column: col, value: val})
	}
	addInt := func(col string, v *int) {
		if v == nil {
			return
		}
		add(col, strconv.Itoa(*v))
	}

	add("timestamp", e.Timestamp)
	add("hostname", e.Hostname)
	add("facility", e.Facility)
	add("severity", e.Severity)
	add("device_type", e.DeviceType)
	add("event", e.Event)
	add("src_ip", e.SrcIP)
	add("dst_ip", e.DstIP)
	add("proto", e.Proto)
	addInt("src_port", e.SrcPort)
	addInt("dst_port", e.DstPort)
	add("action", e.Action)
	add("mac", e.MAC)
	add("client_mac", e.ClientMAC)
	add("dhcp_mac", e.DHCPMAC)
	addInt("vlan_id", e.VLANID)
	add("ifname", e.IfName)
	add("peer_ifname", e.PeerIfName)
	add("ssid", e.SSID)
	add("radio", e.Radio)
	addInt("signal_dbm", e.SignalDBM)
	addInt("tx_rate_mbps", e.TxRateMbps)
	add("eap_status", e.EAPStatus)
	add("ospf_nbr", e.OSPFNbr)
	add("gateway", e.Gateway)
	add("route_dst", e.RouteDst)
	addInt("conntrack_count", e.ConntrackCount)
	return rows
}
