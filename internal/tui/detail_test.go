package tui

import (
	"strings"
	"testing"
	"time"

	"siskamlan/internal/store"
)

// TestDetailShowsOnlyPopulatedFields pins the behaviour of the original
// Textual modal: a firewall row lists its handful of real columns instead of
// thirty "—" placeholders.
func TestDetailShowsOnlyPopulatedFields(t *testing.T) {
	src := "172.20.100.25"
	dst := "172.20.0.4"
	port := 443
	row := &store.LogEntry{
		Timestamp:  time.Date(2026, 10, 27, 18, 0, 0, 0, time.UTC),
		Hostname:   "fw-1",
		Facility:   "user",
		Severity:   "info",
		DeviceType: "firewall",
		Event:      "fw_block",
		SrcIP:      &src,
		DstIP:      &dst,
		DstPort:    &port,
		Action:     "deny",
		RawLine:    "raw line",
	}

	out := newLogDetail(row).view(110, 40)

	// Populated fields must be present.
	for _, want := range []string{"timestamp", "hostname", "device_type", "event",
		"src_ip", "dst_ip", "dst_port", "action", "raw_line", src, dst, "443"} {
		if !strings.Contains(out, want) {
			t.Errorf("detail missing populated field %q", want)
		}
	}

	// Unset fields must be absent entirely, not rendered as a dash.
	for _, unwanted := range []string{"ssid", "radio", "signal_dbm", "tx_rate_mbps",
		"vlan_id", "ifname", "peer_ifname", "stp_root", "client_mac", "eap_status",
		"ospf_nbr", "gateway", "route_dst", "dhcp_mac", "conntrack_count",
		"src_port", "reason", "mac"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("detail lists empty field %q", unwanted)
		}
	}

	// No placeholder dash should appear in a fully populated-enough row.
	if strings.Contains(out, "—") {
		t.Errorf("detail rendered a placeholder dash:\n%s", out)
	}
}

// TestDetailShowsWirelessFields checks a different device class surfaces its
// own columns, proving the filtering is value-driven rather than hard-coded.
func TestDetailShowsWirelessFields(t *testing.T) {
	sig := -61
	rate := 300
	row := &store.LogEntry{
		Timestamp:  time.Date(2026, 10, 27, 18, 0, 0, 0, time.UTC),
		Hostname:   "ap-1",
		DeviceType: "ap",
		Event:      "client_connect",
		ClientMAC:  "aa:bb:cc:dd:ee:ff",
		SSID:       "corp",
		Radio:      "5GHz",
		SignalDBM:  &sig,
		TxRateMbps: &rate,
		EAPStatus:  "success",
	}
	out := newLogDetail(row).view(110, 40)
	for _, want := range []string{"ssid", "corp", "radio", "5GHz", "signal_dbm", "-61",
		"tx_rate_mbps", "300", "eap_status", "success"} {
		if !strings.Contains(out, want) {
			t.Errorf("wireless detail missing %q", want)
		}
	}
	// Firewall-only columns stay hidden.
	for _, unwanted := range []string{"src_ip", "dst_ip", "action", "vlan_id"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("wireless detail lists empty field %q", unwanted)
		}
	}
}

// TestAnomalyDetailOmitsUnsetFields keeps the detection card equally terse.
func TestAnomalyDetailOmitsUnsetFields(t *testing.T) {
	a := store.AnomalyRow{
		ID:          7,
		Timestamp:   time.Date(2026, 10, 27, 18, 0, 0, 0, time.UTC),
		Severity:    "HIGH",
		Description: "Port scan",
		RepeatCount: 3,
	}
	out := newAnomalyDetail(a).view(110, 40)
	if strings.Contains(out, "anomaly_score") {
		t.Error("unset score was rendered")
	}
	if strings.Contains(out, "window_start") || strings.Contains(out, "window_end") {
		t.Error("unset window bounds were rendered")
	}
	for _, want := range []string{"id", "severity", "HIGH", "description", "Port scan", "repeat_count", "3"} {
		if !strings.Contains(out, want) {
			t.Errorf("anomaly detail missing %q", want)
		}
	}
}

// TestDetailWrapsLongRawLine checks the raw document is wrapped, not clipped.
func TestDetailWrapsLongRawLine(t *testing.T) {
	raw := strings.Repeat("abcdefghij ", 40)
	row := &store.LogEntry{Timestamp: time.Now(), RawLine: raw}
	out := newLogDetail(row).view(90, 60)
	if widestLine(out) > 90 {
		t.Fatalf("detail overflowed 90 cells: %d", widestLine(out))
	}
	if !strings.Contains(out, "raw_line") {
		t.Error("raw line section missing")
	}
}

// TestNotifyExpires checks transient status messages clear themselves instead
// of sitting on the footer forever.
func TestNotifyExpires(t *testing.T) {
	m := &Model{}
	m.setNotify("paused")
	if m.notify != "paused" {
		t.Fatalf("notify = %q", m.notify)
	}
	// Not yet expired.
	m.expireNotify()
	if m.notify == "" {
		t.Fatal("notify expired immediately")
	}
	// Pretend the deadline passed.
	m.notifyUntil = time.Now().Add(-time.Second)
	m.expireNotify()
	if m.notify != "" {
		t.Fatalf("stale notify survived: %q", m.notify)
	}
}
