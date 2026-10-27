package parser

import "testing"

func TestPriorityAndFacility(t *testing.T) {
	e := Parse("<134>1 2026-01-02T03:04:05Z host.example firewall: message")
	if e == nil {
		t.Fatal("nil entry")
	}
	if e.Facility != "local0" || e.Severity != "info" {
		t.Fatalf("facility/severity = %q/%q, want local0/info", e.Facility, e.Severity)
	}
	if e.Hostname != "host.example" {
		t.Fatalf("hostname = %q", e.Hostname)
	}
}

func TestNoPriorityDefaults(t *testing.T) {
	e := Parse("2026-01-02T03:04:05+00:00 host.example tag: hello")
	if e.Facility != "user" || e.Severity != "info" {
		t.Fatalf("defaults = %q/%q, want user/info", e.Facility, e.Severity)
	}
}

func TestTraditionalTimestamp(t *testing.T) {
	e := Parse("Oct 27 05:46:39 host.example tag: hello")
	if len(e.Timestamp) == 0 || e.Timestamp[4] != '-' {
		t.Fatalf("timestamp not normalized: %q", e.Timestamp)
	}
	if e.Hostname != "host.example" {
		t.Fatalf("hostname = %q, want host.example", e.Hostname)
	}
}

func TestMikroTikSlashTimestamp(t *testing.T) {
	e := Parse("Oct/27 05:46:39 host.example tag: hello")
	if e.Hostname != "host.example" {
		t.Fatalf("hostname = %q, want host.example (slash-form timestamp)", e.Hostname)
	}
}

func TestDeviceTypeDetection(t *testing.T) {
	cases := map[string]string{
		"router.monitoringsystembak_building-lan":   "router",
		"switch.monitoringsystembak_building-lan":   "switch",
		"ap.monitoringsystembak_building-lan":       "ap",
		"firewall.monitoringsystembak_building-lan": "firewall",
		"lab-firewall.lab-mgmt":                     "firewall",
		"random-host":                               "other",
	}
	for host, want := range cases {
		e := Parse("2026-01-02T03:04:05+00:00 " + host + " tag: x")
		if e.DeviceType != want {
			t.Errorf("host %q -> %q, want %q", host, e.DeviceType, want)
		}
	}
}

func TestMACForms(t *testing.T) {
	colon := Parse("2026-01-02T03:04:05+00:00 switch.example sw: Host aa:bb:cc:dd:ee:ff learned on Gi0/4 vlan 12")
	if colon.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("colon MAC = %q", colon.MAC)
	}
	if colon.VLANID == nil || *colon.VLANID != 12 {
		t.Fatalf("vlan = %v, want 12", colon.VLANID)
	}
	if colon.Event != "mac_learn" {
		t.Fatalf("event = %q, want mac_learn", colon.Event)
	}

	dot := Parse("2026-01-02T03:04:05+00:00 switch.example sw: Host 067b.4438.5d0f learned on Gi0/4 vlan 12")
	if dot.MAC != "067b.4438.5d0f" {
		t.Fatalf("dot MAC = %q", dot.MAC)
	}
}

func TestPortsAndProtocol(t *testing.T) {
	e := Parse("2026-01-02T03:04:05+00:00 fw.example fw: [FW DROP] IN=eth0 SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP SPT=1234 DPT=22")
	if e.DstPort == nil || *e.DstPort != 22 {
		t.Fatalf("dst_port = %v, want 22", e.DstPort)
	}
	if e.SrcPort == nil || *e.SrcPort != 1234 {
		t.Fatalf("src_port = %v, want 1234", e.SrcPort)
	}
	if e.Proto != "TCP" {
		t.Fatalf("proto = %q", e.Proto)
	}
	if e.Action != "deny" || e.Event != "fw_block" {
		t.Fatalf("action/event = %q/%q", e.Action, e.Event)
	}
	if e.SrcIP != "10.0.0.1" || e.DstIP != "10.0.0.2" {
		t.Fatalf("ips = %q/%q", e.SrcIP, e.DstIP)
	}
}

func TestCEFProtoNumeric(t *testing.T) {
	e := Parse("2026-01-02T03:04:05+00:00 fw.example fortigate: CEF:0|Fortinet|FortiGate|v7.0.0|00010|traffic:forward allow|3|src=172.20.100.10 dst=172.20.0.4 spt=21361 dpt=3306 proto=17 act=close")
	if e.Proto != "UDP" {
		t.Fatalf("proto = %q, want UDP", e.Proto)
	}
	if e.Action != "close" {
		t.Fatalf("action = %q, want close", e.Action)
	}
}

func TestSTPRootAndFlapPeer(t *testing.T) {
	e := Parse("2026-01-02T03:04:05+00:00 switch.example rgos: %SPANTREE-5-ROOTCHANGE: Root changed on VLAN1 - new root Gi0/5")
	if e.STPRoot != "Gi0/5" {
		t.Fatalf("stp_root = %q, want Gi0/5", e.STPRoot)
	}
	if e.Event != "stp_event" {
		t.Fatalf("event = %q", e.Event)
	}

	f := Parse("2026-01-02T03:04:05+00:00 switch.example rgos: %SW_MATM-4-MACFLAP_NOTIF: Host aa:bb:cc:dd:ee:ff in vlan 12 is flapping between port Gi0/4 and port Gi0/6")
	if f.PeerIfName != "Gi0/6" {
		t.Fatalf("peer_ifname = %q, want Gi0/6", f.PeerIfName)
	}
	if f.Event != "mac_flap" {
		t.Fatalf("event = %q", f.Event)
	}
}

func TestAPFields(t *testing.T) {
	e := Parse("2026-01-02T03:04:05+00:00 ap.example hostapd: wlan0: STA aa:bb:cc:dd:ee:ff signal=-45 tx_rate=29Mbps")
	if e.ClientMAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("client_mac = %q", e.ClientMAC)
	}
	if e.Radio != "wlan0" {
		t.Fatalf("radio = %q", e.Radio)
	}
	if e.SignalDBM == nil || *e.SignalDBM != -45 {
		t.Fatalf("signal = %v, want -45", e.SignalDBM)
	}
	if e.TxRateMbps == nil || *e.TxRateMbps != 29 {
		t.Fatalf("tx_rate = %v, want 29", e.TxRateMbps)
	}
}

func TestEmptyLine(t *testing.T) {
	if Parse("") != nil {
		t.Fatal("empty line should parse to nil")
	}
	if Parse("\n") != nil {
		t.Fatal("newline-only line should parse to nil")
	}
}
