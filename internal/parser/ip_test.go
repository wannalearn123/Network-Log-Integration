package parser

import "testing"

func TestCleanIP(t *testing.T) {
	cases := []struct{ in, want string }{
		// IPv4
		{"10.0.0.5", "10.0.0.5"},
		{"10.0.0.5:443", "10.0.0.5"},
		{"172.20.0.4", "172.20.0.4"},
		// IPv6, must survive intact
		{"fe80:0000:0000:0000:2481:d6ff:fea2:2a69", "fe80::2481:d6ff:fea2:2a69"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:db8::1:443", "2001:db8::1:443"}, // ambiguous, kept whole
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[::1]", "::1"},
		// Junk passes through for the store to reject
		{"not-an-ip", "not-an-ip"},
		{"", ""},
	}
	for _, c := range cases {
		if got := CleanIP(c.in); got != c.want {
			t.Errorf("CleanIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidIP(t *testing.T) {
	valid := []string{
		"10.0.0.1", "fe80::1", "2001:db8::1",
		"172.20.100.0/24", "2001:db8::/32",
	}
	for _, s := range valid {
		if !ValidIP(s) {
			t.Errorf("ValidIP(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "fe80", "ff02", "172.", "abc", "1.2.3", "1.2.3.4.5"}
	for _, s := range invalid {
		if ValidIP(s) {
			t.Errorf("ValidIP(%q) = true, want false", s)
		}
	}
}

func TestIsIPv4AndIPv6(t *testing.T) {
	if !IsIPv4("10.0.0.1") || IsIPv4("fe80::1") {
		t.Error("IsIPv4 misclassified")
	}
	if !IsIPv6("fe80::1") || IsIPv6("10.0.0.1") {
		t.Error("IsIPv6 misclassified")
	}
	if !IsIPv6("2001:db8::/32") {
		t.Error("IPv6 prefix not recognised")
	}
	if IsIPv6("fe80") || IsIPv6("") {
		t.Error("IsIPv6 accepted a fragment")
	}
}

// TestParseIPv6ViaKV is the regression test for the truncation bug.
func TestParseIPv6ViaKV(t *testing.T) {
	line := "2026-01-02T03:04:05+00:00 lab-firewall kernel: [UFW BLOCK] IN=eth0 " +
		"SRC=fe80:0000:0000:0000:2481:d6ff:fea2:2a69 " +
		"DST=ff02:0000:0000:0000:0000:0000:0000:0001 PROTO=UDP SPT=5678 DPT=5678"
	e := Parse(line)
	if !IsIPv6(e.SrcIP) {
		t.Fatalf("src_ip = %q, want a valid IPv6 address", e.SrcIP)
	}
	if e.SrcIP != "fe80::2481:d6ff:fea2:2a69" {
		t.Fatalf("src_ip = %q, want canonical fe80::2481:d6ff:fea2:2a69", e.SrcIP)
	}
	if !IsIPv6(e.DstIP) || e.DstIP != "ff02::1" {
		t.Fatalf("dst_ip = %q, want ff02::1", e.DstIP)
	}
}

// TestParseIPv6LowercaseKeys covers vendor-style keys.
func TestParseIPv6LowercaseKeys(t *testing.T) {
	e := Parse("2026-01-02T03:04:05+00:00 fw tag: src=2001:db8::1 dst=2001:db8::2 dpt=443")
	if e.SrcIP != "2001:db8::1" || e.DstIP != "2001:db8::2" {
		t.Fatalf("ips = %q / %q", e.SrcIP, e.DstIP)
	}
}

// TestParseIPv4PortStillStripped ensures the colon fix did not regress IPv4.
func TestParseIPv4PortStillStripped(t *testing.T) {
	e := Parse("2026-01-02T03:04:05+00:00 fw tag: SRC=10.0.0.5:443 DST=10.0.0.6:8080")
	if e.SrcIP != "10.0.0.5" {
		t.Fatalf("src_ip = %q, want 10.0.0.5 (port stripped)", e.SrcIP)
	}
	if e.DstIP != "10.0.0.6" {
		t.Fatalf("dst_ip = %q, want 10.0.0.6 (port stripped)", e.DstIP)
	}
}

// TestParseIPv6OSPFNeighbour checks the token copier keeps colons.
func TestParseIPv6OSPFNeighbour(t *testing.T) {
	e := Parse("2026-01-02T03:04:05+00:00 router.example rgos: %OSPF-5-ADJCHG Nbr 2001:db8::9 from FULL to DOWN")
	if e.OSPFNbr != "2001:db8::9" {
		t.Fatalf("ospf_nbr = %q, want 2001:db8::9", e.OSPFNbr)
	}
}

// TestParseIPv6Gateway checks gateway keeps its colons.
func TestParseIPv6Gateway(t *testing.T) {
	e := Parse("2026-01-02T03:04:05+00:00 router.example route: route added gateway=2001:db8::1")
	if e.Gateway != "2001:db8::1" {
		t.Fatalf("gateway = %q, want 2001:db8::1", e.Gateway)
	}
}

// TestParseIPv6Positional checks the fallback scanner finds IPv6.
func TestParseIPv6Positional(t *testing.T) {
	e := Parse("2026-01-02T03:04:05+00:00 host tag: connection from 2001:db8::5 to 2001:db8::6")
	if !IsIPv6(e.SrcIP) || !IsIPv6(e.DstIP) {
		t.Fatalf("positional IPv6 not extracted: %q / %q", e.SrcIP, e.DstIP)
	}
}
