package parser

import (
	"strings"
	"testing"
)

func compileCfg(t *testing.T, raw string) *Parser {
	t.Helper()
	cfg, err := DecodeConfig([]byte(raw))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	p, err := NewParser(&cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

// A configured device overrides built-in extraction for matching hostnames.
func TestConfigOverridesFields(t *testing.T) {
	p := compileCfg(t, `
version: 1
devices:
  - name: customfw
    hostname_match: ['^custom-fw']
    device_type: firewall
    fields:
      - {target: src_ip,   strategy: kv, key: from}
      - {target: dst_ip,   strategy: kv, key: to}
      - {target: dst_port, strategy: kv, key: dport, type: int}
    events:
      - {event: custom_drop, contains: ['DENIED']}
`)
	line := "2026-01-02T03:04:05+00:00 custom-fw-1 daemon: DENIED from=10.1.2.3 to=10.9.9.9 dport=8443"
	e := p.Parse(line)
	if e == nil {
		t.Fatal("nil entry")
	}
	if e.DeviceType != "firewall" {
		t.Fatalf("device_type = %q", e.DeviceType)
	}
	if e.SrcIP != "10.1.2.3" || e.DstIP != "10.9.9.9" {
		t.Fatalf("ips = %q/%q", e.SrcIP, e.DstIP)
	}
	if e.DstPort == nil || *e.DstPort != 8443 {
		t.Fatalf("dst_port = %v, want 8443", e.DstPort)
	}
	if e.Event != "custom_drop" {
		t.Fatalf("event = %q, want custom_drop", e.Event)
	}
}

// Hosts that do not match any device keep the built-in behaviour.
func TestConfigLeavesOtherHostsAlone(t *testing.T) {
	p := compileCfg(t, `
version: 1
devices:
  - name: customfw
    hostname_match: ['^custom-fw']
    events:
      - {event: custom_drop, contains: ['DENIED']}
`)
	line := "2026-01-02T03:04:05+00:00 switch.example rgos: %MATM-5-LEARN: Host aa:bb:cc:dd:ee:ff learned on Gi0/4 vlan 12"
	e := p.Parse(line)
	if e.Event != "mac_learn" {
		t.Fatalf("event = %q, want mac_learn (built-in parser)", e.Event)
	}
	if e.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("mac = %q", e.MAC)
	}
}

// A nil config must be identical to the package-level Parse.
func TestNilConfigMatchesBuiltin(t *testing.T) {
	p, err := NewParser(nil)
	if err != nil {
		t.Fatal(err)
	}
	line := "2026-01-02T03:04:05+00:00 ap.example hostapd: wlan0: AP-STA-CONNECTED aa:bb:cc:dd:ee:ff"
	a, b := Parse(line), p.Parse(line)
	if a.Event != b.Event || a.ClientMAC != b.ClientMAC || a.DeviceType != b.DeviceType {
		t.Fatalf("nil config diverged: %+v vs %+v", a, b)
	}
}

func TestConfigRegexStrategy(t *testing.T) {
	p := compileCfg(t, `
version: 1
devices:
  - name: jarvis
    hostname_match: ['^edge-']
    fields:
      - {target: src_ip, strategy: regex, pattern: 'client=(\d+\.\d+\.\d+\.\d+)'}
      - {target: reason, strategy: regex, pattern: 'code:(\d+)', type: int}
`)
	e := p.Parse("2026-01-02T03:04:05+00:00 edge-7 srv: client=192.0.2.55 rejected code:403")
	if e.SrcIP != "192.0.2.55" {
		t.Fatalf("src_ip = %q", e.SrcIP)
	}
	if e.Reason == nil || *e.Reason != 403 {
		t.Fatalf("reason = %v, want 403", e.Reason)
	}
}

func TestConfigWordMapStrategy(t *testing.T) {
	p := compileCfg(t, `
version: 1
devices:
  - name: fw
    hostname_match: ['^firewall']
    fields:
      - {target: action, strategy: kv, key: verdict}
      - {target: action, strategy: word_map, source: action,
         map: {denied: deny, allowed: allow}}
    events:
      - {event: fw_block, field: action, equals: deny}
`)
	e := p.Parse("2026-01-02T03:04:05+00:00 firewall.example fw: verdict=denied")
	if e.Action != "deny" {
		t.Fatalf("action = %q, want deny", e.Action)
	}
	if e.Event != "fw_block" {
		t.Fatalf("event = %q, want fw_block", e.Event)
	}
}

func TestConfigMultipleKeys(t *testing.T) {
	p := compileCfg(t, `
version: 1
devices:
  - name: multi
    hostname_match: ['^mx-']
    fields:
      - {target: src_ip, strategy: kv, keys: [srcip, source, from]}
`)
	e := p.Parse("2026-01-02T03:04:05+00:00 mx-1 app: source=203.0.113.9")
	if e.SrcIP != "203.0.113.9" {
		t.Fatalf("src_ip = %q", e.SrcIP)
	}
}

func TestValidateConfigRejectsBadDocuments(t *testing.T) {
	bad := []string{
		// unknown target column
		"version: 1\ndevices:\n  - name: x\n    hostname_match: ['^x']\n    fields:\n      - {target: nope, strategy: kv, key: a}\n",
		// unknown strategy
		"version: 1\ndevices:\n  - name: x\n    fields:\n      - {target: src_ip, strategy: nope}\n",
		// kv without key
		"version: 1\ndevices:\n  - name: x\n    fields:\n      - {target: src_ip, strategy: kv}\n",
		// bad regex pattern
		"version: 1\ndevices:\n  - name: x\n    fields:\n      - {target: src_ip, strategy: regex, pattern: '([unclosed'}\n",
		// bad hostname regex
		"version: 1\ndevices:\n  - name: x\n    hostname_match: ['([bad']\n",
		// word_map without map
		"version: 1\ndevices:\n  - name: x\n    fields:\n      - {target: action, strategy: word_map, source: action}\n",
		// event with no condition
		"version: 1\ndevices:\n  - name: x\n    events:\n      - {event: foo}\n",
		// bad device_type
		"version: 1\ndevices:\n  - name: x\n    device_type: toaster\n",
		// duplicate names
		"version: 1\ndevices:\n  - name: x\n  - name: x\n",
		// unknown yaml key
		"version: 1\ndevices:\n  - name: x\n    bogus_field: 1\n",
	}
	for i, raw := range bad {
		cfg, err := DecodeConfig([]byte(raw))
		if err != nil {
			continue // strict decoding rejected it, which is fine
		}
		if err := ValidateConfig(cfg); err == nil {
			t.Errorf("case %d: invalid config accepted", i)
		}
	}
}

func TestTemplateIsValid(t *testing.T) {
	cfg, err := DecodeConfig([]byte(TemplateYAML))
	if err != nil {
		t.Fatalf("template does not decode: %v", err)
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("template does not validate: %v", err)
	}
	if len(cfg.Devices) != 0 {
		t.Fatalf("template should ship no devices, got %d", len(cfg.Devices))
	}
}

func TestConfigRoundTrip(t *testing.T) {
	raw := `
version: 1
devices:
  - name: fw
    hostname_match: ['^firewall']
    device_type: firewall
    fields:
      - {target: src_ip, strategy: kv, key: src}
    events:
      - {event: fw_block, contains: ['deny']}
`
	cfg, _ := DecodeConfig([]byte(raw))
	encoded, err := EncodeConfig(cfg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := DecodeConfig(encoded)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if err := ValidateConfig(back); err != nil {
		t.Fatalf("round-tripped config invalid: %v", err)
	}
	if len(back.Devices) != 1 || back.Devices[0].Name != "fw" {
		t.Fatalf("round trip lost data: %+v", back)
	}
	if !strings.Contains(string(encoded), "src_ip") {
		t.Fatalf("encoded output missing field: %s", encoded)
	}
}
