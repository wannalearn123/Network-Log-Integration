package tui

import (
	"strings"
	"testing"

	"siskamlan/internal/parser"
)

// switchLine is the shape that exposed the original gap: a vendor log with
// no `=` anywhere, so a kv-only picker found nothing to assign.
const switchLine = `2026-10-29T06:48:26+00:00 switch.monitoringsystembak_building-lan rgos: %MATM-5-LEARN: Host 43bd.794d.31a7 learned on Gi0/2 vlan 12`

const firewallLine = `2026-10-28T14:29:06+00:00 firewall.monitoringsystembak_building-lan kernel: [FW ALLOW] IN=eth0 OUT= SRC=172.20.100.48 DST=172.0.0.4 LEN=57 PROTO=UDP SPT=11627 DPT=22`

// TestCandidatesCoverNonKvVendor pins the fix for "switch has no keywords":
// a line with no key=value must still yield assignable rules.
func TestCandidatesCoverNonKvVendor(t *testing.T) {
	cands := buildCandidates([]string{switchLine})
	if len(cands) == 0 {
		t.Fatal("no candidates derived from a switch line")
	}

	byTarget := map[string]candidate{}
	for _, c := range cands {
		if _, ok := byTarget[c.target]; !ok {
			byTarget[c.target] = c
		}
	}
	for target, want := range map[string]string{
		"mac":     "43bd.794d.31a7",
		"ifname":  "Gi0/2",
		"vlan_id": "12",
	} {
		c, ok := byTarget[target]
		if !ok {
			t.Errorf("no candidate for %q from switch line", target)
			continue
		}
		if c.strategy == "kv" {
			t.Errorf("%q candidate should not be kv for a line with no '='", target)
		}
		if c.sample != want {
			t.Errorf("%q sample = %q, want %q", target, c.sample, want)
		}
	}
}

// TestCandidatesFromKvVendor checks a firewall line still yields kv rules,
// which are cheaper and more stable than regex there.
func TestCandidatesFromKvVendor(t *testing.T) {
	cands := buildCandidates([]string{firewallLine})

	var kvTargets []string
	for _, c := range cands {
		if c.strategy == "kv" {
			kvTargets = append(kvTargets, c.target)
		}
	}
	for _, want := range []string{"src_ip", "dst_ip", "proto", "src_port", "dst_port"} {
		found := false
		for _, got := range kvTargets {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no kv candidate for %q; got %v", want, kvTargets)
		}
	}
}

// TestCandidatesSkipEnvelope guards against the classic mistake: capturing
// the timestamp or hostname because the pattern was too loose.
func TestCandidatesSkipEnvelope(t *testing.T) {
	for _, c := range buildCandidates([]string{switchLine, firewallLine}) {
		for _, bad := range []string{
			"2026-10-29T06:48:26+00:00",
			"switch.monitoringsystembak_building-lan",
		} {
			if c.sample == bad {
				t.Errorf("candidate %q sampled the log envelope: %q", c.target, bad)
			}
		}
	}
}

// TestVerifyRuleRejectsInertKv is the core regression: `kv` + `key: Host`
// passes schema validation but extracts nothing from a switch line, so it
// must be rejected at edit time instead of saved as a silent no-op.
func TestVerifyRuleRejectsInertKv(t *testing.T) {
	rule := parser.FieldRule{Target: "mac", Strategy: "kv", Key: "Host"}
	if err := verifyRule(rule, []string{switchLine}); err == nil {
		t.Fatal("inert kv rule was accepted")
	}
}

// TestVerifyRuleAcceptsWorkingRegex checks the equivalent regex rule passes.
func TestVerifyRuleAcceptsWorkingRegex(t *testing.T) {
	rule := parser.FieldRule{
		Target:   "mac",
		Strategy: "regex",
		Pattern:  `(?i)\b([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\b`,
	}
	if err := verifyRule(rule, []string{switchLine}); err != nil {
		t.Fatalf("working regex rule rejected: %v", err)
	}
}

// TestAddCandidateRuleAppendsWorkingRule walks the path the operator takes:
// pick a candidate, and end up with a rule that actually fills the column.
func TestAddCandidateRuleAppendsWorkingRule(t *testing.T) {
	e := newParsersEditorWithTemplate(t)
	e.cfg.Devices = []parser.Device{{
		Name: "sw", HostnameMatch: []string{"switch"}, DeviceType: "switch",
	}}
	e.sample = []string{switchLine}

	var mac candidate
	for _, c := range buildCandidates([]string{switchLine}) {
		if c.target == "mac" {
			mac = c
			break
		}
	}
	if mac.target == "" {
		t.Fatal("no mac candidate")
	}
	if err := e.addCandidateRule(0, mac); err != nil {
		t.Fatalf("addCandidateRule: %v", err)
	}

	rows, err := previewLine(e.cfg, switchLine)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.column] = r.value
	}
	if got["mac"] != "43bd.794d.31a7" {
		t.Fatalf("saved rule did not fill mac: %v", got)
	}
}

// TestPickerIsNotEmptyForEveryVendor checks all four sample vendors produce
// candidates, which is what "cannot customize" looked like when kv-only.
func TestPickerIsNotEmptyForEveryVendor(t *testing.T) {
	lines := map[string]string{
		"switch":   switchLine,
		"firewall": firewallLine,
		"router":   `2026-10-28T14:29:12+00:00 router.monitoringsystembak_building-lan zebra: route dst-address=10.0.0.0/8 gateway=172.20.0.1 interface=eth1`,
		"ap":       `2026-10-28T14:29:12+00:00 ap.monitoringsystembak_building-lan hostapd: wlan0: AP-STA-CONNECTED aa:bb:cc:b2:25:e4`,
	}
	for vendor, line := range lines {
		if len(buildCandidates([]string{line})) == 0 {
			t.Errorf("%s: picker produced no candidates", vendor)
		}
	}
}

// TestHostnameSuggestEscapesHost ensures the seeded matcher is a literal
// hostname, not a regex that could match unrelated hosts.
func TestHostnameSuggestEscapesHost(t *testing.T) {
	got := hostnameSuggest("/x/data/syslog/switch.monitoringsystembak_building-lan.log")
	if !strings.HasPrefix(got, "^") || !strings.HasSuffix(got, "$") {
		t.Fatalf("matcher is not anchored: %q", got)
	}
	if strings.Contains(got, ".log") {
		t.Fatalf("matcher kept the file extension: %q", got)
	}
	if !strings.Contains(got, `\.`) {
		t.Fatalf("dots are not escaped, so the regex is too loose: %q", got)
	}
}

// TestCandidatesNoJunkPositional guards the fallback: a positional rule is
// only offered when nothing better exists, and never for a value an anchored
// extractor already handles. Otherwise the picker suggests nonsense such as
// writing a MAC address into the `action` column.
func TestCandidatesNoJunkPositional(t *testing.T) {
	cands := buildCandidates([]string{switchLine})
	for _, c := range cands {
		if c.strategy != "positional" {
			continue
		}
		t.Errorf("switch line should not need positional fallback, got %s → %s",
			c.target, c.sample)
	}

	// A line with no recognizable structure still gets a fallback.
	junk := `2026-10-29T09:00:00+00:00 mystery.host myapp: something happened to 98765`
	if len(buildCandidates([]string{junk})) == 0 {
		t.Fatal("unstructured line produced no candidates at all")
	}
}

// TestGuessTargetDoesNotInventColumns pins the mis-mappings seen on the real
// vendor logs: `gateway` became src_ip, `dst-address` became action, and
// `status=1` became dst_port. A guessed column the parser never reads is
// worse than an empty one, because the operator accepts the pre-filled form.
func TestGuessTargetDoesNotInventColumns(t *testing.T) {
	for _, tc := range []struct{ key, value, want string }{
		{"gateway", "172.20.0.12", "gateway"},
		{"dst-address", "172.20.100.0/24", "dst_ip"},
		{"src-address", "172.20.100.5", "src_ip"},
		{"src", "172.20.100.25", "src_ip"},
		{"dst", "172.20.0.4", "dst_ip"},
		{"spt", "33330", "src_port"},
		{"dpt", "443", "dst_port"},
		{"proto", "17", "proto"},
		{"signal", "57", "signal_dbm"},
		{"interface", "GigabitEthernet0/0", "ifname"},
	} {
		if got := guessTarget(tc.key, tc.value); got != tc.want {
			t.Errorf("guessTarget(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}

	// A bare integer must not be guessed as a port, and an unknown key must
	// not silently become src_ip or action.
	if got := guessTarget("status", "1"); got != "" {
		t.Errorf("guessTarget(status) invented %q", got)
	}
	if got := guessTarget("deviceExternalId", "FGT100F000000003811"); got == "action" {
		t.Error("unknown key fell through to action")
	}
}
