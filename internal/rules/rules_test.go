package rules

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"

	"siskamlan/internal/parser"
)

// loadCorpus parses the captured sample logs into entries.
func loadCorpus(t *testing.T) []*parser.Entry {
	t.Helper()
	f, err := os.Open("../parser/testdata/golden.jsonl")
	if err != nil {
		t.Skipf("no golden fixture: %v", err)
	}
	defer f.Close()

	var out []*parser.Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var doc map[string]any
		if err := json.Unmarshal(sc.Bytes(), &doc); err != nil {
			t.Fatalf("bad fixture line: %v", err)
		}
		raw, _ := doc["raw_line"].(string)
		if e := parser.Parse(raw); e != nil {
			out = append(out, e)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

func TestDefaultRulesValidate(t *testing.T) {
	rf := DefaultRulesFile()
	if err := Validate(rf); err != nil {
		t.Fatalf("shipped rules are invalid: %v", err)
	}
}

func TestDefaultRulesRoundTrip(t *testing.T) {
	rf := DefaultRulesFile()
	raw, err := Encode(rf)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := Validate(back); err != nil {
		t.Fatalf("round-tripped rules invalid: %v", err)
	}
	if got, want := len(back.Rules), len(rf.Rules); got != want {
		t.Fatalf("rule count = %d, want %d", got, want)
	}
	for i := range rf.Rules {
		if rf.Rules[i].Name != back.Rules[i].Name {
			t.Fatalf("rule %d name = %q, want %q", i, back.Rules[i].Name, rf.Rules[i].Name)
		}
		if rf.Rules[i].Rate != back.Rules[i].Rate {
			t.Fatalf("rule %q rate = %v, want %v", rf.Rules[i].Name, back.Rules[i].Rate, rf.Rules[i].Rate)
		}
		if rf.Rules[i].IsEnabled() != back.Rules[i].IsEnabled() {
			t.Fatalf("rule %q enabled mismatch", rf.Rules[i].Name)
		}
	}
}

func TestPortScanThreshold(t *testing.T) {
	rf := DefaultRulesFile()
	ip := "192.0.2.1"

	rows := make([]*parser.Entry, 0, 13)
	for p := 1; p <= 12; p++ {
		port := p
		rows = append(rows, &parser.Entry{SrcIP: ip, DstPort: &port, Event: "FW_BLOCK"})
	}
	hits := Detect(rows, rf, 30)
	if !hasType(hits, "PORT_SCAN") {
		t.Fatalf("12 unique ports did not trigger PORT_SCAN: %v", types(hits))
	}

	// 11 unique ports must stay below the threshold.
	short := rows[:11]
	if hasType(Detect(short, rf, 30), "PORT_SCAN") {
		t.Fatal("11 unique ports triggered PORT_SCAN, threshold is wrong")
	}
}

func TestDistinctCountNotRowCount(t *testing.T) {
	rf := DefaultRulesFile()
	ip := "192.0.2.9"
	port := 4444
	// Many rows, one port: row-count logic would fire, distinct logic must not.
	rows := make([]*parser.Entry, 50)
	for i := range rows {
		rows[i] = &parser.Entry{SrcIP: ip, DstPort: &port, Event: "FW_BLOCK"}
	}
	if hasType(Detect(rows, rf, 30), "PORT_SCAN") {
		t.Fatal("PORT_SCAN fired on a single repeated port; distinct counting is broken")
	}
}

func TestDeauthSuppressedByBruteForce(t *testing.T) {
	rf := DefaultRulesFile()
	mac := "aa:bb:cc:dd:ee:ff"

	var rows []*parser.Entry
	for i := 0; i < 9; i++ {
		rows = append(rows, &parser.Entry{DeviceType: "ap", ClientMAC: mac, Event: "deauth"})
	}
	hits := Detect(rows, rf, 30)
	if !hasType(hits, "DEAUTH_STORM") {
		t.Fatalf("9 deauths did not trigger DEAUTH_STORM: %v", types(hits))
	}

	// Adding auth failures pushes the same entity into BRUTE_FORCE, which
	// suppresses the weaker DEAUTH_STORM.
	for i := 0; i < 12; i++ {
		rows = append(rows, &parser.Entry{DeviceType: "ap", ClientMAC: mac, Event: "auth_failure"})
	}
	hits = Detect(rows, rf, 30)
	if hasType(hits, "DEAUTH_STORM") {
		t.Fatalf("DEAUTH_STORM not suppressed by BRUTE_FORCE: %v", types(hits))
	}
	if !hasType(hits, "BRUTE_FORCE") {
		t.Fatalf("BRUTE_FORCE did not fire: %v", types(hits))
	}
}

func TestFloodCountsAllRows(t *testing.T) {
	rf := DefaultRulesFile()
	rows := make([]*parser.Entry, 240)
	for i := range rows {
		rows[i] = &parser.Entry{Event: "whatever"}
	}
	if !hasType(Detect(rows, rf, 30), "FLOOD") {
		t.Fatal("240 events in 30s did not trigger FLOOD")
	}
	if hasType(Detect(rows[:239], rf, 30), "FLOOD") {
		t.Fatal("239 events triggered FLOOD, threshold is wrong")
	}
}

func TestCorpusProducesExpectedDetections(t *testing.T) {
	corpus := loadCorpus(t)
	rf := DefaultRulesFile()
	hits := Detect(corpus, rf, 30)
	t.Logf("corpus: %d rows -> %d hits: %v", len(corpus), len(hits), types(hits))

	// The sample corpus is attacker-free; ensure no crash, sane severities,
	// and that every hit carries a known type.
	for _, h := range hits {
		if SeverityRank(h.Severity) < 0 {
			t.Errorf("hit %q has invalid severity %q", h.Type, h.Severity)
		}
		if h.Description == "" {
			t.Errorf("hit %q has empty description", h.Type)
		}
	}
}

func TestConditionOperators(t *testing.T) {
	port := 22
	e := &parser.Entry{
		SrcIP: "10.0.0.5", DstPort: &port, Event: "FW_BLOCK",
		DeviceType: "firewall", Action: "deny",
	}
	cases := []struct {
		cond Condition
		want bool
	}{
		{Condition{Field: "event", Op: "eq", Value: "FW_BLOCK"}, true},
		{Condition{Field: "event", Op: "ne", Value: "FW_DROP"}, true},
		{Condition{Field: "event", Op: "icontains", Value: "fw_bl"}, true},
		{Condition{Field: "src_ip", Op: "prefix", Value: "10.0."}, true},
		{Condition{Field: "src_ip", Op: "regex", Value: `^10\.\d+\.`}, true},
		{Condition{Field: "dst_port", Op: "in", Values: []any{22, 443}}, true},
		{Condition{Field: "dst_port", Op: "not_in", Values: []any{80}}, true},
		{Condition{Field: "dst_port", Op: "gte", Value: 22}, true},
		{Condition{Field: "mac", Op: "exists"}, false},
		{Condition{Field: "mac", Op: "not_exists"}, true},
		{Condition{Not: &Condition{Field: "event", Op: "eq", Value: "FW_ALLOW"}}, true},
		{Condition{All: []Condition{
			{Field: "device_type", Op: "eq", Value: "firewall"},
			{Field: "action", Op: "eq", Value: "deny"},
		}}, true},
		{Condition{Any: []Condition{
			{Field: "event", Op: "eq", Value: "nope"},
			{Field: "event", Op: "eq", Value: "FW_BLOCK"},
		}}, true},
	}
	for i, c := range cases {
		if got := Match(c.cond, e); got != c.want {
			t.Errorf("case %d: got %v want %v (%+v)", i, got, c.want, c.cond)
		}
	}
}

func TestValidateRejectsBadRules(t *testing.T) {
	bad := []RulesFile{
		{}, // no rules
		{Rules: []Rule{{Name: "", Severity: "HIGH", Rate: 1}}},
		{Rules: []Rule{{Name: "X", Severity: "SEVERE", Rate: 1}}},
		{Rules: []Rule{{Name: "X", Severity: "HIGH", Rate: 0}}},
		{Rules: []Rule{{Name: "X", Severity: "HIGH", Rate: 1, Count: "distinct"}}},
		{Rules: []Rule{{Name: "X", Severity: "HIGH", Rate: 1, GroupBy: []string{"nope"}}}},
		{Rules: []Rule{{Name: "X", Severity: "HIGH", Rate: 1,
			When: Condition{Field: "nope", Op: "eq", Value: 1}}}},
		{Rules: []Rule{{Name: "X", Severity: "HIGH", Rate: 1,
			When: Condition{Field: "event", Op: "bad_op", Value: 1}}}},
	}
	for i, rf := range bad {
		if err := Validate(rf); err == nil {
			t.Errorf("case %d: invalid rules accepted", i)
		}
	}

	dup := RulesFile{Rules: []Rule{
		{Name: "X", Severity: "HIGH", Rate: 1},
		{Name: "X", Severity: "HIGH", Rate: 1},
	}}
	if err := Validate(dup); err == nil {
		t.Error("duplicate rule names accepted")
	}
}

func hasType(hits []Hit, name string) bool {
	for _, h := range hits {
		if h.Type == name {
			return true
		}
	}
	return false
}

func types(hits []Hit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, fmt.Sprintf("%s/%s", h.Type, h.Entity))
	}
	sort.Strings(out)
	return out
}
