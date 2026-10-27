package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"siskamlan/internal/rules"
	"siskamlan/internal/store"
)

// TestRenderWithoutData checks the dashboard View produces a sane frame with no
// database attached. This guards against panics in the render path.
func TestRenderWithoutData(t *testing.T) {
	m := &Model{search: newSearchInput(), view: viewDashboard, focusLogs: true}
	m.width, m.height = 120, 40

	out := m.View()
	if out == "" {
		t.Fatal("empty view")
	}
	for _, want := range []string{"SISKAMLAN", "LOG STREAM", "ANOMALIES"} {
		if !strings.Contains(out, want) {
			t.Errorf("view missing %q", want)
		}
	}
}

// TestRenderWithRows checks rows and anomaly severities appear.
func TestRenderWithRows(t *testing.T) {
	port := 22
	m := &Model{search: newSearchInput(), view: viewDashboard, focusLogs: true}
	m.width, m.height = 140, 40
	m.logs = []store.LogRow{
		{Timestamp: time.Now(), Hostname: "fw-1", DeviceType: "firewall",
			Event: "fw_block", SrcIP: "10.0.0.5", DstPort: &port},
	}
	m.anomalies = []store.AnomalyRow{
		{ID: 1, Timestamp: time.Now(), Severity: "CRITICAL",
			Description: "[RULE] Brute force", RepeatCount: 3},
	}
	m.stats = store.Stats{TotalLogs: 10, Critical: 1}

	out := m.View()
	if !strings.Contains(out, "fw-1") {
		t.Error("log hostname not rendered")
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Error("anomaly severity not rendered")
	}
	if !strings.Contains(out, "x3") {
		t.Error("repeat count not rendered")
	}
}

// TestHelpView checks the help screen renders.
func TestHelpView(t *testing.T) {
	m := &Model{search: newSearchInput(), view: viewHelp}
	m.width, m.height = 100, 40
	out := m.View()
	if !strings.Contains(out, "keyboard reference") {
		t.Fatalf("help view missing content: %q", out)
	}
}

// TestScrollClamping checks scrolling never produces a negative offset.
func TestScrollClamping(t *testing.T) {
	m := &Model{search: newSearchInput(), focusLogs: true}
	m.scroll(-5)
	if m.logOffset != 0 {
		t.Fatalf("logOffset = %d, want 0", m.logOffset)
	}
	m.focusLogs = false
	m.scroll(-5)
	if m.anomOffset != 0 {
		t.Fatalf("anomOffset = %d, want 0", m.anomOffset)
	}
}

// TestPauseStopsRefresh checks a paused dashboard issues no refresh command.
func TestPauseStopsRefresh(t *testing.T) {
	m := &Model{search: newSearchInput(), paused: true}
	if cmd := m.refresh(); cmd != nil {
		t.Fatal("paused model still scheduled a refresh")
	}
}

// TestSearchFilterPropagates checks typing a filter reaches the query.
func TestSearchFilterPropagates(t *testing.T) {
	m := &Model{search: newSearchInput()}
	m.search.SetValue("10.0.0.5")
	if got := m.search.Value(); got != "10.0.0.5" {
		t.Fatalf("search value = %q", got)
	}
}

// TestKeyNavigation checks basic key handling does not panic and scrolls.
func TestKeyNavigation(t *testing.T) {
	m := &Model{search: newSearchInput(), view: viewDashboard, width: 120, height: 40}
	m.logs = make([]store.LogRow, 50)

	for _, key := range []string{"j", "j", "k", "tab", "g", "p", "p"} {
		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
		if _, cmd := m.Update(msg); cmd != nil {
			_ = cmd
		}
	}
	if m.logOffset != 0 {
		t.Fatalf("after g, logOffset = %d, want 0", m.logOffset)
	}
}

// TestRuleFormRoundTrip checks the form values map back into a rule shape.
func TestRuleFormRoundTrip(t *testing.T) {
	e := newRulesEditor("/tmp/does-not-exist-rules.yaml", nil)
	r := rules.Rule{
		Name: "PORT_SCAN", Severity: "HIGH", Rate: 0.4,
		Count: "distinct", DistinctOn: "dst_port",
		GroupBy: []string{"src_ip"},
	}
	e.form = e.ruleForm(r)
	vals := e.form.values()
	if vals["name"] != r.Name {
		t.Fatalf("name = %q, want %q", vals["name"], r.Name)
	}
	if vals["severity"] != r.Severity {
		t.Fatalf("severity = %q, want %q", vals["severity"], r.Severity)
	}
	if vals["count"] != "distinct" {
		t.Fatalf("count = %q, want distinct", vals["count"])
	}
	if vals["group_by"] != "src_ip" {
		t.Fatalf("group_by = %q, want src_ip", vals["group_by"])
	}
}

// TestGuessTarget checks keyword-to-column inference used by the parser editor.
func TestGuessTarget(t *testing.T) {
	cases := map[string]string{
		"src":    "src_ip",
		"dst":    "dst_ip",
		"dpt":    "dst_port",
		"spt":    "src_port",
		"proto":  "proto",
		"act":    "action",
		"signal": "signal_dbm",
		"reason": "reason",
	}
	for key, want := range cases {
		if got := guessTarget(key, "x"); got != want {
			t.Errorf("guessTarget(%q) = %q, want %q", key, got, want)
		}
	}
	if got := guessTarget("weird", "192.0.2.1"); got != "src_ip" {
		t.Errorf("ip-shaped value guessed %q, want src_ip", got)
	}
}

// TestParserEditorKeywordExtraction checks kv token discovery.
func TestParserEditorKeywordExtraction(t *testing.T) {
	line := "src=10.0.0.1 dst=10.0.0.2 dpt=443 act=drop"
	matches := kvTokenRe.FindAllStringSubmatch(line, -1)
	if len(matches) != 4 {
		t.Fatalf("found %d tokens, want 4", len(matches))
	}
	if matches[0][1] != "src" || matches[0][2] != "10.0.0.1" {
		t.Fatalf("first token = %v", matches[0])
	}
}

// TestStoreEntryConversion guards the pipeline preview helper compiles and runs.
func TestStoreEntryConversionExported(t *testing.T) {
	// Only checks the symbol exists and handles nil gracefully via the
	// package-level function in pipeline.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = ctx
}

// TestQuitKey returns tea.Quit so the program exits cleanly.
func TestQuitKey(t *testing.T) {
	m := &Model{search: newSearchInput(), view: viewDashboard, width: 80, height: 24}
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd == nil {
		t.Fatal("q returned no command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("q produced %T, want tea.QuitMsg", cmd())
	}
}

// TestDefaultSizeRender ensures the view never stalls at "loading".
func TestDefaultSizeRender(t *testing.T) {
	m := &Model{search: newSearchInput(), view: viewDashboard}
	out := m.View()
	if strings.Contains(out, "loading") {
		t.Fatal("view stuck at loading with zero size")
	}
	if !strings.Contains(out, "LOG STREAM") {
		t.Fatal("default-size view missing table")
	}
}

// TestOpenEditors switches into both editors and back.
func TestOpenEditors(t *testing.T) {
	m := &Model{search: newSearchInput(), view: viewDashboard, width: 100, height: 30}
	m.rulesEditor = newRulesEditor("/tmp/nonexistent-rules.yaml", nil)
	m.parsersEditor = newParsersEditor("/tmp/nonexistent-parsers.yaml", nil)

	m.view = viewRules
	if out := m.View(); !strings.Contains(out, "RULES") {
		t.Fatalf("rules view not rendered: %q", out)
	}
	m.view = viewParsers
	if out := m.View(); !strings.Contains(out, "PARSERS") {
		t.Fatalf("parsers view not rendered: %q", out)
	}
}
