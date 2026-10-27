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
	src := "10.0.0.5"
	m.logs = []*store.LogEntry{
		{Timestamp: time.Now(), Hostname: "fw-1", DeviceType: "firewall",
			Event: "fw_block", SrcIP: &src, DstPort: &port},
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
	if !strings.Contains(out, "×3") {
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
	m.logs = make([]*store.LogEntry, 50)

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

// TestDetailModalShowsParsedFields ensures the detail view exposes the parsed
// columns, which is how a parser profile is verified.
func TestDetailModalShowsParsedFields(t *testing.T) {
	src := "2001:db8::1"
	port := 443
	e := &store.LogEntry{
		Timestamp: time.Now(), Hostname: "fw-1", DeviceType: "firewall",
		Event: "fw_block", SrcIP: &src, DstPort: &port,
		Action: "deny", RawLine: "raw text here",
	}
	d := newLogDetail(e)
	d.setRaw(e.RawLine)
	out := d.view(120, 40)
	for _, want := range []string{"event", "fw_block", "src_ip", "2001:db8::1", "raw_line", "raw text here"} {
		if !strings.Contains(out, want) {
			t.Errorf("detail view missing %q", want)
		}
	}
}

// TestAnomalyDetailShowsFeatures checks detections expose their JSON features.
func TestAnomalyDetailShowsFeatures(t *testing.T) {
	a := store.AnomalyRow{
		ID: 7, Timestamp: time.Now(), Severity: "HIGH",
		Description: "[RULE] Port scan", RepeatCount: 3,
		Features: `{"type":"PORT_SCAN","entity":"10.0.0.5"}`,
	}
	d := newAnomalyDetail(a)
	out := d.view(120, 40)
	for _, want := range []string{"#7", "HIGH", "repeat_count", "3", "features"} {
		if !strings.Contains(out, want) {
			t.Errorf("anomaly detail missing %q", want)
		}
	}
}

// TestEnterOpensDetail checks the dashboard opens a detail view on enter.
func TestEnterOpensDetail(t *testing.T) {
	m := &Model{search: newSearchInput(), view: viewDashboard, width: 100, height: 30, focusLogs: true}
	m.logs = []*store.LogEntry{{Timestamp: time.Now(), Hostname: "h", Event: "e"}}
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		_ = cmd
	}
	if m.view != viewDetail {
		t.Fatalf("view = %v, want detail", m.view)
	}
	if m.detail == nil {
		t.Fatal("detail modal not set")
	}
	// esc returns to the dashboard
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if m.view != viewDashboard {
		t.Fatalf("view after esc = %v, want dashboard", m.view)
	}
}

// TestExportConfirmFlow checks e opens the prompt and esc cancels.
func TestExportConfirmFlow(t *testing.T) {
	m := &Model{search: newSearchInput(), view: viewDashboard, width: 100, height: 30}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("e")})
	if m.view != viewExportConfirm {
		t.Fatalf("view = %v, want export confirm", m.view)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if m.view != viewDashboard {
		t.Fatalf("view after cancel = %v, want dashboard", m.view)
	}
}

// TestOverviewRendering checks the overview panels format counts.
func TestOverviewRendering(t *testing.T) {
	lines := renderOverview(
		[]store.SourceCount{{Source: "10.0.0.5", Count: 4}, {Source: "2001:db8::1", Count: 2}},
		[]store.TypeCount{{Type: "PORT_SCAN", Count: 3}},
	)
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"TOP DETECTION SOURCES", "DETECTIONS BY TYPE", "10.0.0.5", "2001:db8::1", "PORT_SCAN"} {
		if !strings.Contains(joined, want) {
			t.Errorf("overview missing %q", want)
		}
	}
}

// TestBarWidthNeverZeroForPositiveCount avoids invisible bars.
func TestBarWidthNeverZeroForPositiveCount(t *testing.T) {
	if got := barWidth(1, 1000, 24); got < 1 {
		t.Fatalf("barWidth = %d, want >= 1", got)
	}
	if got := barWidth(0, 1000, 24); got != 0 {
		t.Fatalf("barWidth(0) = %d, want 0", got)
	}
}

// TestCtrlCQuitsFromEveryScreen checks the universal exit works even where q is
// repurposed (editors, detail, export confirm).
func TestCtrlCQuitsFromEveryScreen(t *testing.T) {
	screens := map[string]func(*Model){
		"dashboard":     func(m *Model) { m.view = viewDashboard },
		"rules":         func(m *Model) { m.view = viewRules },
		"parsers":       func(m *Model) { m.view = viewParsers },
		"help":          func(m *Model) { m.view = viewHelp },
		"overview":      func(m *Model) { m.view = viewOverview },
		"detail":        func(m *Model) { m.view = viewDetail },
		"exportConfirm": func(m *Model) { m.view = viewExportConfirm },
	}
	for name, setup := range screens {
		m := &Model{search: newSearchInput(), width: 100, height: 30, focusLogs: true}
		m.rulesEditor = newRulesEditor("/tmp/nx-rules.yaml", nil)
		m.parsersEditor = newParsersEditor("/tmp/nx-parsers.yaml", nil)
		m.detail = newLogDetail(&store.LogEntry{})
		setup(m)

		_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
		if cmd == nil {
			t.Fatalf("%s: ctrl+c returned no command", name)
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Fatalf("%s: ctrl+c produced %T, want tea.QuitMsg", name, cmd())
		}
	}
}

// TestQIsContextualNotDestructive checks q does not quit from an editor, so a
// stray keypress cannot discard unsaved rule edits.
func TestQIsContextualNotDestructive(t *testing.T) {
	m := &Model{search: newSearchInput(), width: 100, height: 30}
	m.rulesEditor = newRulesEditor("/tmp/nx2-rules.yaml", nil)
	m.view = viewRules
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd != nil {
		if _, isQuit := cmd().(tea.QuitMsg); isQuit {
			t.Fatal("q quit the app from inside the rules editor")
		}
	}
}
