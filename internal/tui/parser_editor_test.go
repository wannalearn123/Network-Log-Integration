package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"siskamlan/internal/parser"
)

// newParsersEditorWithTemplate writes the shipped template (no devices) and
// returns an opened editor with no database behind it.
func newParsersEditorWithTemplate(t *testing.T) *parsersEditor {
	t.Helper()
	path := filepath.Join(t.TempDir(), "parsers.yaml")
	if err := os.WriteFile(path, []byte(parser.TemplateYAML), 0o644); err != nil {
		t.Fatalf("seed parsers: %v", err)
	}
	e := newParsersEditor(path, nil)
	e.open()
	return e
}

// TestParsersEmptyStateExplainsBuiltInParser pins the fix for the screen
// looking broken: an empty device list means the built-in parser is handling
// every line, not that nothing is being ingested.
func TestParsersEmptyStateExplainsBuiltInParser(t *testing.T) {
	e := newParsersEditorWithTemplate(t)
	out := e.view(120, 30)
	if !strings.Contains(out, ".monitoringsystembak_building-lan.log") {
		t.Fatalf("file list missing syslog files:\n%s", out)
	}
}

// TestDeviceFormExplainsEveryField checks the three device fields carry help,
// since they are the ones that looked unexplained.
func TestDeviceFormExplainsEveryField(t *testing.T) {
	e := newParsersEditorWithTemplate(t)
	e.startDeviceForm(-1)

	if e.form.subtitle == "" {
		t.Error("device form has no subtitle explaining what a profile does")
	}
	for _, label := range []string{"name", "hostname_match", "device_type"} {
		f := fieldByLabel(e.form, label)
		if f == nil {
			t.Fatalf("device form missing %q", label)
		}
		if strings.TrimSpace(f.help) == "" {
			t.Errorf("device field %q has no help text", label)
		}
	}
	// The name is a label only; that is the most common misunderstanding.
	if h := fieldByLabel(e.form, "name").help; !strings.Contains(h, "not for matching") {
		t.Errorf("name help does not say it is not used for matching: %q", h)
	}
}

// TestFieldFormShowsOnlyRelevantInputs checks the field-assignment form is
// strategy-aware.
//
// The old form listed key/keys/pattern/source/map/pos for every strategy,
// which is how a switch MAC ended up saved as `kv` + `key: Host` — a rule
// the parser accepts but that extracts nothing.
func TestFieldFormShowsOnlyRelevantInputs(t *testing.T) {
	e := newParsersEditorWithTemplate(t)

	for _, tc := range []struct {
		strategy string
		want     []string
		notWant  []string
	}{
		{"kv", []string{"target", "strategy", "key", "keys", "type"}, []string{"pattern", "pos", "map"}},
		{"regex", []string{"target", "strategy", "pattern", "type"}, []string{"key", "keys", "pos"}},
		{"positional", []string{"target", "strategy", "pos", "type"}, []string{"key", "pattern"}},
		{"word_map", []string{"target", "strategy", "source", "map", "type"}, []string{"key", "pattern"}},
	} {
		fm := e.fieldForm(parser.FieldRule{Target: "mac", Strategy: tc.strategy})
		for _, label := range tc.want {
			hf := fieldByLabel(fm, label)
			if hf == nil {
				t.Fatalf("%s form missing %q", tc.strategy, label)
			}
			if strings.TrimSpace(hf.help) == "" {
				t.Errorf("%s field %q has no help text", tc.strategy, label)
			}
		}
		for _, label := range tc.notWant {
			if fieldByLabel(fm, label) != nil {
				t.Errorf("%s form should not show %q", tc.strategy, label)
			}
		}
	}
}

// TestApplyFormRejectsEmptyHostnameMatch pins the bug that made every
// hand-built profile inert: without hostname_match the profile never runs.
func TestApplyFormRejectsEmptyHostnameMatch(t *testing.T) {
	e := newParsersEditorWithTemplate(t)
	e.startDeviceForm(-1)
	e.form.fields[0].value = "my-switch" // name
	fieldByLabel(e.form, "hostname_match").value = ""
	e.applyForm()

	if len(e.cfg.Devices) != 0 {
		t.Fatalf("profile with no hostname_match was saved: %+v", e.cfg.Devices)
	}
	if !strings.Contains(e.errText, "hostname_match is required") {
		t.Fatalf("expected an explanation, got %q", e.errText)
	}
}

// TestDeviceFormSeedsHostnameMatchFromFile checks the form starts from a
// matcher derived from the selected file instead of an empty field.
func TestDeviceFormSeedsHostnameMatchFromFile(t *testing.T) {
	e := newParsersEditorWithTemplate(t)
	e.selectedFile = "/x/data/syslog/switch.monitoringsystembak_building-lan.log"
	e.startDeviceForm(-1)

	got := fieldByLabel(e.form, "hostname_match").value
	if got == "" {
		t.Fatal("hostname_match was not seeded from the selected file")
	}
	if !strings.Contains(got, "switch") {
		t.Fatalf("seeded matcher %q does not name the file's host", got)
	}
}

// TestApplyFormDropsIrrelevantInputs checks a kv rule cannot carry a pos, and
// a regex rule cannot carry a key, once it reaches the config.
func TestApplyFormDropsIrrelevantInputs(t *testing.T) {
	e := newParsersEditorWithTemplate(t)
	e.cfg.Devices = []parser.Device{{
		Name: "d", HostnameMatch: []string{"switch"}, DeviceType: "switch",
	}}
	e.editDevice, e.editField = 0, -1
	// Start from a regex rule so the form exposes a pattern input.
	e.startFieldForm(0, -1)
	fieldByLabel(e.form, "strategy").value = "regex"
	e.rebuildFieldForm()

	fieldByLabel(e.form, "pattern").value = `vlan\s+(\d+)`
	// These inputs do not exist on a regex form, so they must have no effect.
	if f := fieldByLabel(e.form, "key"); f != nil {
		f.value = "Host"
	}
	if f := fieldByLabel(e.form, "pos"); f != nil {
		f.value = "first"
	}
	e.applyForm()

	if len(e.cfg.Devices[0].Fields) != 1 {
		t.Fatalf("expected one rule, got %+v", e.cfg.Devices[0].Fields)
	}
	f := e.cfg.Devices[0].Fields[0]
	if f.Key != "" || f.Pos != "" {
		t.Fatalf("irrelevant inputs survived: key=%q pos=%q", f.Key, f.Pos)
	}
	if f.Pattern == "" {
		t.Fatal("pattern was lost")
	}
}

// TestCleanRawLine makes raw log text safe to draw.
func TestCleanRawLine(t *testing.T) {
	got := cleanRawLine("a\tb\x00c\x1b[31md")
	if strings.ContainsAny(got, "\t\x00\x1b") {
		t.Fatalf("control characters survived: %q", got)
	}
	if !strings.HasPrefix(got, "a b") {
		t.Fatalf("tab should become a space: %q", got)
	}
}

// TestSampleViewWithoutStoreIsSilent checks the parser screen still renders
// when no database is attached (tests, or a failed connection). The pane
// keeps its header so the layout does not jump, but promises no rows.
func TestSampleViewWithoutStoreIsSilent(t *testing.T) {
	e := newParsersEditorWithTemplate(t)
	lines := e.sampleView(80, 3)
	if len(lines) != 1 {
		t.Fatalf("expected only the header without a store, got %v", lines)
	}
	if !strings.Contains(lines[0], "RECENT RAW") {
		t.Fatalf("expected the RECENT RAW header, got %q", lines[0])
	}
}

// TestSampleViewPreviewsParsedColumns checks the pane shows the *result* of
// the profile, which is what tells the operator whether it works.
func TestSampleViewPreviewsParsedColumns(t *testing.T) {
	e := newParsersEditorWithTemplate(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "switch.log")
	line := `2026-10-29T06:48:26+00:00 switch.monitoringsystembak_building-lan rgos: %MATM-5-LEARN: Host 43bd.794d.31a7 learned on Gi0/2 vlan 12`
	if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.selectedFile = path
	e.loadFileSample()

	out := strings.Join(e.sampleView(120, 30), "\n")
	if !strings.Contains(out, "SAMPLE → PARSED") {
		t.Fatalf("preview pane missing:\n%s", out)
	}
	for _, want := range []string{"mac", "43bd.794d.31a7", "ifname", "Gi0/2", "vlan_id", "12"} {
		if !strings.Contains(out, want) {
			t.Errorf("preview missing %q:\n%s", want, out)
		}
	}
}

// TestPreviewLineMatchesIngest checks the preview runs the real parser, so
// what the operator sees cannot drift from what gets stored.
func TestPreviewLineMatchesIngest(t *testing.T) {
	line := `2026-10-29T06:48:26+00:00 switch.host rgos: %MATM-5-LEARN: Host 43bd.794d.31a7 learned on Gi0/2 vlan 12`
	rows, err := previewLine(parser.Config{Version: 1}, line)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.column] = r.value
	}
	if got["event"] != "mac_learn" {
		t.Errorf("event = %q, want mac_learn", got["event"])
	}
	if got["mac"] != "43bd.794d.31a7" {
		t.Errorf("mac = %q", got["mac"])
	}
}

// TestStrategyCycleRebuildsForm pins the navigation fix: choosing a different
// strategy must reveal that strategy's inputs and keep the cursor usable.
func TestStrategyCycleRebuildsForm(t *testing.T) {
	e := newParsersEditorWithTemplate(t)
	e.startFieldForm(0, -1)

	if fieldByLabel(e.form, "pattern") != nil {
		t.Fatal("kv form should not show pattern")
	}
	// Put the cursor on the strategy row, then cycle it like a keypress does.
	for i := range e.form.fields {
		if e.form.fields[i].label == "strategy" {
			e.form.cursor = i
			break
		}
	}
	for i := 0; i < len(parser.Strategies); i++ {
		if fieldByLabel(e.form, "strategy").value == "regex" {
			break
		}
		e.updateForm(tea.KeyMsg{Type: tea.KeyRight})
	}
	if got := fieldByLabel(e.form, "strategy").value; got != "regex" {
		t.Fatalf("strategy = %q, want regex", got)
	}
	if fieldByLabel(e.form, "pattern") == nil {
		t.Fatal("regex form did not expose a pattern input")
	}
	if fieldByLabel(e.form, "key") != nil {
		t.Fatal("regex form still shows the kv key input")
	}
	if e.form.fields[e.form.cursor].label != "strategy" {
		t.Errorf("cursor moved off strategy to %q", e.form.fields[e.form.cursor].label)
	}
}

// TestSaveRefusesInvalidConfig checks a rejected document never overwrites
// the file the ingester is reading.
func TestSaveRefusesInvalidConfig(t *testing.T) {
	e := newParsersEditorWithTemplate(t)
	path := e.file.Path()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A device with no hostname_match is inert; refuse to write it.
	e.cfg.Devices = []parser.Device{{Name: "broken", DeviceType: "switch"}}
	e.save()

	if !strings.Contains(e.errText, "not saved") {
		t.Fatalf("expected a refusal, got %q", e.errText)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("file was overwritten with an invalid config")
	}
}
