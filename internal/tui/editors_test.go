package tui

import (
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"siskamlan/internal/config"
	"siskamlan/internal/parser"
	"siskamlan/internal/rules"
)

// seedRulesFile writes a default rules document and returns its path.
func seedRulesFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	raw, err := rules.Encode(rules.DefaultRulesFile())
	if err != nil {
		t.Fatalf("encode defaults: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	return path
}

// TestRulesEditorAddAndSave exercises the full editor write path: add a rule
// through the form, save, then reload the file and confirm it round-trips.
func TestRulesEditorAddAndSave(t *testing.T) {
	path := seedRulesFile(t)
	e := newRulesEditor(path, nil)
	e.open()
	before := len(e.rf.Rules)

	e.startAdd()
	setForm(e.form, "name", "ICMP_FLOOD")
	setForm(e.form, "severity", "HIGH")
	setForm(e.form, "rate", "5")
	setForm(e.form, "group_by", "src_ip")
	setForm(e.form, "count", "rows")
	setForm(e.form, "event_contains", "ICMP, FLOOD")
	setForm(e.form, "description", "ICMP flood from {entity} — {count} in {window}s")
	e.applyForm()

	if len(e.rf.Rules) != before+1 {
		t.Fatalf("rule count = %d, want %d", len(e.rf.Rules), before+1)
	}
	e.save()
	if e.errText != "" {
		t.Fatalf("save failed: %s", e.errText)
	}

	// Reload independently and confirm persistence + validation.
	f := config.NewFile[rules.RulesFile](path)
	f.Decode = rules.Decode
	f.Validate = rules.Validate
	if err := f.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	rf, _ := f.Current()
	var added *rules.Rule
	for i := range rf.Rules {
		if rf.Rules[i].Name == "ICMP_FLOOD" {
			added = &rf.Rules[i]
		}
	}
	if added == nil {
		t.Fatal("ICMP_FLOOD not persisted")
	}
	if added.Severity != "HIGH" || added.Rate != 5 {
		t.Fatalf("persisted rule = %+v", added)
	}
	if len(added.GroupBy) != 1 || added.GroupBy[0] != "src_ip" {
		t.Fatalf("group_by = %v", added.GroupBy)
	}
}

// TestRulesEditorToggleAndDelete checks list operations mark the file dirty.
func TestRulesEditorToggleAndDelete(t *testing.T) {
	path := seedRulesFile(t)
	e := newRulesEditor(path, nil)
	e.open()
	if len(e.rf.Rules) == 0 {
		t.Fatal("no rules loaded")
	}
	name := e.rf.Rules[0].Name
	wasEnabled := e.rf.Rules[0].IsEnabled()

	// Toggle.
	press(e, " ")
	if e.rf.Rules[0].IsEnabled() == wasEnabled {
		t.Fatal("space did not toggle the rule")
	}
	// Delete.
	press(e, "x")
	for _, r := range e.rf.Rules {
		if r.Name == name {
			t.Fatalf("rule %q was not deleted", name)
		}
	}
	if e.status == "" {
		t.Fatal("expected an unsaved status message")
	}
}

// TestParsersEditorAddDeviceAndField exercises the parser editor write path.
func TestParsersEditorAddDeviceAndField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "parsers.yaml")
	if err := os.WriteFile(path, []byte(parser.TemplateYAML), 0o644); err != nil {
		t.Fatalf("seed parsers: %v", err)
	}

	e := newParsersEditor(path, nil)
	e.open()

	// Add a device.
	e.startDeviceForm(-1)
	setForm(e.form, "name", "acme-fw")
	setForm(e.form, "hostname_match", "^acme-fw")
	setForm(e.form, "device_type", "firewall")
	e.applyForm()
	if len(e.cfg.Devices) != 1 {
		t.Fatalf("device count = %d, want 1", len(e.cfg.Devices))
	}

	// Add a field assignment.
	e.startFieldForm(0, -1)
	setForm(e.form, "target", "src_ip")
	setForm(e.form, "strategy", "kv")
	setForm(e.form, "key", "from")
	e.applyForm()
	if len(e.cfg.Devices[0].Fields) != 1 {
		t.Fatalf("field count = %d, want 1", len(e.cfg.Devices[0].Fields))
	}

	e.save()
	if e.errText != "" {
		t.Fatalf("save failed: %s", e.errText)
	}

	// Reload and confirm the device parses a line.
	f := config.NewFile[parser.Config](path)
	f.Decode = parser.DecodeConfig
	f.Validate = parser.ValidateConfig
	if err := f.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	cfg, _ := f.Current()
	if len(cfg.Devices) != 1 || cfg.Devices[0].Name != "acme-fw" {
		t.Fatalf("persisted config = %+v", cfg)
	}
	p, err := parser.NewParser(&cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	entry := p.Parse("2026-01-02T03:04:05+00:00 acme-fw-1 app: from=198.51.100.4")
	if entry.SrcIP != "198.51.100.4" {
		t.Fatalf("src_ip = %q, want 198.51.100.4", entry.SrcIP)
	}
}

// TestParsersEditorRejectsInvalidConfig ensures an invalid edit is not saved.
func TestParsersEditorRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "parsers.yaml")
	if err := os.WriteFile(path, []byte(parser.TemplateYAML), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	e := newParsersEditor(path, nil)
	e.open()

	// A kv field with no key is invalid.
	e.startDeviceForm(-1)
	setForm(e.form, "name", "bad")
	setForm(e.form, "hostname_match", "^bad")
	setForm(e.form, "device_type", "other")
	e.applyForm()
	e.startFieldForm(0, -1)
	setForm(e.form, "target", "src_ip")
	setForm(e.form, "strategy", "kv")
	setForm(e.form, "key", "")
	e.applyForm()

	if e.errText == "" {
		t.Fatal("expected a validation error for kv without key")
	}
	e.save()
	if e.errText == "" {
		t.Fatal("save should refuse an invalid document")
	}
}

// commitForm applies the current form values via applyForm.
func setForm(f *form, label, value string) {
	for i := range f.fields {
		if f.fields[i].label == label {
			f.fields[i].value = value
			return
		}
	}
}

// press sends a single-rune key to a rules editor.
func press(e *rulesEditor, key string) {
	e.update(keyMsgFor(key))
}

// keyMsgFor builds a rune key message.
func keyMsgFor(key string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
}
