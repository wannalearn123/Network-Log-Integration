package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// TestFieldFormExplainsStrategies checks the field-assignment form explains
// what each strategy means and which inputs it reads.
func TestFieldFormExplainsStrategies(t *testing.T) {
	e := newParsersEditorWithTemplate(t)
	e.startFieldForm(0, -1)

	if e.form.subtitle == "" {
		t.Error("field form has no subtitle explaining that unused inputs can stay empty")
	}
	for _, label := range []string{"target", "strategy", "key", "pattern", "source", "map", "pos", "type"} {
		f := fieldByLabel(e.form, label)
		if f == nil {
			t.Fatalf("field form missing %q", label)
		}
		if strings.TrimSpace(f.help) == "" {
			t.Errorf("field %q has no help text", label)
		}
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
// when no database is attached (tests, or a failed connection).
func TestSampleViewWithoutStoreIsSilent(t *testing.T) {
	e := newParsersEditorWithTemplate(t)
	if lines := e.sampleView(80, 3); lines != nil {
		t.Fatalf("expected no sample block without a store, got %v", lines)
	}
}
