package main

import (
	"os"
	"path/filepath"
	"testing"

	"siskamlan/internal/config"
	"siskamlan/internal/parser"
	"siskamlan/internal/rules"
)

// TestLoadConfigsSeedsBothFiles checks a fresh install is bootstrapped.
func TestLoadConfigsSeedsBothFiles(t *testing.T) {
	root := t.TempDir()

	cfgs, err := loadConfigs(root)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}

	// Both files must now exist.
	for _, p := range []string{cfgs.paths.Rules, cfgs.paths.Parsers} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to be seeded: %v", p, err)
		}
	}

	// The rules file must contain the shipped defaults.
	rf, ok := cfgs.rules.Current()
	if !ok || len(rf.Rules) == 0 {
		t.Fatalf("rules not loaded: %+v", rf)
	}
	if err := rules.Validate(rf); err != nil {
		t.Fatalf("seeded rules invalid: %v", err)
	}

	// The parser template ships with comments and no devices.
	raw, err := os.ReadFile(cfgs.paths.Parsers)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("parser template is empty")
	}
	if cfgs.parsers == nil {
		t.Fatal("parser provider not built")
	}
}

// TestLoadConfigsKeepsExistingFiles ensures a real configuration is never
// overwritten by the shipped defaults on restart.
func TestLoadConfigsKeepsExistingFiles(t *testing.T) {
	root := t.TempDir()
	paths := config.DefaultPaths(root)
	if err := os.MkdirAll(filepath.Dir(paths.Rules), 0o755); err != nil {
		t.Fatal(err)
	}

	// A user file with a single custom rule.
	userRules := rules.RulesFile{Version: 1, WindowSeconds: 30, Rules: []rules.Rule{{
		Name: "ONLY_RULE", Severity: "LOW", Rate: 1, Description: "custom",
	}}}
	raw, err := rules.Encode(userRules)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Rules, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	cfgs, err := loadConfigs(root)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}
	rf, _ := cfgs.rules.Current()
	if len(rf.Rules) != 1 || rf.Rules[0].Name != "ONLY_RULE" {
		t.Fatalf("existing rules were replaced: %+v", rf.Rules)
	}
}

// TestLoadConfigsRejectsInvalidRules surfaces a broken file instead of
// silently falling back to defaults.
func TestLoadConfigsRejectsInvalidRules(t *testing.T) {
	root := t.TempDir()
	paths := config.DefaultPaths(root)
	if err := os.MkdirAll(filepath.Dir(paths.Rules), 0o755); err != nil {
		t.Fatal(err)
	}
	// A rule with no severity fails validation.
	if err := os.WriteFile(paths.Rules, []byte("version: 1\nrules:\n  - name: X\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfigs(root); err == nil {
		t.Fatal("invalid rules were accepted at startup")
	}
}

// TestLoadConfigsSeedsParserTemplate checks the commented template is written
// verbatim rather than re-encoded (which would drop the guidance comments).
func TestLoadConfigsSeedsParserTemplate(t *testing.T) {
	root := t.TempDir()
	cfgs, err := loadConfigs(root)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}
	raw, err := os.ReadFile(cfgs.paths.Parsers)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != parser.TemplateYAML {
		t.Fatal("seeded parser file differs from the template")
	}
}

// TestProjectRootIsSet guards the init-time root resolution.
func TestProjectRootIsSet(t *testing.T) {
	if projectRoot == "" {
		t.Fatal("projectRoot is empty; config paths would resolve incorrectly")
	}
}
