package pipeline

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"siskamlan/internal/config"
	"siskamlan/internal/parser"
)

// writeParserConfig writes a parsers.yaml and bumps its mtime.
func writeParserConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write parser config: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}

func newTestProvider(t *testing.T) (*ParserProvider, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "parsers.yaml")
	if err := os.WriteFile(path, []byte(parser.TemplateYAML), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	f := config.NewFile[parser.Config](path)
	f.Decode = parser.DecodeConfig
	f.Validate = parser.ValidateConfig
	if err := f.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	return NewParserProvider(f), path
}

// TestParserProviderAppliesConfig checks a device profile is honoured.
func TestParserProviderAppliesConfig(t *testing.T) {
	p, path := newTestProvider(t)
	writeParserConfig(t, path, `
version: 1
devices:
  - name: acme
    hostname_match: ['^acme-']
    fields:
      - {target: src_ip, strategy: kv, key: from}
`)
	p.Reload()

	e := p.Parse("2026-01-02T03:04:05+00:00 acme-1 app: from=198.51.100.9")
	if e.SrcIP != "198.51.100.9" {
		t.Fatalf("src_ip = %q, want 198.51.100.9", e.SrcIP)
	}
}

// TestParserProviderKeepsPreviousOnInvalidEdit is the safety property: a
// broken edit must not stop parsing.
func TestParserProviderKeepsPreviousOnInvalidEdit(t *testing.T) {
	p, path := newTestProvider(t)
	writeParserConfig(t, path, `
version: 1
devices:
  - name: acme
    hostname_match: ['^acme-']
    fields:
      - {target: src_ip, strategy: kv, key: from}
`)
	p.Reload()

	// A malformed edit.
	writeParserConfig(t, path, "version: 1\ndevices: [ {name: broken\n")
	p.Reload() // must not panic or drop the working parser

	e := p.Parse("2026-01-02T03:04:05+00:00 acme-1 app: from=198.51.100.9")
	if e.SrcIP != "198.51.100.9" {
		t.Fatalf("previous config lost after invalid edit: src_ip = %q", e.SrcIP)
	}
}

// TestParserProviderAppliesValidReplacement checks a good edit takes effect.
func TestParserProviderAppliesValidReplacement(t *testing.T) {
	p, path := newTestProvider(t)
	writeParserConfig(t, path, `
version: 1
devices:
  - name: one
    hostname_match: ['^acme-']
    fields:
      - {target: src_ip, strategy: kv, key: from}
`)
	p.Reload()

	writeParserConfig(t, path, `
version: 1
devices:
  - name: two
    hostname_match: ['^acme-']
    fields:
      - {target: src_ip, strategy: kv, key: source}
`)
	p.Reload()

	e := p.Parse("2026-01-02T03:04:05+00:00 acme-1 app: source=203.0.113.5 from=198.51.100.9")
	if e.SrcIP != "203.0.113.5" {
		t.Fatalf("src_ip = %q, want the new key's value 203.0.113.5", e.SrcIP)
	}
}

// TestParserProviderWithoutConfigUsesBuiltin checks the nil-config fallback.
func TestParserProviderWithoutConfigUsesBuiltin(t *testing.T) {
	p, _ := newTestProvider(t)
	e := p.Parse("2026-01-02T03:04:05+00:00 switch.example rgos: Host aa:bb:cc:dd:ee:ff learned on Gi0/4 vlan 12")
	if e.Event != "mac_learn" || e.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("built-in parsing not used: %+v", e)
	}
}

// TestParserProviderReloadIsNoopWithoutChange checks mtime gating.
func TestParserProviderReloadIsNoopWithoutChange(t *testing.T) {
	p, _ := newTestProvider(t)
	for i := 0; i < 3; i++ {
		p.Reload() // no file change; must stay stable
	}
	if e := p.Parse("2026-01-02T03:04:05+00:00 host tag: x"); e == nil {
		t.Fatal("parser returned nil after no-op reloads")
	}
}
