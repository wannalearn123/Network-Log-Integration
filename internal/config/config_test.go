package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

type sample struct {
	Version int      `yaml:"version"`
	Names   []string `yaml:"names"`
}

func decodeSample(raw []byte) (sample, error) {
	var s sample
	err := yaml.Unmarshal(raw, &s)
	return s, err
}

func encodeSample(s sample) ([]byte, error) { return yaml.Marshal(s) }

func validateSample(s sample) error { return nil }

func newSampleFile(t *testing.T, path string) *File[sample] {
	t.Helper()
	f := NewFile[sample](path)
	f.Decode = decodeSample
	f.Validate = validateSample
	return f
}

func TestLoadOrSeedCreatesFileAndLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config", "rules.yaml")
	f := newSampleFile(t, path)

	if err := LoadOrSeed(f, sample{Version: 1, Names: []string{"a"}}, encodeSample); err != nil {
		t.Fatalf("LoadOrSeed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("seed file not created: %v", err)
	}
	got, ok := f.Current()
	if !ok || got.Version != 1 || len(got.Names) != 1 {
		t.Fatalf("unexpected value: %+v ok=%v", got, ok)
	}
}

func TestReloadDetectsChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	f := newSampleFile(t, path)

	if err := LoadOrSeed(f, sample{Version: 1}, encodeSample); err != nil {
		t.Fatalf("seed: %v", err)
	}

	changed, err := f.Reload()
	if err != nil {
		t.Fatalf("Reload with no change: %v", err)
	}
	if changed {
		t.Fatal("Reload reported change without touching the file")
	}

	// Rewrite with a distinct mtime.
	if err := WriteAtomic(path, []byte("version: 2\nnames: [x, y]\n")); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	bumpMtime(t, path)

	changed, err = f.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !changed {
		t.Fatal("Reload missed a modified file")
	}
	got, _ := f.Current()
	if got.Version != 2 || len(got.Names) != 2 {
		t.Fatalf("stale value after reload: %+v", got)
	}
}

func TestReloadKeepsPreviousValueOnMalformedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	f := newSampleFile(t, path)

	if err := LoadOrSeed(f, sample{Version: 7}, encodeSample); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A broken edit must never disable detection.
	if err := WriteAtomic(path, []byte("version: [unclosed\n")); err != nil {
		t.Fatalf("write bad yaml: %v", err)
	}
	bumpMtime(t, path)

	if _, err := f.Reload(); err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
	got, _ := f.Current()
	if got.Version != 7 {
		t.Fatalf("previous value lost: %+v", got)
	}
}

func TestSaveRejectsInvalidValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	f := NewFile[sample](path)
	f.Decode = decodeSample
	f.Validate = func(s sample) error {
		if s.Version <= 0 {
			return os.ErrInvalid
		}
		return nil
	}

	if err := f.Save(sample{Version: 0}, encodeSample); err == nil {
		t.Fatal("Save accepted an invalid value")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("Save wrote a file for an invalid value")
	}
}

func TestWriteAtomicLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	for i := 0; i < 5; i++ {
		if err := WriteAtomic(path, []byte("version: 1\n")); err != nil {
			t.Fatalf("WriteAtomic: %v", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("temp files leaked: %v", names)
	}
}

func TestLoadDotEnvDoesNotOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "# comment\nexport KEPT=from_file\nALSO=from_file\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	t.Setenv("KEPT", "from_env")
	os.Unsetenv("ALSO")
	t.Cleanup(func() { os.Unsetenv("ALSO") })

	root := LoadDotEnv(path)
	if root != dir {
		t.Fatalf("root = %q, want %q", root, dir)
	}
	if got := os.Getenv("KEPT"); got != "from_env" {
		t.Fatalf("existing env overwritten: %q", got)
	}
	if got := os.Getenv("ALSO"); got != "from_file" {
		t.Fatalf("ALSO = %q, want from_file", got)
	}
}

func bumpMtime(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	next := info.ModTime().Add(2 * 1e9)
	if err := os.Chtimes(path, next, next); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}
