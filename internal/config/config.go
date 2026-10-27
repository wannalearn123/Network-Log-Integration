// Package config loads, validates and atomically rewrites the user-editable
// YAML files that drive the parser and the rules engine.
//
// Both files are hot-reloaded: the pipeline re-reads them when their mtime
// changes, so edits from the TUI take effect without restarting the process.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Paths holds the on-disk locations of the editable configuration files.
type Paths struct {
	Rules   string
	Parsers string
}

// DefaultPaths resolves config/ relative to the project root.
func DefaultPaths(root string) Paths {
	return Paths{
		Rules:   filepath.Join(root, "config", "rules.yaml"),
		Parsers: filepath.Join(root, "config", "parsers.yaml"),
	}
}

// WriteAtomic replaces path with data without ever exposing a partial file.
// The temp file is created in the same directory so the rename stays on one
// filesystem and is therefore atomic.
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("config: create %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return fmt.Errorf("config: temp file: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename succeeds

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("config: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("config: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("config: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("config: rename to %s: %w", path, err)
	}
	return nil
}

// ErrNotLoaded is returned by Reload before a successful Load.
var ErrNotLoaded = errors.New("config: not loaded")

// File is a hot-reloadable YAML file of type T.
//
// The zero value is not usable; construct with NewFile. Call Load once at
// startup, then Reload from the pipeline tick. Loaded snapshots are immutable
// and safe to share across goroutines.
type File[T any] struct {
	mu      sync.RWMutex
	path    string
	value   T
	loaded  bool
	modTime time.Time
	// Decode converts raw bytes into T. Set before first use.
	Decode func([]byte) (T, error)
	// Validate rejects a decoded value. Set before first use.
	Validate func(T) error
}

// NewFile binds a File to path. Decode and Validate must be set by the caller.
func NewFile[T any](path string) *File[T] {
	return &File[T]{path: path}
}

// Path reports the file location.
func (f *File[T]) Path() string { return f.path }

// Current returns the last successfully loaded value.
func (f *File[T]) Current() (T, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.value, f.loaded
}

// Load reads the file unconditionally. A decode or validation error leaves the
// previously loaded value intact and is returned to the caller.
func (f *File[T]) Load() error {
	info, err := os.Stat(f.path)
	if err != nil {
		return fmt.Errorf("config: stat %s: %w", f.path, err)
	}
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return fmt.Errorf("config: read %s: %w", f.path, err)
	}
	if f.Decode == nil || f.Validate == nil {
		return errors.New("config: Decode and Validate must be set")
	}
	value, err := f.Decode(raw)
	if err != nil {
		return fmt.Errorf("config: decode %s: %w", f.path, err)
	}
	if err := f.Validate(value); err != nil {
		return fmt.Errorf("config: invalid %s: %w", f.path, err)
	}

	f.mu.Lock()
	f.value = value
	f.loaded = true
	f.modTime = info.ModTime()
	f.mu.Unlock()
	return nil
}

// Reload re-reads the file only when its mtime moved since the last successful
// read. It reports whether the in-memory value changed.
//
// A missing or malformed file keeps the old value and returns the error, so a
// half-written edit from an editor can never disable detection.
func (f *File[T]) Reload() (changed bool, err error) {
	info, statErr := os.Stat(f.path)
	if statErr != nil {
		return false, fmt.Errorf("config: stat %s: %w", f.path, statErr)
	}

	f.mu.RLock()
	prev := f.modTime
	f.mu.RUnlock()
	if info.ModTime().Equal(prev) {
		return false, nil
	}
	if err := f.Load(); err != nil {
		return false, err
	}
	return true, nil
}

// Save validates value and atomically writes it to the bound path, then makes
// it current. Save is what the TUI calls after an edit.
func (f *File[T]) Save(value T, encode func(T) ([]byte, error)) error {
	if f.Validate == nil {
		return errors.New("config: Validate must be set")
	}
	if err := f.Validate(value); err != nil {
		return fmt.Errorf("config: refusing to save invalid %s: %w", f.path, err)
	}
	if encode == nil {
		return errors.New("config: encode function required")
	}
	raw, err := encode(value)
	if err != nil {
		return fmt.Errorf("config: encode %s: %w", f.path, err)
	}
	if err := WriteAtomic(f.path, raw); err != nil {
		return err
	}

	info, err := os.Stat(f.path)
	f.mu.Lock()
	f.value = value
	f.loaded = true
	if err == nil {
		f.modTime = info.ModTime()
	}
	f.mu.Unlock()
	return nil
}

// LoadOrSeed loads path, creating it from seed when it does not exist yet.
// The seed is encoded with encode so first-run output matches TUI output.
func LoadOrSeed[T any](f *File[T], seed T, encode func(T) ([]byte, error)) error {
	if _, err := os.Stat(f.path); errors.Is(err, os.ErrNotExist) {
		raw, encErr := encode(seed)
		if encErr != nil {
			return fmt.Errorf("config: seed encode %s: %w", f.path, encErr)
		}
		if err := WriteAtomic(f.path, raw); err != nil {
			return err
		}
	}
	return f.Load()
}
