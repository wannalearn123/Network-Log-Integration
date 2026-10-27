package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// LoadDotEnv reads KEY=VALUE pairs from path into the process environment
// without overriding variables already set. It mirrors python-dotenv's
// default behaviour used by db/init.py. A missing file is not an error.
//
// It returns the project root (the directory holding path) so callers can
// resolve config/ and data/ relative to it.
func LoadDotEnv(path string) string {
	root := filepath.Dir(path)
	f, err := os.Open(path)
	if err != nil {
		return root
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}
	return root
}
