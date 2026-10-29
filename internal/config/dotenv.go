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
		value = unquote(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}
	return root
}

// unquote returns the value of a KEY=VALUE right-hand side. A quoted value is
// taken verbatim between its quotes. An unquoted value ends at the first " #",
// so `https://x   # comment` yields `https://x`, as python-dotenv does.
func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		if end := strings.IndexByte(v[1:], v[0]); end >= 0 {
			return v[1 : 1+end]
		}
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	} else if i := strings.Index(v, "\t#"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
