package rules

import (
	"bufio"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestParityWithPythonEngine compares the Go rules engine against the original
// Python detect_rules() output over the same row corpus. The oracle file is
// produced by scripts/gen_rules_oracle.py.
func TestParityWithPythonEngine(t *testing.T) {
	want, err := readLines("testdata/python_hits.txt")
	if err != nil {
		t.Skipf("no oracle fixture: %v", err)
	}

	corpus := loadCorpus(t)
	hits := Detect(corpus, DefaultRulesFile(), 30)

	got := make([]string, 0, len(hits))
	for _, h := range hits {
		got = append(got, h.Type+"|"+h.Entity)
	}
	sort.Strings(got)

	if len(got) != len(want) {
		t.Errorf("hit count = %d, want %d", len(got), len(want))
	}
	missing, extra := diff(want, got)
	for _, m := range missing {
		t.Errorf("missing hit: %s", m)
	}
	for _, e := range extra {
		t.Errorf("unexpected hit: %s", e)
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			out = append(out, s)
		}
	}
	return out, sc.Err()
}

// diff returns entries present in want but not got, and vice versa.
func diff(want, got []string) (missing, extra []string) {
	w := map[string]int{}
	for _, s := range want {
		w[s]++
	}
	g := map[string]int{}
	for _, s := range got {
		g[s]++
	}
	for s, n := range w {
		if g[s] < n {
			missing = append(missing, s)
		}
	}
	for s, n := range g {
		if w[s] < n {
			extra = append(extra, s)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}
