package parser

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestParityWithCOracle replays every captured sample through the Go parser
// and compares it field-for-field against the JSON the original C collector
// produced. The fixture is generated once from the compiled C binary, so this
// test is the proof that the port did not change behaviour.
func TestParityWithCOracle(t *testing.T) {
	f, err := os.Open("testdata/golden.jsonl")
	if err != nil {
		t.Skipf("no golden fixture: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var total, mismatches int
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		total++

		var want map[string]any
		if err := json.Unmarshal([]byte(line), &want); err != nil {
			t.Fatalf("bad golden line: %v", err)
		}
		raw, _ := want["raw_line"].(string)

		got := Parse(raw)
		if got == nil {
			mismatches++
			t.Errorf("Parse returned nil for %q", raw)
			continue
		}
		gotJSON, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var gotMap map[string]any
		if err := json.Unmarshal(gotJSON, &gotMap); err != nil {
			t.Fatalf("unmarshal got: %v", err)
		}

		if !reflect.DeepEqual(want, gotMap) {
			mismatches++
			if mismatches <= 15 {
				t.Errorf("mismatch for line:\n  raw:  %s\n  want: %v\n  got:  %v",
					raw, want, gotMap)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	t.Logf("parity: %d lines, %d mismatches", total, mismatches)
	if mismatches > 0 {
		t.Fatalf("%d/%d lines diverged from the C oracle", mismatches, total)
	}
}
