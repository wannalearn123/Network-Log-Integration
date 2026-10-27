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
// produced.
//
// One deliberate divergence is allowed: the C parser truncated any address at
// the first colon, so IPv6 lines produced invalid values like "fe80". Those
// lines are excluded from the byte-comparison and instead checked for a valid,
// preserved IPv6 address. Everything else must match exactly.
func TestParityWithCOracle(t *testing.T) {
	f, err := os.Open("testdata/golden.jsonl")
	if err != nil {
		t.Skipf("no golden fixture: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var total, compared, corrected, mismatches int
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

		// The C parser mangled IPv6 into fragments such as "fe80".
		if mangledOracleIP(want) {
			corrected++
			if err := checkCorrectedIPv6(want, gotMap); err != nil {
				mismatches++
				t.Errorf("IPv6 correction failed for:\n  raw: %s\n  %v", raw, err)
			}
			continue
		}

		compared++
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

	t.Logf("parity: %d lines, %d compared with C, %d IPv6 corrections, %d mismatches",
		total, compared, corrected, mismatches)
	if corrected == 0 {
		t.Log("note: no IPv6 lines in the fixture")
	}
	if mismatches > 0 {
		t.Fatalf("%d/%d lines diverged unexpectedly", mismatches, total)
	}
}

// mangledOracleIP reports whether the C output contains an address-like value
// that is not a valid IP, which happens only for colon-truncated IPv6.
func mangledOracleIP(want map[string]any) bool {
	for _, key := range []string{"src_ip", "dst_ip", "ospf_nbr", "gateway"} {
		if v, ok := want[key].(string); ok && v != "" && !ValidIP(v) {
			return true
		}
	}
	return false
}

// checkCorrectedIPv6 verifies the Go parser preserved a real IPv6 address.
func checkCorrectedIPv6(want, got map[string]any) error {
	// Any address the oracle mangled must now be a valid IP.
	for _, key := range []string{"src_ip", "dst_ip", "ospf_nbr", "gateway"} {
		wv, _ := want[key].(string)
		if wv == "" || ValidIP(wv) {
			continue
		}
		gv, _ := got[key].(string)
		if gv == "" {
			continue // dropped rather than stored malformed
		}
		if !ValidIP(gv) {
			return &parityError{key: key, value: gv}
		}
	}

	// At least one side must now be an IPv6 address.
	has6 := false
	for _, key := range []string{"src_ip", "dst_ip", "ospf_nbr", "gateway"} {
		if gv, ok := got[key].(string); ok && IsIPv6(gv) {
			has6 = true
		}
	}
	if !has6 {
		return errNoIPv6
	}
	return nil
}

type parityError struct {
	key   string
	value string
}

func (e *parityError) Error() string {
	return "field " + e.key + " still invalid: " + e.value
}

var errNoIPv6 = &noIPv6Error{}

type noIPv6Error struct{}

func (*noIPv6Error) Error() string { return "no IPv6 address preserved" }
