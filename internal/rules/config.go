package rules

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Decode parses a rules document.
func Decode(raw []byte) (RulesFile, error) {
	var rf RulesFile
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&rf); err != nil {
		return RulesFile{}, err
	}
	return rf, nil
}

// Encode serializes a rules document with a stable rule order.
func Encode(rf RulesFile) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(rf); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Validate rejects documents that the engine cannot evaluate.
func Validate(rf RulesFile) error {
	if len(rf.Rules) == 0 {
		return fmt.Errorf("rules: at least one rule is required")
	}
	if rf.WindowSeconds < 0 {
		return fmt.Errorf("rules: window_seconds must be nonnegative")
	}
	names := map[string]bool{}
	for i, r := range rf.Rules {
		where := fmt.Sprintf("rules[%d]", i)
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("%s: name is required", where)
		}
		where = fmt.Sprintf("rule %q", r.Name)
		if names[r.Name] {
			return fmt.Errorf("%s: duplicate name", where)
		}
		names[r.Name] = true

		if SeverityRank(r.Severity) < 0 {
			return fmt.Errorf("%s: severity must be one of %s", where, strings.Join(Severities, ", "))
		}
		if r.Rate < 0 {
			return fmt.Errorf("%s: rate must be nonnegative", where)
		}
		if r.Rate == 0 && r.MinCount == 0 {
			return fmt.Errorf("%s: set a positive rate or min_count", where)
		}
		if r.Count != "" && r.Count != "rows" && r.Count != "distinct" {
			return fmt.Errorf("%s: count must be \"rows\" or \"distinct\"", where)
		}
		if r.IsDistinct() && r.DistinctOn == "" {
			return fmt.Errorf("%s: count: distinct requires distinct_on", where)
		}
		if r.DistinctOn != "" && !isField(r.DistinctOn) {
			return fmt.Errorf("%s: unknown distinct_on field %q", where, r.DistinctOn)
		}
		for _, g := range r.GroupBy {
			if !isField(g) {
				return fmt.Errorf("%s: unknown group_by field %q", where, g)
			}
		}
		if err := validateCondition(r.When, where); err != nil {
			return err
		}
	}
	return nil
}

func isField(name string) bool {
	for _, f := range KnownFields {
		if f == name {
			return true
		}
	}
	return false
}

var operators = map[string]bool{
	"eq": true, "ne": true,
	"contains": true, "icontains": true, "contains_any": true,
	"prefix": true, "iprefix": true, "suffix": true, "isuffix": true,
	"regex": true, "in": true, "not_in": true, "exists": true, "not_exists": true,
	"gt": true, "gte": true, "lt": true, "lte": true,
}

func validateCondition(c Condition, where string) error {
	if c.Field != "" {
		if !isField(c.Field) {
			return fmt.Errorf("%s: unknown field %q", where, c.Field)
		}
		if c.Op != "" && !operators[c.Op] {
			return fmt.Errorf("%s: unknown op %q", where, c.Op)
		}
		if (c.Op == "in" || c.Op == "not_in" || c.Op == "contains_any") && len(c.Values) == 0 {
			return fmt.Errorf("%s: op %q requires values", where, c.Op)
		}
		if c.Op == "regex" {
			return nil // validated at match time
		}
	}
	for _, sub := range c.All {
		if err := validateCondition(sub, where); err != nil {
			return err
		}
	}
	for _, sub := range c.Any {
		if err := validateCondition(sub, where); err != nil {
			return err
		}
	}
	if c.Not != nil {
		return validateCondition(*c.Not, where)
	}
	return nil
}

// Names returns the rule names in document order.
func Names(rf RulesFile) []string {
	out := make([]string, len(rf.Rules))
	for i, r := range rf.Rules {
		out[i] = r.Name
	}
	return out
}

// SortNames returns a sorted copy of the rule names.
func SortNames(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}
