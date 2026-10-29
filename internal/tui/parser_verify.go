package tui

import (
	"fmt"

	"siskamlan/internal/parser"
)

// verifyRule checks that a rule extracts something on its own from the lines
// the operator is looking at.
//
// Two things make this check subtler than it looks:
//
//  1. A `kv` rule with `key: Host` passes schema validation (kv only needs a
//     key) but extracts nothing from a switch log, because the vendor never
//     writes `Host=`.
//  2. The built-in extractors already fill columns like mac/vlan_id/ifname
//     from switch, router, and AP lines. So "the column has a value" proves
//     nothing — the built-in parser may have put it there while the custom
//     rule did nothing.
//
// parser.ApplyFieldRule clears the target column and applies only this rule,
// which is what makes the result trustworthy.
func verifyRule(rule parser.FieldRule, lines []string) error {
	if len(lines) == 0 {
		// Nothing to check against; schema validation already passed.
		return nil
	}
	for _, line := range lines {
		if v, ok := parser.ApplyFieldRule(rule, line); ok && v != "" {
			return nil
		}
	}
	return fmt.Errorf("%s extraction produced nothing for %q — check the %s against the file",
		rule.Strategy, rule.Target, ruleHint(rule))
}

// ruleHint names the input that decides whether the rule works.
func ruleHint(rule parser.FieldRule) string {
	switch rule.Strategy {
	case "kv":
		return "key (it must appear as KEY=value)"
	case "regex":
		return "pattern"
	case "word_map":
		return "source and map"
	case "positional":
		return "pos"
	}
	return "rule"
}
