package rules

import (
	"fmt"
	"sort"
	"strings"

	"siskamlan/internal/parser"
)

// Detect evaluates every enabled rule against the rows and returns hits.
//
// Window is the observation window in seconds; a rule's own WindowSeconds, if
// set, overrides it. Results keep rule order so behaviour is deterministic.
func Detect(rows []*parser.Entry, rf RulesFile, window int) []Hit {
	if window <= 0 {
		window = 30
	}

	var hits []Hit

	for _, rule := range rf.Rules {
		if !rule.IsEnabled() {
			continue
		}
		w := ruleWindow(rule, rf, window)
		if w <= 0 {
			w = 30
		}

		// Collect matching rows grouped by the configured key.
		groups := map[string][]*parser.Entry{}
		var order []string
		for _, row := range rows {
			if !Match(rule.When, row) {
				continue
			}
			key, ok := groupKey(rule.GroupBy, row)
			if !ok {
				continue // a group field is empty; original engine skips these
			}
			if _, seen := groups[key]; !seen {
				order = append(order, key)
			}
			groups[key] = append(groups[key], row)
		}

		for _, key := range order {
			members := groups[key]
			count := len(members)
			if rule.IsDistinct() {
				count = distinctCount(rule.DistinctOn, members)
			}
			if count == 0 {
				continue
			}
			if rule.MinCount > 0 && count < rule.MinCount {
				continue
			}
			rate := float64(count) / float64(w)
			if rate < rule.Rate {
				continue
			}

			entity := groupEntity(rule.GroupBy, key)
			hits = append(hits, Hit{
				Type:        rule.Name,
				Severity:    rule.Severity,
				Description: render(rule, entity, count, w),
				Entity:      entity,
				SrcIP:       srcIPFor(entity),
			})
		}
	}

	return applySuppression(hits, rf)
}

func ruleWindow(rule Rule, rf RulesFile, fallback int) int {
	if rf.WindowSeconds > 0 {
		return rf.WindowSeconds
	}
	return fallback
}

// groupKey joins the rendered group fields. An empty group list yields one
// global bucket with key "". The bool is false when a grouped field is empty,
// which callers use to skip the row (mirroring the original engine).
func groupKey(fields []string, e *parser.Entry) (string, bool) {
	if len(fields) == 0 {
		return "", true
	}
	parts := make([]string, len(fields))
	for i, f := range fields {
		s, ok := fieldString(RowField(e, f))
		if !ok || s == "" {
			return "", false
		}
		parts[i] = s
	}
	return strings.Join(parts, "\x00"), true
}

func distinctCount(field string, rows []*parser.Entry) int {
	seen := map[string]struct{}{}
	for _, r := range rows {
		if s, ok := fieldString(RowField(r, field)); ok {
			seen[s] = struct{}{}
		}
	}
	return len(seen)
}

// groupEntity returns the first group field's value, or "" for global rules.
func groupEntity(fields []string, key string) string {
	if len(fields) == 0 {
		return ""
	}
	if i := strings.IndexByte(key, 0); i >= 0 {
		return key[:i]
	}
	return key
}

func render(rule Rule, entity string, count, window int) string {
	desc := rule.Description
	if desc == "" {
		desc = rule.Name
	}
	if entity == "" {
		entity = "-"
	}
	r := strings.NewReplacer(
		"{entity}", entity,
		"{count}", fmt.Sprint(count),
		"{window}", fmt.Sprint(window),
		"{rule}", rule.Name,
	)
	return r.Replace(desc)
}

func srcIPFor(entity string) *string {
	if ipv4Re.MatchString(entity) {
		e := entity
		return &e
	}
	return nil
}

// applySuppression drops hits whose (rule, entity) is covered by another rule.
func applySuppression(hits []Hit, rf RulesFile) []Hit {
	suppressors := map[string]map[string]bool{}
	for _, r := range rf.Rules {
		if len(r.SuppressBy) == 0 {
			continue
		}
		if _, ok := suppressors[r.Name]; !ok {
			suppressors[r.Name] = map[string]bool{}
		}
	}
	if len(suppressors) == 0 {
		return hits
	}

	// Which rule fired for which entity.
	fired := map[string]map[string]bool{}
	for _, h := range hits {
		if fired[h.Type] == nil {
			fired[h.Type] = map[string]bool{}
		}
		fired[h.Type][h.Entity] = true
	}

	keep := hits[:0]
	for _, h := range hits {
		rule := findRule(rf, h.Type)
		suppressed := false
		if rule != nil {
			for _, s := range rule.SuppressBy {
				if fired[s][h.Entity] {
					suppressed = true
					break
				}
			}
		}
		if !suppressed {
			keep = append(keep, h)
		}
	}
	return keep
}

func findRule(rf RulesFile, name string) *Rule {
	for i := range rf.Rules {
		if rf.Rules[i].Name == name {
			return &rf.Rules[i]
		}
	}
	return nil
}

// SeverityRank returns an ordering value for a severity label.
func SeverityRank(s string) int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return -1
}

// SortBySeverity orders hits from most to least severe, preserving order
// among equals.
func SortBySeverity(hits []Hit) {
	sort.SliceStable(hits, func(i, j int) bool {
		return SeverityRank(hits[i].Severity) > SeverityRank(hits[j].Severity)
	})
}
