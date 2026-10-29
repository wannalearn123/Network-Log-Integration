package tui

import (
	"fmt"
	"strings"

	"siskamlan/internal/rules"
)

// describeCondition renders a rule condition as one readable line, so the
// editor can show what a rule actually matches.
//
// The form can only express a single "event contains any of these" filter. A
// nested tree is displayed but never rewritten: rewriting it would silently
// widen the rule to match every row.
func describeCondition(c rules.Condition) string {
	return describeCond(c, true)
}

// describeCond renders a condition, parenthesising nested groups so an
// AND inside an OR cannot be misread.
func describeCond(c rules.Condition, top bool) string {
	var parts []string
	for _, sub := range c.All {
		parts = append(parts, describeCond(sub, false))
	}
	if len(c.Any) > 0 {
		or := make([]string, 0, len(c.Any))
		for _, sub := range c.Any {
			or = append(or, describeCond(sub, false))
		}
		parts = append(parts, "("+strings.Join(or, " OR ")+")")
	}
	if c.Not != nil {
		parts = append(parts, "NOT ("+describeCond(*c.Not, false)+")")
	}
	if c.Field != "" {
		parts = append(parts, describeLeaf(c))
	}
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}
	s := strings.Join(parts, " AND ")
	if !top {
		s = "(" + s + ")"
	}
	return s
}

// describeLeaf renders a single comparison.
func describeLeaf(c rules.Condition) string {
	op := c.Op
	if op == "" {
		op = "eq"
	}
	switch {
	case op == "exists" || op == "not_exists":
		return c.Field + " " + op
	case len(c.Values) > 0:
		vals := make([]string, 0, len(c.Values))
		for _, v := range c.Values {
			vals = append(vals, fmt.Sprint(v))
		}
		return c.Field + " " + op + " [" + strings.Join(vals, "|") + "]"
	case c.Value != nil:
		return c.Field + " " + op + " " + fmt.Sprint(c.Value)
	default:
		return c.Field + " " + op
	}
}

// editableEventFilter reports whether the condition is one the form can edit,
// and returns its substrings when it is.
//
// A zero condition counts as editable (an empty list means "all rows"), as
// does an event leaf using contains_any or a single contains value — the
// shapes the form writes. Anything else is left alone rather than flattened.
func editableEventFilter(c rules.Condition) ([]string, bool) {
	if len(c.All) == 0 && len(c.Any) == 0 && c.Not == nil && c.Field == "" {
		return nil, true
	}
	if len(c.All) > 0 || len(c.Any) > 0 || c.Not != nil || c.Field != "event" {
		return nil, false
	}
	switch c.Op {
	case "contains_any":
		if c.Value != nil {
			return nil, false
		}
		out := make([]string, 0, len(c.Values))
		for _, v := range c.Values {
			out = append(out, fmt.Sprint(v))
		}
		return out, true
	case "contains":
		if s, ok := c.Value.(string); ok {
			return []string{s}, true
		}
	}
	return nil, false
}

// matchesSummary is the one-line "what does this rule match" cell for the list.
func matchesSummary(r rules.Rule) string {
	if s := describeCondition(r.When); s != "" {
		return s
	}
	return "(all rows)"
}
