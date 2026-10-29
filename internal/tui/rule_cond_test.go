package tui

import (
	"reflect"
	"strings"
	"testing"

	"siskamlan/internal/rules"
)

// TestDescribeCondition pins the one-line summaries the editor shows, since
// they are the only way an operator can tell what a rule matches.
func TestDescribeCondition(t *testing.T) {
	cases := []struct {
		name string
		when rules.Condition
		want string
	}{
		{"empty", rules.Condition{}, ""},
		{"exists", rules.Condition{Field: "src_ip", Op: "exists"}, "src_ip exists"},
		{"contains", rules.Condition{Field: "event", Op: "contains", Value: "DEAUTH"},
			"event contains DEAUTH"},
		{"contains_any", rules.Condition{Field: "event", Op: "contains_any",
			Values: []any{"BRUTE", "AUTH_FAILURE"}}, "event contains_any [BRUTE|AUTH_FAILURE]"},
		{"all", rules.Condition{All: []rules.Condition{
			{Field: "src_ip", Op: "exists"},
			{Field: "dst_port", Op: "exists"},
		}}, "src_ip exists AND dst_port exists"},
		{"any of one", rules.Condition{Any: []rules.Condition{
			{Field: "event", Op: "eq", Value: "MAC_FLAP"},
		}}, "(event eq MAC_FLAP)"},
		{"all inside any", rules.Condition{Any: []rules.Condition{
			{Field: "event", Op: "contains", Value: "A"},
			{All: []rules.Condition{
				{Field: "event", Op: "contains", Value: "B"},
				{Field: "dst_port", Op: "in", Values: []any{22, 443}},
			}},
		}}, "(event contains A OR (event contains B AND dst_port in [22|443]))"},
	}
	for _, c := range cases {
		if got := describeCondition(c.when); got != c.want {
			t.Errorf("%s: describeCondition = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestEditableEventFilter checks which conditions the form may rewrite. A
// condition it cannot express must report false so applyForm leaves it alone.
func TestEditableEventFilter(t *testing.T) {
	cases := []struct {
		name string
		when rules.Condition
		ok   bool
	}{
		{"empty", rules.Condition{}, true},
		{"contains_any", rules.Condition{Field: "event", Op: "contains_any",
			Values: []any{"A", "B"}}, true},
		{"contains", rules.Condition{Field: "event", Op: "contains", Value: "X"}, true},
		{"nested all", rules.Condition{All: []rules.Condition{
			{Field: "src_ip", Op: "exists"}}}, false},
		{"exact in", rules.Condition{Field: "event", Op: "in",
			Values: []any{"A"}}, false},
		{"other field", rules.Condition{Field: "dst_port", Op: "exists"}, false},
	}
	for _, c := range cases {
		if _, ok := editableEventFilter(c.when); ok != c.ok {
			t.Errorf("%s: editable = %v, want %v", c.name, ok, c.ok)
		}
	}
}

// TestRulesEditorEditKeepsConditions is the regression test for the data loss
// where editing any field rebuilt the rule from the form, dropping a nested
// when tree and suppress_by. Every default rule must survive a rate edit with
// its condition byte-identical.
func TestRulesEditorEditKeepsConditions(t *testing.T) {
	path := seedRulesFile(t)
	e := newRulesEditor(path, nil)
	e.open()

	original := make([]rules.Rule, len(e.rf.Rules))
	copy(original, e.rf.Rules)
	// Remember which conditions the form may rewrite; those are normalized to
	// the form's own shape, so only their meaning is compared.
	editable := make([]bool, len(original))
	for i, r := range original {
		_, editable[i] = editableEventFilter(r.When)
	}

	for i := range e.rf.Rules {
		name := e.rf.Rules[i].Name
		e.startEdit(i)
		setForm(e.form, "rate", "1.5")
		e.applyForm()
		if e.rf.Rules[i].Name != name {
			t.Fatalf("rule %d renamed to %q", i, e.rf.Rules[i].Name)
		}
	}

	for i, want := range original {
		got := e.rf.Rules[i]
		if editable[i] {
			wantVals, _ := editableEventFilter(want.When)
			gotVals, ok := editableEventFilter(got.When)
			if !ok || !reflect.DeepEqual(gotVals, wantVals) {
				t.Errorf("%s: filter changed\n got: %v\nwant: %v", want.Name, gotVals, wantVals)
			}
		} else if !reflect.DeepEqual(got.When, want.When) {
			t.Errorf("%s: when changed\n got: %+v\nwant: %+v", want.Name, got.When, want.When)
		}
		if !reflect.DeepEqual(got.SuppressBy, want.SuppressBy) {
			t.Errorf("%s: suppress_by changed\n got: %v\nwant: %v", want.Name, got.SuppressBy, want.SuppressBy)
		}
		if got.Rate != 1.5 {
			t.Errorf("%s: rate = %v, want 1.5", want.Name, got.Rate)
		}
		if !reflect.DeepEqual(got.GroupBy, want.GroupBy) {
			t.Errorf("%s: group_by changed\n got: %v\nwant: %v", want.Name, got.GroupBy, want.GroupBy)
		}
	}

	// The file must still validate after the edit pass.
	e.save()
	if e.errText != "" {
		t.Fatalf("save failed: %s", e.errText)
	}
}

// TestRulesEditorLockedConditionIsReadOnly checks a rule the form cannot
// express shows its condition as a non-editable field, and that the form
// offers no event_contains field that would overwrite it.
func TestRulesEditorLockedConditionIsReadOnly(t *testing.T) {
	path := seedRulesFile(t)
	e := newRulesEditor(path, nil)
	e.open()

	idx := ruleIndex(t, e, "BRUTE_FORCE")
	e.startEdit(idx)
	if !e.whenLocked {
		t.Fatal("BRUTE_FORCE condition should be locked")
	}
	if fieldByLabel(e.form, "event_contains") != nil {
		t.Fatal("locked rule must not expose an editable event_contains field")
	}
	when := fieldByLabel(e.form, "when")
	if when == nil {
		t.Fatal("locked rule should show a read-only when field")
	}
	if when.kind != kindInfo {
		t.Fatalf("when field kind = %v, want kindInfo", when.kind)
	}
	if !strings.Contains(when.value, "event") {
		t.Fatalf("when field does not describe the condition: %q", when.value)
	}
}

// TestRulesEditorSuppressByIsShown checks the preserved field is visible, so
// an operator is not surprised that it cannot be edited here.
func TestRulesEditorSuppressByIsShown(t *testing.T) {
	path := seedRulesFile(t)
	e := newRulesEditor(path, nil)
	e.open()

	e.startEdit(ruleIndex(t, e, "DEAUTH_STORM"))
	sb := fieldByLabel(e.form, "suppress_by")
	if sb == nil || sb.kind != kindInfo || sb.value != "BRUTE_FORCE" {
		t.Fatalf("suppress_by field = %+v, want read-only BRUTE_FORCE", sb)
	}
}

// TestRulesEditorEventFilterEditable checks a simple event filter is prefilled
// and can be rewritten through the form.
func TestRulesEditorEventFilterEditable(t *testing.T) {
	path := seedRulesFile(t)
	e := newRulesEditor(path, nil)
	e.open()

	idx := ruleIndex(t, e, "DEAUTH_STORM")
	e.startEdit(idx)
	if e.whenLocked {
		t.Fatal("a single event contains filter should stay editable")
	}
	f := fieldByLabel(e.form, "event_contains")
	if f == nil || f.value != "DEAUTH" {
		t.Fatalf("event_contains = %+v, want prefilled DEAUTH", f)
	}

	setForm(e.form, "event_contains", "DEAUTH, DISASSOC")
	e.applyForm()
	got := e.rf.Rules[idx].When
	if got.Field != "event" || got.Op != "contains_any" || len(got.Values) != 2 {
		t.Fatalf("when = %+v, want event contains_any with two values", got)
	}

	// Clearing the field means "all rows".
	e.startEdit(idx)
	setForm(e.form, "event_contains", "")
	e.applyForm()
	if !reflect.DeepEqual(e.rf.Rules[idx].When, rules.Condition{}) {
		t.Fatalf("cleared filter left %+v", e.rf.Rules[idx].When)
	}
}

// TestRulesListShowsMatches checks the list surfaces what each rule matches.
func TestRulesListShowsMatches(t *testing.T) {
	path := seedRulesFile(t)
	e := newRulesEditor(path, nil)
	e.open()

	out := e.view(140, 30)
	for _, want := range []string{"MATCHES", "src_ip exists", "BRUTE|AUTH_F"} {
		if !strings.Contains(out, want) {
			t.Errorf("rules list missing %q:\n%s", want, out)
		}
	}
}

func ruleIndex(t *testing.T, e *rulesEditor, name string) int {
	t.Helper()
	for i := range e.rf.Rules {
		if e.rf.Rules[i].Name == name {
			return i
		}
	}
	t.Fatalf("rule %q not found", name)
	return -1
}

func fieldByLabel(f *form, label string) *formField {
	for i := range f.fields {
		if f.fields[i].label == label {
			return &f.fields[i]
		}
	}
	return nil
}
