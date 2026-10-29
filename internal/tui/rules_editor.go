package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"siskamlan/internal/config"
	"siskamlan/internal/parser"
	"siskamlan/internal/pipeline"
	"siskamlan/internal/rules"
	"siskamlan/internal/store"
)

// rulesEditor lists and edits config/rules.yaml.
type rulesEditor struct {
	file  *config.File[rules.RulesFile]
	store *store.Store

	rf      rules.RulesFile
	cursor  int
	offset  int
	status  string
	errText string

	mode    editorMode
	form    *form
	editIdx int

	// whenLocked is set when the rule's condition is a nested tree the form
	// cannot express. It is then shown read-only and preserved verbatim.
	whenLocked bool

	preview []string
}

type editorMode int

const (
	modeList editorMode = iota
	modeForm
	modePreview
)

func newRulesEditor(path string, store *store.Store) *rulesEditor {
	f := config.NewFile[rules.RulesFile](path)
	f.Decode = rules.Decode
	f.Validate = rules.Validate
	return &rulesEditor{file: f, store: store}
}

// open reloads the file and shows the list.
func (e *rulesEditor) open() {
	if err := e.file.Load(); err != nil {
		e.errText = err.Error()
		return
	}
	e.refreshFromFile()
	e.mode = modeList
	e.status = ""
	e.preview = nil
}

func (e *rulesEditor) refreshFromFile() {
	if rf, ok := e.file.Current(); ok {
		e.rf = rf
	}
	if e.cursor >= len(e.rf.Rules) {
		e.cursor = maxInt(0, len(e.rf.Rules)-1)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// update processes keys and returns an optional command.
func (e *rulesEditor) update(msg tea.KeyMsg) tea.Cmd {
	switch e.mode {
	case modeForm:
		return e.updateForm(msg)
	case modePreview:
		switch msg.String() {
		case "esc", "enter", "b":
			e.mode = modeList
		}
		return nil
	}
	return e.updateList(msg)
}

func (e *rulesEditor) updateList(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "b":
		return func() tea.Msg { return closeEditorMsg{} }
	case "up", "k":
		if e.cursor > 0 {
			e.cursor--
		}
	case "down", "j":
		if e.cursor < len(e.rf.Rules)-1 {
			e.cursor++
		}
	case " ":
		if e.cursor < len(e.rf.Rules) {
			r := &e.rf.Rules[e.cursor]
			on := !r.IsEnabled()
			r.Enabled = &on
			e.status = "toggled (unsaved)"
		}
	case "a":
		e.startAdd()
	case "e", "enter":
		if e.cursor < len(e.rf.Rules) {
			e.startEdit(e.cursor)
		}
	case "x":
		if e.cursor < len(e.rf.Rules) {
			name := e.rf.Rules[e.cursor].Name
			e.rf.Rules = append(e.rf.Rules[:e.cursor], e.rf.Rules[e.cursor+1:]...)
			e.status = "deleted " + name + " (unsaved)"
			if e.cursor >= len(e.rf.Rules) {
				e.cursor = maxInt(0, len(e.rf.Rules)-1)
			}
		}
	case "p":
		if e.cursor < len(e.rf.Rules) {
			e.runPreview(e.rf.Rules[e.cursor])
		}
	case "s":
		e.save()
	}
	return nil
}

// closeEditorMsg asks the app to return to the dashboard.
type closeEditorMsg struct{}

// startAdd opens the form for a new rule with defaults.
func (e *rulesEditor) startAdd() {
	e.editIdx = -1
	r := rules.Rule{Name: "NEW_RULE", Severity: "MEDIUM", Rate: 0.4}
	e.form = e.ruleForm(r)
	e.mode = modeForm
}

// startEdit opens the form for an existing rule.
func (e *rulesEditor) startEdit(idx int) {
	e.editIdx = idx
	e.form = e.ruleForm(e.rf.Rules[idx])
	e.mode = modeForm
}

// ruleForm builds the edit form for a rule.
//
// Only the fields listed here are editable. Anything else on the rule (a
// nested when tree, suppress_by) is shown read-only and carried through
// untouched by applyForm, so editing a rate cannot silently widen a rule.
func (e *rulesEditor) ruleForm(r rules.Rule) *form {
	enabled := "on"
	if !r.IsEnabled() {
		enabled = "off"
	}
	count := r.Count
	if count == "" {
		count = "rows"
	}
	groupBy := strings.Join(r.GroupBy, ", ")
	if groupBy == "" {
		groupBy = "(none)"
	}

	fields := []formField{
		{label: "name", kind: kindText, value: r.Name},
		{label: "enabled", kind: kindEnum, value: enabled, options: []string{"on", "off"}},
		{label: "severity", kind: kindEnum, value: orDefault(r.Severity, "MEDIUM"),
			options: rules.Severities},
		{label: "rate", kind: kindText, value: trimFloat(r.Rate),
			help: "events per second; 30s window: rate*30"},
		{label: "min_count", kind: kindInt, value: intOrEmpty(r.MinCount)},
		{label: "group_by", kind: kindText, value: groupBy,
			help: "columns comma-separated; use $identity or $mac"},
		{label: "count", kind: kindEnum, value: count, options: []string{"rows", "distinct"}},
		{label: "distinct_on", kind: kindText, value: orDefault(r.DistinctOn, ""),
			help: "required when count=distinct"},
	}

	if vals, ok := editableEventFilter(r.When); ok {
		e.whenLocked = false
		fields = append(fields, formField{label: "event_contains", kind: kindList,
			value: strings.Join(vals, ", "),
			help:  "case-insensitive substrings on the event column, any match; empty = all rows"})
	} else {
		e.whenLocked = true
		fields = append(fields, formField{label: "when", kind: kindInfo,
			value: describeCondition(r.When),
			help:  "nested condition — kept as-is; edit config/rules.yaml to change it"})
	}

	if len(r.SuppressBy) > 0 {
		fields = append(fields, formField{label: "suppress_by", kind: kindInfo,
			value: strings.Join(r.SuppressBy, ", "),
			help:  "kept as-is; edit config/rules.yaml to change it"})
	}

	fields = append(fields,
		formField{label: "cooldown_seconds", kind: kindInt, value: intOrEmpty(r.CooldownSeconds)},
		formField{label: "description", kind: kindText, value: r.Description,
			help: "supports {entity} {count} {window}"},
	)
	return newForm("Rule: "+r.Name, fields)
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func trimFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func intOrEmpty(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// updateForm handles form keys and applies the result on save.
func (e *rulesEditor) updateForm(msg tea.KeyMsg) tea.Cmd {
	done, cancel := e.form.update(msg)
	if cancel {
		e.mode = modeList
		e.form = nil
		return nil
	}
	if done {
		e.applyForm()
	}
	return nil
}

// applyForm converts the form back into a rule and stores it.
//
// When editing, it starts from the rule already in memory and overwrites only
// the fields the form owns. That keeps suppress_by and any nested when tree
// intact — rebuilding the rule from the form alone would drop them and turn a
// narrow rule into one that matches every row.
func (e *rulesEditor) applyForm() {
	v := e.form.values()
	var r rules.Rule
	if e.editIdx >= 0 && e.editIdx < len(e.rf.Rules) {
		r = e.rf.Rules[e.editIdx]
	}

	r.Name = strings.TrimSpace(v["name"])
	r.Severity = v["severity"]
	r.Description = v["description"]
	r.Rate = e.form.floatValue("rate", 0)
	r.MinCount = e.form.intValue("min_count", 0)
	r.DistinctOn = strings.TrimSpace(v["distinct_on"])
	r.CooldownSeconds = e.form.intValue("cooldown_seconds", 0)
	on := v["enabled"] != "off"
	r.Enabled = &on

	r.Count = ""
	if v["count"] == "distinct" {
		r.Count = "distinct"
	}

	r.GroupBy = nil
	if g := strings.TrimSpace(v["group_by"]); g != "" && g != "(none)" {
		for _, part := range strings.Split(g, ",") {
			if p := strings.TrimSpace(part); p != "" {
				r.GroupBy = append(r.GroupBy, p)
			}
		}
	}

	// A locked condition was never editable, so it is carried through as-is.
	if !e.whenLocked {
		r.When = rules.Condition{}
		if ev := strings.TrimSpace(v["event_contains"]); ev != "" {
			var vals []any
			for _, part := range strings.Split(ev, ",") {
				if p := strings.TrimSpace(part); p != "" {
					vals = append(vals, p)
				}
			}
			if len(vals) > 0 {
				r.When = rules.Condition{Field: "event", Op: "contains_any", Values: vals}
			}
		}
	}

	if r.Description == "" {
		r.Description = r.Name + " — {count} in {window}s"
	}

	if e.editIdx >= 0 && e.editIdx < len(e.rf.Rules) {
		e.rf.Rules[e.editIdx] = r
		e.status = "edited " + r.Name + " (unsaved)"
	} else {
		e.rf.Rules = append(e.rf.Rules, r)
		e.cursor = len(e.rf.Rules) - 1
		e.status = "added " + r.Name + " (unsaved)"
	}
	e.mode = modeList
	e.form = nil
	e.whenLocked = false
}

// save validates and writes the file.
func (e *rulesEditor) save() {
	if err := e.file.Save(e.rf, rules.Encode); err != nil {
		e.errText = err.Error()
		return
	}
	e.errText = ""
	e.status = "saved — detection reloads within 15s"
}

// runPreview dry-runs a rule against the last five minutes.
func (e *rulesEditor) runPreview(r rules.Rule) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := e.store.QueryWindow(ctx, 300)
	if err != nil {
		e.errText = err.Error()
		return
	}
	entries := make([]*parser.Entry, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, pipeline.EntryFromStore(row))
	}
	single := rules.RulesFile{Version: e.rf.Version, WindowSeconds: 300, Rules: []rules.Rule{
		withEnabled(r, true),
	}}
	hits := rules.Detect(entries, single, 300)

	e.preview = []string{
		fmt.Sprintf("Preview of %q over %d rows (last 5 min)", r.Name, len(entries)),
		fmt.Sprintf("Hits: %d", len(hits)),
	}
	if len(hits) == 0 {
		e.preview = append(e.preview, styleDim.Render("no matches — lower the rate or widen the filter"))
	}
	for i, h := range hits {
		if i >= 20 {
			e.preview = append(e.preview, styleDim.Render("…"))
			break
		}
		e.preview = append(e.preview, fmt.Sprintf("  %s — %s", h.Severity, h.Description))
	}
	e.mode = modePreview
}

func withEnabled(r rules.Rule, on bool) rules.Rule {
	r.Enabled = &on
	return r
}

// view renders the rules screen.
func (e *rulesEditor) view(width, height int) string {
	switch e.mode {
	case modeForm:
		return "\n" + e.form.view(width)
	case modePreview:
		return e.viewPreview(width)
	}
	return e.viewList(width, height)
}

func (e *rulesEditor) viewList(width, height int) string {
	var b strings.Builder
	b.WriteString(truncateWidth(styleBrand.Render("◈ RULES")+
		styleDim.Render("   config/rules.yaml — edits apply live after save"), width-1))
	b.WriteByte('\n')
	hint := "a add · e edit · space toggle · x delete · p preview · s save · esc back"
	if width < 78 {
		hint = "a add · e edit · space on/off · x del · p preview · s save"
	}
	b.WriteString(styleDim.Render(truncateWidth(hint, width-1)))
	b.WriteByte('\n')

	avail := width - 8
	sets := [][]col{
		{{"", 2, false}, {"NAME", 14, true}, {"SEVERITY", 9, false},
			{"RATE", 6, false}, {"GROUP BY", 14, true}, {"COUNT", 8, false},
			{"MATCHES", 18, true}},
		{{"", 2, false}, {"NAME", 14, true}, {"SEVERITY", 9, false},
			{"RATE", 6, false}, {"MATCHES", 20, true}},
		{{"", 2, false}, {"NAME", 14, true}, {"SEVERITY", 9, false},
			{"RATE", 6, false}},
		{{"", 2, false}, {"NAME", 14, true}},
	}
	headers, widths, ok := fitCols(sets, avail)
	if !ok {
		headers = []string{"", "NAME"}
		widths = []int{2, maxIntOf(10, avail-2)}
	}

	rows := make([]string, 0, len(e.rf.Rules))
	for i, r := range e.rf.Rules {
		on := "●"
		if !r.IsEnabled() {
			on = "○"
		}
		group := "(global)"
		if len(r.GroupBy) > 0 {
			group = strings.Join(r.GroupBy, ",")
		}
		count := "rows"
		if r.IsDistinct() {
			count = "distinct"
		}

		// Build cells from the header names so any column set works.
		cells := make([]string, len(headers))
		for j, h := range headers {
			switch h {
			case "":
				cells[j] = on
			case "NAME":
				cells[j] = r.Name
			case "SEVERITY":
				cells[j] = r.Severity
			case "RATE":
				cells[j] = trimFloat(r.Rate)
			case "GROUP BY":
				cells[j] = group
			case "COUNT":
				cells[j] = count
			case "MATCHES":
				cells[j] = matchesSummary(r)
			}
		}

		if i == e.cursor {
			rows = append(rows, styledRow(cells, widths, true))
			continue
		}
		// Colour the on/off marker and the severity, keeping alignment.
		parts := make([]string, len(cells))
		for j, v := range cells {
			switch headers[j] {
			case "":
				parts[j] = cell(v, styleAccentHi, widths[j])
			case "SEVERITY":
				parts[j] = cell(v, severityStyle(r.Severity), widths[j])
			case "RATE":
				parts[j] = cell(v, styleDim, widths[j])
			default:
				parts[j] = cell(v, styleText, widths[j])
			}
		}
		rows = append(rows, strings.TrimRight(strings.Join(parts, "  "), " "))
	}
	if len(rows) == 0 {
		rows = []string{styleDim.Render("no rules — press a to add one")}
	}

	tableHeight := height - 8
	if tableHeight < 4 {
		tableHeight = 4
	}
	viewport := tableHeight - 2
	if viewport < 2 {
		viewport = 2
	}
	if e.cursor < e.offset {
		e.offset = e.cursor
	}
	if e.cursor >= e.offset+viewport {
		e.offset = e.cursor - viewport + 1
	}
	body, off := renderTable(headers, widths, rows, e.offset, viewport)
	e.offset = off

	b.WriteString(panel("", body, width-2, tableHeight+2, true))
	b.WriteByte('\n')
	b.WriteString(e.statusLine(width))
	return b.String()
}

func (e *rulesEditor) viewPreview(width int) string {
	var b strings.Builder
	b.WriteString(styleBrand.Render("◈ RULE PREVIEW"))
	b.WriteByte('\n')
	for _, line := range e.preview {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString("\n" + styleDim.Render("esc to return"))
	return modalBox(b.String(), minInt(width-6, 102))
}

func (e *rulesEditor) statusLine(width int) string {
	switch {
	case e.errText != "":
		return styleError.Render(truncateWidth("error: "+e.errText, width-1))
	case e.status != "":
		return styleAccent.Render(truncateWidth(e.status, width-1))
	default:
		return styleDim.Render(truncateWidth("changes are not written until you press s", width-1))
	}
}

// Compile-time guard: the editor must satisfy nothing but is kept referenced.
var _ = lipgloss.NewStyle
