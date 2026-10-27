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
	eventContains := ""
	if r.When.Field == "event" && r.When.Op == "contains_any" {
		parts := make([]string, 0, len(r.When.Values))
		for _, v := range r.When.Values {
			parts = append(parts, fmt.Sprint(v))
		}
		eventContains = strings.Join(parts, ", ")
	}

	f := newForm("Rule: "+r.Name, []formField{
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
		{label: "event_contains", kind: kindList, value: eventContains,
			help: "case-insensitive substrings, any match; empty = all rows"},
		{label: "cooldown_seconds", kind: kindInt, value: intOrEmpty(r.CooldownSeconds)},
		{label: "description", kind: kindText, value: r.Description,
			help: "supports {entity} {count} {window}"},
	})
	return f
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
func (e *rulesEditor) applyForm() {
	v := e.form.values()
	r := rules.Rule{
		Name:            strings.TrimSpace(v["name"]),
		Severity:        v["severity"],
		Description:     v["description"],
		Rate:            e.form.floatValue("rate", 0),
		MinCount:        e.form.intValue("min_count", 0),
		DistinctOn:      strings.TrimSpace(v["distinct_on"]),
		CooldownSeconds: e.form.intValue("cooldown_seconds", 0),
	}
	on := v["enabled"] != "off"
	r.Enabled = &on
	if v["count"] == "distinct" {
		r.Count = "distinct"
	}
	if g := strings.TrimSpace(v["group_by"]); g != "" && g != "(none)" {
		for _, part := range strings.Split(g, ",") {
			if p := strings.TrimSpace(part); p != "" {
				r.GroupBy = append(r.GroupBy, p)
			}
		}
	}
	if ev := strings.TrimSpace(v["event_contains"]); ev != "" {
		var vals []any
		for _, part := range strings.Split(ev, ",") {
			if p := strings.TrimSpace(part); p != "" {
				vals = append(vals, p)
			}
		}
		r.When = rules.Condition{Field: "event", Op: "contains_any", Values: vals}
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
	b.WriteString(styleTitle.Render("RULES") + styleDim.Render("  config/rules.yaml — edits apply live after save"))
	b.WriteByte('\n')
	b.WriteString(styleDim.Render("a add · e edit · space toggle · x delete · p preview · s save · esc back"))
	b.WriteByte('\n')

	headers := []string{"", "NAME", "SEV", "RATE", "GROUP", "COUNT"}
	widths := []int{2, 20, 9, 8, 22, 8}
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
		line := renderRow([]string{on, r.Name, r.Severity, trimFloat(r.Rate), group, count}, widths, false)
		if i == e.cursor {
			line = styleSelected.Render(padWidth(on+"  "+r.Name, 22)) +
				"  " + padWidth(r.Severity, widths[2]) + "  " +
				padWidth(trimFloat(r.Rate), widths[3]) + "  " +
				padWidth(group, widths[4]) + "  " + count
		}
		rows = append(rows, line)
	}
	if len(rows) == 0 {
		rows = []string{styleDim.Render("no rules — press a to add one")}
	}

	tableHeight := height - 8
	if tableHeight < 4 {
		tableHeight = 4
	}
	body, off := renderTable(headers, widths, rows, e.offset, tableHeight)
	e.offset = off

	b.WriteString(styleBorder.Width(width - 2).Render(body))
	b.WriteByte('\n')
	b.WriteString(e.statusLine())
	return b.String()
}

func (e *rulesEditor) viewPreview(width int) string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("RULE PREVIEW"))
	b.WriteByte('\n')
	for _, line := range e.preview {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString("\n" + styleDim.Render("esc to return"))
	return styleBorder.Padding(1, 2).Width(minInt(width-4, 100)).Render(b.String())
}

func (e *rulesEditor) statusLine() string {
	switch {
	case e.errText != "":
		return styleError.Render("error: " + truncateWidth(e.errText, 100))
	case e.status != "":
		return styleAccent.Render(e.status)
	default:
		return styleDim.Render("changes are not written until you press s")
	}
}

// Compile-time guard: the editor must satisfy nothing but is kept referenced.
var _ = lipgloss.NewStyle
