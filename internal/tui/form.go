package tui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type fieldKind int

const (
	kindText fieldKind = iota
	kindInt
	kindEnum
	kindList // comma-separated text
)

type formField struct {
	label   string
	kind    fieldKind
	value   string
	options []string
	help    string
}

// form is a small modal editor used by the rules and parser screens.
type form struct {
	title   string
	fields  []formField
	cursor  int
	editing bool
	input   textinput.Model
	errText string
}

func newForm(title string, fields []formField) *form {
	ti := textinput.New()
	ti.CharLimit = 300
	return &form{title: title, fields: fields, input: ti}
}

// beginEdit starts inline editing of a text/list field.
func (f *form) beginEdit() {
	fld := &f.fields[f.cursor]
	f.editing = true
	f.input.SetValue(fld.value)
	f.input.CursorEnd()
	f.input.Focus()
}

// commitEdit stores the inline edit.
func (f *form) commitEdit() {
	f.fields[f.cursor].value = strings.TrimSpace(f.input.Value())
	f.editing = false
	f.input.Blur()
}

// update processes a key. done is true when the user confirms, cancel when
// they dismiss the form.
func (f *form) update(msg tea.KeyMsg) (done, cancel bool) {
	if f.editing {
		switch msg.String() {
		case "enter":
			f.commitEdit()
			return false, false
		case "esc":
			f.editing = false
			f.input.Blur()
			return false, false
		}
		var cmd tea.Cmd
		f.input, cmd = f.input.Update(msg)
		_ = cmd
		return false, false
	}

	switch msg.String() {
	case "esc":
		return false, true
	case "ctrl+s":
		return true, false
	case "s":
		// Plain "s" confirms unless the cursor sits on a text field the user
		// may want to type into; require ctrl+s there to avoid surprises.
		if f.fields[f.cursor].kind == kindEnum {
			return true, false
		}
		return true, false
	case "up", "k":
		if f.cursor > 0 {
			f.cursor--
		}
	case "down", "j":
		if f.cursor < len(f.fields)-1 {
			f.cursor++
		}
	case "left", "h":
		f.cycle(-1)
	case "right", "l":
		f.cycle(1)
	case " ":
		f.cycle(1)
	case "enter":
		if f.fields[f.cursor].kind == kindEnum {
			f.cycle(1)
		} else {
			f.beginEdit()
		}
	}
	return false, false
}

// cycle changes an enum value.
func (f *form) cycle(delta int) {
	fld := &f.fields[f.cursor]
	if fld.kind != kindEnum || len(fld.options) == 0 {
		return
	}
	idx := 0
	for i, o := range fld.options {
		if o == fld.value {
			idx = i
			break
		}
	}
	idx = (idx + delta + len(fld.options)) % len(fld.options)
	fld.value = fld.options[idx]
}

// values returns the current values by label.
func (f *form) values() map[string]string {
	out := make(map[string]string, len(f.fields))
	for _, fld := range f.fields {
		out[fld.label] = fld.value
	}
	return out
}

// intValue parses a numeric field, returning fallback when unset/invalid.
func (f *form) intValue(label string, fallback int) int {
	if v, ok := f.values()[label]; ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func (f *form) floatValue(label string, fallback float64) float64 {
	if v, ok := f.values()[label]; ok && v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
	}
	return fallback
}

// view renders the form.
func (f *form) view(width int) string {
	var b strings.Builder
	b.WriteString(styleTitle.Render(f.title))
	b.WriteByte('\n')
	b.WriteString(styleDim.Render("↑↓ field · ←→ cycle · enter edit · ctrl+s save · esc cancel"))
	b.WriteByte('\n')
	b.WriteByte('\n')

	labelWidth := 0
	for _, fld := range f.fields {
		if w := lipgloss.Width(fld.label); w > labelWidth {
			labelWidth = w
		}
	}
	for i, fld := range f.fields {
		marker := "  "
		if i == f.cursor {
			marker = styleAccent.Render("▸ ")
		}
		label := padWidth(fld.label, labelWidth)
		val := fld.value
		if fld.kind == kindEnum {
			val = "< " + val + " >"
		}
		if val == "" {
			val = styleDim.Render("(empty)")
		}
		line := marker + styleDim.Render(label) + "  " + val
		if i == f.cursor && f.editing {
			line = marker + styleDim.Render(label) + "  " + f.input.View()
		} else if i == f.cursor {
			line = marker + styleTitle.Render(label) + "  " + val
		}
		b.WriteString(line)
		if fld.help != "" && i == f.cursor {
			b.WriteString("\n    " + styleDim.Render(fld.help))
		}
		b.WriteByte('\n')
	}
	if f.errText != "" {
		b.WriteString("\n" + styleError.Render(f.errText))
		b.WriteByte('\n')
	}
	return styleBorder.Padding(1, 2).Width(minInt(width-4, 72)).Render(b.String())
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
