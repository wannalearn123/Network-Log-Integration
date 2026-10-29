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
	kindInfo // displayed only: the editor cannot express this value
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
	title    string
	subtitle string // optional one-line explanation under the title
	fields   []formField
	cursor   int
	editing  bool
	input    textinput.Model
	errText  string
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
		} else if f.fields[f.cursor].kind != kindInfo {
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
	b.WriteString(styleBrand.Render("◈ " + f.title))
	b.WriteByte('\n')
	if f.subtitle != "" {
		b.WriteString(styleDim.Render(f.subtitle))
		b.WriteByte('\n')
	}
	b.WriteString(styleDim.Render("↑↓ field · ←→ cycle · enter edit · ctrl+s save · esc cancel"))
	b.WriteString("\n\n")

	labelWidth := 0
	for _, fld := range f.fields {
		if w := lipgloss.Width(fld.label); w > labelWidth {
			labelWidth = w
		}
	}
	// Values can be long (a description, a nested rule condition), so they wrap
	// inside the modal instead of overflowing it.
	contentW := minInt(width-4, 76) - 8
	valueW := contentW - (2 + labelWidth + 2)
	if valueW < 12 {
		valueW = 12
	}
	indent := strings.Repeat(" ", 2+labelWidth+2)

	for i, fld := range f.fields {
		selected := i == f.cursor
		marker := "  "
		if selected {
			marker = styleAccentHi.Render("▸ ")
		}

		label := padWidth(fld.label, labelWidth)
		if selected {
			label = styleText.Bold(true).Render(label)
		} else {
			label = styleDim.Render(label)
		}

		var lines []string
		switch {
		case selected && f.editing:
			lines = []string{f.input.View()}
		case fld.kind == kindInfo:
			text := fld.value
			if text == "" {
				text = "(none)"
			}
			for _, l := range wrapText(text, valueW) {
				lines = append(lines, styleDim.Render(l))
			}
		case fld.kind == kindEnum:
			if selected {
				lines = []string{styleAccentHi.Render("< " + fld.value + " >")}
			} else {
				lines = []string{styleText.Render("< " + fld.value + " >")}
			}
		case fld.value == "":
			lines = []string{styleDim.Render("(empty)")}
		case selected:
			for _, l := range wrapText(fld.value, valueW) {
				lines = append(lines, styleAccentHi.Render(l))
			}
		default:
			for _, l := range wrapText(fld.value, valueW) {
				lines = append(lines, styleText.Render(l))
			}
		}

		b.WriteString(marker + label + "  " + lines[0])
		b.WriteByte('\n')
		for _, extra := range lines[1:] {
			b.WriteString(indent + extra)
			b.WriteByte('\n')
		}
		if selected && fld.help != "" {
			b.WriteString("    " + styleDim.Render(fld.help))
			b.WriteByte('\n')
		}
	}

	if f.errText != "" {
		b.WriteString("\n" + styleError.Render("! "+f.errText))
		b.WriteByte('\n')
	}
	return modalBox(b.String(), minInt(width-4, 76))
}

// fieldByLabel returns the field with the given label, or nil.
//
// Editors use it to inspect or retarget a single row of a form.
func fieldByLabel(f *form, label string) *formField {
	if f == nil {
		return nil
	}
	for i := range f.fields {
		if f.fields[i].label == label {
			return &f.fields[i]
		}
	}
	return nil
}
