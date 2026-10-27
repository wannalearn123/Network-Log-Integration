package tui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/mattn/go-runewidth"
)

// truncateWidth cuts s to at most w display cells, adding an ellipsis.
func truncateWidth(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if runewidth.StringWidth(s) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}
	out := make([]rune, 0, w)
	width := 0
	for _, r := range s {
		rw := runewidth.RuneWidth(r)
		if width+rw > w-1 {
			break
		}
		out = append(out, r)
		width += rw
	}
	return string(out) + "…"
}

// padWidth right-pads s to exactly w display cells (truncating if needed).
func padWidth(s string, w int) string {
	s = truncateWidth(s, w)
	gap := w - runewidth.StringWidth(s)
	if gap < 0 {
		gap = 0
	}
	return s + strings.Repeat(" ", gap)
}

// minInt returns the smaller of two ints.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// maxIntOf returns the larger of two ints.
func maxIntOf(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// commas renders an integer with thousands separators (12,480).
func commas(n int) string {
	neg := n < 0
	if neg {
		n = -n
	}
	s := strconv.Itoa(n)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// renderRow renders a fixed-width row, applying the selected style when set.
func renderRow(cells []string, widths []int, selected bool) string {
	var b strings.Builder
	for i, cell := range cells {
		w := 0
		if i < len(widths) {
			w = widths[i]
		}
		b.WriteString(padWidth(cell, w))
		if i < len(cells)-1 {
			b.WriteString("  ")
		}
	}
	line := strings.TrimRight(b.String(), " ")
	if selected {
		return styleSelected.Render(line)
	}
	return line
}

// fitColumns shrinks host/event columns so the row fits inside avail cells.
//
// Fixed columns keep their width; the remaining space is shared between the
// text-heavy columns, with a floor so nothing becomes unreadable.
func fitColumns(widths []int, avail int, flexible ...int) []int {
	out := append([]int(nil), widths...)
	total := func() int {
		sum := 0
		for _, w := range out {
			sum += w
		}
		return sum + 2*(len(out)-1) // separators
	}
	// Shrink proportionally until it fits, never below 6 cells.
	for total() > avail {
		shrunk := false
		for _, i := range flexible {
			if i < len(out) && out[i] > 6 {
				out[i]--
				shrunk = true
				if total() <= avail {
					break
				}
			}
		}
		if !shrunk {
			break
		}
	}
	return out
}

// col is a table column with a minimum width; flex columns absorb spare space.
type col struct {
	name string
	w    int
	flex bool
}

// fitCols picks the widest column layout that fits avail cells.
//
// Sets are tried richest first, so a wide terminal gets every column and a
// narrow one degrades gracefully instead of wrapping.
func fitCols(sets [][]col, avail int) (headers []string, widths []int, ok bool) {
	for _, set := range sets {
		sep := 2 * (len(set) - 1)
		base := 0
		for _, c := range set {
			base += c.w
		}
		if base+sep > avail {
			continue
		}
		widths = make([]int, len(set))
		headers = make([]string, len(set))
		for i, c := range set {
			widths[i] = c.w
			headers[i] = c.name
		}
		// Distribute the remainder across flexible columns. If a set has no
		// flexible column the loop must stop, or it would spin forever.
		flex := 0
		for _, c := range set {
			if c.flex {
				flex++
			}
		}
		if extra := avail - base - sep; flex > 0 {
			for i := 0; extra > 0; i = (i + 1) % len(set) {
				if set[i].flex {
					widths[i]++
					extra--
				}
			}
		}
		return headers, widths, true
	}
	return nil, nil, false
}

// rowWidth is the rendered width of a row with these columns.
func rowWidth(widths []int) int {
	w := 2 * (len(widths) - 1)
	for _, c := range widths {
		w += c
	}
	return w
}

// cell pads plain text to w and applies a style.
//
// Padding happens before styling so ANSI escapes never affect the width.
func cell(text string, style lipgloss.Style, w int) string {
	return style.Render(padWidth(text, w))
}

// styledRow joins styled cells with two-space separators.
func styledRow(cells []string, widths []int, selected bool) string {
	parts := make([]string, len(cells))
	for i, c := range cells {
		w := 0
		if i < len(widths) {
			w = widths[i]
		}
		parts[i] = padWidth(c, w)
	}
	line := strings.TrimRight(strings.Join(parts, "  "), " ")
	if selected {
		return styleSelected.Render(line)
	}
	return line
}

// renderTable draws a styled header plus a scrolling window of rows.
//
// offset is the index of the first visible row; maxRows is the viewport
// height. It returns the rendered block and the visible offset.
func renderTable(headers []string, widths []int, rows []string, offset, maxRows int) (string, int) {
	if maxRows < 1 {
		maxRows = 1
	}
	if offset < 0 {
		offset = 0
	}
	maxOffset := len(rows) - maxRows
	if maxOffset < 0 {
		maxOffset = 0
	}
	if offset > maxOffset {
		offset = maxOffset
	}

	var b strings.Builder
	b.WriteString(styleAccentHi.Render(renderRow(headers, widths, false)))
	b.WriteByte('\n')
	b.WriteString(styleDim.Render(rule(rowWidth(widths))))
	b.WriteByte('\n')

	drawn := 0
	for i := offset; i < len(rows) && drawn < maxRows; i++ {
		b.WriteString(rows[i])
		b.WriteByte('\n')
		drawn++
	}
	for drawn < maxRows {
		b.WriteByte('\n')
		drawn++
	}
	return b.String(), offset
}

// rule builds a horizontal divider of the given width.
func rule(width int) string {
	if width < 1 {
		return ""
	}
	return strings.Repeat("─", width)
}

// panel wraps content in a rounded card with a title line.
//
// The focused card uses the brighter accent border, matching the original
// Textual focus behaviour.
func panel(title, content string, width, height int, focused bool) string {
	if width < 8 {
		width = 8
	}
	if height < 3 {
		height = 3
	}
	innerW := width - 4 // border + horizontal padding
	// lipgloss Height() is the content box and the border adds two rows on top,
	// so the rendered panel is innerH+2 rows. Reserve the border here so callers
	// get exactly `height` rows.
	innerH := height - 2

	titleText := styleAccentHi.Render(title)
	if !focused {
		titleText = styleDim.Render(title)
	}
	// renderTable ends with a newline; trim it so the panel is exactly the
	// requested height.
	body := strings.TrimRight(titleText+"\n"+content, "\n")

	st := stylePanel
	if focused {
		st = stylePanelActive
	}
	return st.Width(innerW).Height(innerH).Padding(0, 1).Render(body)
}

// modalBox wraps a modal body with padding and a bright border.
func modalBox(body string, width int) string {
	if width > 100 {
		width = 100
	}
	if width < 40 {
		width = 40
	}
	return stylePanelActive.Width(width-4).Padding(1, 2).Render(body)
}

// centerBlock places a rendered box in the middle of the terminal.
//
// The original Textual modals used `align: center middle`. When the box is
// taller than the terminal it is left top-aligned so the first lines stay
// visible instead of being pushed off screen.
func centerBlock(box string, width, height int) string {
	lines := strings.Split(box, "\n")
	if height <= 0 || len(lines) >= height {
		return box
	}
	top := (height - len(lines)) / 2

	var b strings.Builder
	for i := 0; i < top; i++ {
		b.WriteByte('\n')
	}
	for i, line := range lines {
		pad := (width - lipgloss.Width(line)) / 2
		if pad > 0 {
			b.WriteString(strings.Repeat(" ", pad))
		}
		b.WriteString(line)
		if i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}
