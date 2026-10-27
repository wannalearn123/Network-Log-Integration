package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
)

// Style shortcuts.
var (
	styleAccent   = lipgloss.NewStyle().Foreground(ColorAccent).Bold(true)
	styleDim      = lipgloss.NewStyle().Foreground(ColorDim)
	styleTitle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff")).Bold(true)
	styleSelected = lipgloss.NewStyle().Background(lipgloss.Color("#1f2a4a")).Foreground(lipgloss.Color("#ffffff"))
	styleBorder   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(ColorDim)
	styleHelp     = lipgloss.NewStyle().Foreground(ColorDim)
	styleError    = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff5555")).Bold(true)
	styleOK       = lipgloss.NewStyle().Foreground(lipgloss.Color("#50fa7b"))
)

// severityStyle colours a severity label.
func severityStyle(sev string) lipgloss.Style {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#ff5555")).Bold(true)
	case "HIGH":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#ffb86c")).Bold(true)
	case "MEDIUM":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#f1fa8c"))
	case "LOW":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#8be9fd"))
	default:
		return styleDim
	}
}

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

// renderRow renders a fixed-width row, applying the selected style when bold.
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

// renderTable draws a header plus a scrolling window of rows.
//
// offset is the index of the first visible row; maxRows is the viewport
// height. It returns the rendered block, the visible offset and the number of
// rows drawn.
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
	b.WriteString(styleAccent.Render(renderRow(headers, widths, false)))
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
