package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"siskamlan/internal/store"
)

// refreshInterval is how often dashboard data is reloaded.
const refreshInterval = 3 * time.Second

// view identifies which screen is showing.
type view int

const (
	viewDashboard view = iota
	viewRules
	viewParsers
	viewHelp
)

// dataMsg carries a completed refresh.
type dataMsg struct {
	logs      []store.LogRow
	anomalies []store.AnomalyRow
	stats     store.Stats
	err       error
}

// tickMsg triggers a refresh.
type tickMsg time.Time

// Model is the dashboard state.
type Model struct {
	store  *store.Store
	notify string // status line shown under the header

	width, height int
	paused        bool
	search        textinput.Model
	searching     bool

	view view

	logs      []store.LogRow
	anomalies []store.AnomalyRow
	stats     store.Stats
	lastErr   error
	updated   time.Time

	logOffset  int
	anomOffset int
	// focusLogs selects which pane the arrow keys scroll.
	focusLogs bool

	rulesEditor   *rulesEditor
	parsersEditor *parsersEditor
}

// Options configure the dashboard.
type Options struct {
	Store *store.Store
	// RulesPath and ParsersPath let the editors write config files.
	RulesPath   string
	ParsersPath string
}

// newSearchInput builds the filter box.
func newSearchInput() textinput.Model {
	ti := textinput.New()
	ti.Placeholder = "filter host / event / ip / mac"
	ti.CharLimit = 64
	ti.Prompt = "/ "
	return ti
}

// New builds the dashboard model.
func New(opts Options) *Model {
	m := &Model{
		store:     opts.Store,
		search:    newSearchInput(),
		focusLogs: true,
		view:      viewDashboard,
	}
	m.rulesEditor = newRulesEditor(opts.RulesPath, opts.Store)
	m.parsersEditor = newParsersEditor(opts.ParsersPath, opts.Store)
	return m
}

// Init starts the refresh loop.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.refresh(), m.tick())
}

func (m *Model) tick() tea.Cmd {
	return tea.Tick(refreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// refresh loads dashboard data without blocking the UI.
func (m *Model) refresh() tea.Cmd {
	if m.paused {
		return nil
	}
	filter := ""
	if m.searching || m.search.Value() != "" {
		filter = m.search.Value()
	}
	st := m.store
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		logs, err := st.RecentLogs(ctx, 300, filter)
		if err != nil {
			return dataMsg{err: err}
		}
		anoms, err := st.RecentAnomalies(ctx, 200, filter)
		if err != nil {
			return dataMsg{err: err}
		}
		stats, err := st.Stats(ctx)
		if err != nil {
			return dataMsg{err: err}
		}
		return dataMsg{logs: logs, anomalies: anoms, stats: stats}
	}
}

// Update handles all messages.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case dataMsg:
		m.updated = time.Now()
		if msg.err != nil {
			m.lastErr = msg.err
			return m, nil
		}
		m.lastErr = nil
		m.logs = msg.logs
		m.anomalies = msg.anomalies
		m.stats = msg.stats
		return m, nil

	case tickMsg:
		return m, tea.Batch(m.refresh(), m.tick())

	case tea.KeyMsg:
		return m.handleKey(msg)

	case closeEditorMsg:
		m.view = viewDashboard
		return m, m.refresh()
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Modal editors consume keys first.
	if m.view == viewRules {
		return m, m.rulesEditor.update(msg)
	}
	if m.view == viewParsers {
		return m, m.parsersEditor.update(msg)
	}

	if m.searching {
		switch msg.String() {
		case "esc":
			m.searching = false
			m.search.Blur()
			return m, m.refresh()
		case "enter":
			m.searching = false
			m.search.Blur()
			return m, m.refresh()
		}
		var cmd tea.Cmd
		m.search, cmd = m.search.Update(msg)
		return m, cmd
	}

	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "p":
		m.paused = !m.paused
		if m.paused {
			m.notify = "paused"
		} else {
			m.notify = ""
			return m, m.refresh()
		}
	case "/":
		m.searching = true
		m.search.Focus()
		return m, textinput.Blink
	case "esc":
		if m.search.Value() != "" {
			m.search.SetValue("")
			return m, m.refresh()
		}
	case "tab":
		m.focusLogs = !m.focusLogs
	case "up", "k":
		m.scroll(-1)
	case "down", "j":
		m.scroll(1)
	case "pgup":
		m.scroll(-10)
	case "pgdown":
		m.scroll(10)
	case "g":
		if m.focusLogs {
			m.logOffset = 0
		} else {
			m.anomOffset = 0
		}
	case "r":
		return m, m.refresh()
	case "R":
		m.view = viewRules
		m.rulesEditor.open()
		return m, nil
	case "P":
		m.view = viewParsers
		m.parsersEditor.open()
		return m, nil
	case "?":
		m.view = viewHelp
	case "b":
		if m.view == viewHelp {
			m.view = viewDashboard
		}
	}
	return m, nil
}

// scroll moves the focused pane.
func (m *Model) scroll(delta int) {
	if m.focusLogs {
		m.logOffset += delta
		if m.logOffset < 0 {
			m.logOffset = 0
		}
	} else {
		m.anomOffset += delta
		if m.anomOffset < 0 {
			m.anomOffset = 0
		}
	}
}

// View renders the active screen.
func (m *Model) View() string {
	switch m.view {
	case viewRules:
		return m.rulesEditor.view(m.width, m.height)
	case viewParsers:
		return m.parsersEditor.view(m.width, m.height)
	case viewHelp:
		return m.viewHelp()
	}
	return m.viewDashboard()
}

func (m *Model) viewDashboard() string {
	if m.width <= 0 {
		m.width = 80
	}
	if m.height <= 0 {
		m.height = 24
	}
	var b strings.Builder

	b.WriteString(m.viewHeader())
	b.WriteByte('\n')
	b.WriteString(m.viewStats())
	b.WriteByte('\n')
	b.WriteString(m.search.View())
	b.WriteByte('\n')

	bodyHeight := m.height - 9
	if bodyHeight < 6 {
		bodyHeight = 6
	}
	tableHeight := bodyHeight - 2

	logWidth := m.width * 3 / 5
	if logWidth < 40 {
		logWidth = 40
	}
	anomWidth := m.width - logWidth - 4
	if anomWidth < 24 {
		anomWidth = 24
	}

	logsPane := m.viewLogs(logWidth, tableHeight)
	anomPane := m.viewAnomalies(anomWidth, tableHeight)
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, logsPane, "  ", anomPane))
	b.WriteString("\n")
	b.WriteString(m.viewFooter())

	return b.String()
}

func (m *Model) viewHeader() string {
	left := styleTitle.Render("SISKAMLAN") + styleDim.Render("  LAN security monitoring")
	state := styleOK.Render("● live")
	if m.paused {
		state = styleDim.Render("❚❚ paused")
	}
	if m.lastErr != nil {
		state = styleError.Render("! " + truncateWidth(m.lastErr.Error(), 50))
	}
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(state)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + state
}

func (m *Model) viewStats() string {
	s := m.stats
	cells := []string{
		fmt.Sprintf("logs %d", s.TotalLogs),
		fmt.Sprintf("1h %d", s.LogsLastHour),
		fmt.Sprintf("devices %d", s.ActiveDevices),
		fmt.Sprintf("anomalies %d", s.TotalAnomalies),
		severityStyle("CRITICAL").Render(fmt.Sprintf("crit %d", s.Critical)),
		severityStyle("HIGH").Render(fmt.Sprintf("high %d", s.High)),
		severityStyle("MEDIUM").Render(fmt.Sprintf("med %d", s.Medium)),
		severityStyle("LOW").Render(fmt.Sprintf("low %d", s.Low)),
	}
	return strings.Join(cells, styleDim.Render("  │  "))
}

func (m *Model) viewLogs(width, height int) string {
	widths := []int{8, 14, 9, 15, 7, 6}
	if width > 90 {
		widths = []int{8, 20, 10, 17, 16, 16, 6, 6}
	}
	headers := []string{"TIME", "HOST", "DEVICE", "EVENT", "SRC", "PORT"}
	if width > 90 {
		headers = []string{"TIME", "HOST", "DEVICE", "EVENT", "SRC", "DST", "PROTO", "PORT"}
	}

	rows := make([]string, 0, len(m.logs))
	for _, r := range m.logs {
		port := "-"
		if r.DstPort != nil {
			port = fmt.Sprint(*r.DstPort)
		}
		if width > 90 {
			rows = append(rows, renderRow([]string{
				r.Timestamp.Format("15:04:05"), r.Hostname, r.DeviceType, r.Event,
				r.SrcIP, r.DstIP, r.Proto, port,
			}, widths, false))
		} else {
			rows = append(rows, renderRow([]string{
				r.Timestamp.Format("15:04:05"), r.Hostname, r.DeviceType, r.Event,
				r.SrcIP, port,
			}, widths, false))
		}
	}
	if len(rows) == 0 {
		rows = []string{styleDim.Render("no log rows match")}
	}

	title := " LOG STREAM "
	if m.focusLogs {
		title = styleTitle.Render(" LOG STREAM ")
	}
	body, off := renderTable(headers, widths, rows, m.logOffset, height)
	m.logOffset = off

	inner := lipgloss.NewStyle().Width(width).Height(height + 1).Render(body)
	return styleBorder.Width(width).Render(title + "\n" + inner)
}

func (m *Model) viewAnomalies(width, height int) string {
	timeW, sevW := 9, 8
	descW := width - timeW - sevW - 8
	if descW < 12 {
		descW = 12
	}
	widths := []int{timeW, sevW, descW}
	headers := []string{"TIME", "SEV", "DETECTION"}

	rows := make([]string, 0, len(m.anomalies))
	for _, a := range m.anomalies {
		desc := strings.TrimPrefix(a.Description, "[RULE] ")
		if a.RepeatCount > 1 {
			desc = fmt.Sprintf("%s (x%d)", desc, a.RepeatCount)
		}
		rows = append(rows, renderRow([]string{
			a.Timestamp.Format("15:04:05"),
			a.Severity,
			truncateWidth(desc, widths[2]),
		}, widths, false))
	}
	if len(rows) == 0 {
		rows = []string{styleDim.Render("no detections")}
	}

	// Colour the severity column by re-rendering per row.
	for i, a := range m.anomalies {
		sev := severityStyle(a.Severity).Render(padWidth(a.Severity, widths[1]))
		desc := strings.TrimPrefix(a.Description, "[RULE] ")
		if a.RepeatCount > 1 {
			desc = fmt.Sprintf("%s (x%d)", desc, a.RepeatCount)
		}
		line := padWidth(a.Timestamp.Format("15:04:05"), widths[0]) + "  " +
			sev + "  " + padWidth(desc, widths[2])
		rows[i] = line
	}

	title := " ANOMALIES "
	if !m.focusLogs {
		title = styleTitle.Render(" ANOMALIES ")
	}
	body, off := renderTable(headers, widths, rows, m.anomOffset, height)
	m.anomOffset = off

	inner := lipgloss.NewStyle().Width(width).Height(height + 1).Render(body)
	return styleBorder.Width(width).Render(title + "\n" + inner)
}

func (m *Model) viewFooter() string {
	keys := "q quit · p pause · / search · ↑↓ scroll · tab focus · R rules · P parsers · ? help"
	if m.notify != "" {
		keys = styleAccent.Render(m.notify) + styleDim.Render(" · ") + keys
	}
	return styleHelp.Render(keys)
}

func (m *Model) viewHelp() string {
	lines := []string{
		styleTitle.Render("SISKAMLAN — keyboard reference"),
		"",
		styleAccent.Render("Dashboard"),
		"  q            quit",
		"  p            pause / resume live refresh",
		"  /            filter (host, event, ip, mac, ssid)",
		"  esc          clear filter",
		"  ↑ ↓ / j k    scroll the focused pane",
		"  tab          switch focus between logs and anomalies",
		"  g            jump to top of the focused pane",
		"  r            refresh now",
		"",
		styleAccent.Render("Configuration (live, no restart)"),
		"  R            rules editor",
		"  P            parser editor",
		"",
		styleAccent.Render("Rules editor"),
		"  a add · e edit · space toggle · x delete · s save · esc close",
		"",
		styleAccent.Render("Parser editor"),
		"  n new device · a add field · i assign keyword · s save · esc close",
		"",
		styleDim.Render("Press b or ? to return to the dashboard."),
	}
	box := styleBorder.Padding(1, 2).Render(strings.Join(lines, "\n"))
	return "\n" + box
}
