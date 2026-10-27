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
	viewOverview
	viewDetail
	viewExportConfirm
)

// dataMsg carries a completed refresh.
type dataMsg struct {
	logs      []*store.LogEntry
	anomalies []store.AnomalyRow
	stats     store.Stats
	err       error
}

// overviewMsg carries security overview data.
type overviewMsg struct {
	sources []store.SourceCount
	types   []store.TypeCount
	err     error
}

// exportMsg carries the result of writing CSV files.
type exportMsg struct {
	res ExportResult
	err error
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

	logs      []*store.LogEntry
	anomalies []store.AnomalyRow
	stats     store.Stats
	lastErr   error
	updated   time.Time

	logOffset  int // selected row
	anomOffset int // selected row
	logTop     int // first visible log row
	anomTop    int // first visible anomaly row
	// focusLogs selects which pane the arrow keys scroll.
	focusLogs bool

	overview   []string
	exportDir  string
	exportWarn string

	detail        *detailModal
	rulesEditor   *rulesEditor
	parsersEditor *parsersEditor
}

// Options configure the dashboard.
type Options struct {
	Store *store.Store
	// RulesPath and ParsersPath let the editors write config files.
	RulesPath   string
	ParsersPath string
	// ExportDir is where CSV exports are written.
	ExportDir string
}

// New builds the dashboard model.
func New(opts Options) *Model {
	m := &Model{
		store:     opts.Store,
		search:    newSearchInput(),
		focusLogs: true,
		view:      viewDashboard,
		exportDir: opts.ExportDir,
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

// loadOverview fetches the security overview panels.
func (m *Model) loadOverview() tea.Cmd {
	st := m.store
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sources, err := st.TopSources(ctx, 10)
		if err != nil {
			return overviewMsg{err: err}
		}
		types, err := st.DetectionBreakdown(ctx)
		if err != nil {
			return overviewMsg{err: err}
		}
		return overviewMsg{sources: sources, types: types}
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

	case overviewMsg:
		if msg.err != nil {
			m.lastErr = msg.err
			return m, nil
		}
		m.overview = renderOverview(msg.sources, msg.types)
		return m, nil

	case exportMsg:
		if msg.err != nil {
			m.notify = "export failed: " + msg.err.Error()
			return m, nil
		}
		m.notify = fmt.Sprintf("exported %d logs + %d anomalies to %s",
			msg.res.LogRows, msg.res.AnomalyRows, shortenPath(msg.res.LogPath))
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
	switch m.view {
	case viewRules:
		return m, m.rulesEditor.update(msg)
	case viewParsers:
		return m, m.parsersEditor.update(msg)
	case viewDetail:
		return m, m.handleDetailKey(msg)
	case viewExportConfirm:
		return m, m.handleExportKey(msg)
	case viewOverview:
		switch msg.String() {
		case "esc", "b", "o":
			m.view = viewDashboard
		case "r":
			return m, m.loadOverview()
		}
		return m, nil
	}

	if m.searching {
		switch msg.String() {
		case "esc", "enter":
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
	case "enter":
		return m, m.openDetail()
	case "g":
		if m.focusLogs {
			m.logOffset, m.logTop = 0, 0
		} else {
			m.anomOffset, m.anomTop = 0, 0
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
	case "o":
		m.view = viewOverview
		m.overview = []string{styleDim.Render("loading…")}
		return m, m.loadOverview()
	case "e":
		m.view = viewExportConfirm
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

// openDetail shows the row under the cursor.
func (m *Model) openDetail() tea.Cmd {
	if m.focusLogs {
		if m.logOffset < 0 || m.logOffset >= len(m.logs) {
			return nil
		}
		d := newLogDetail(m.logs[m.logOffset])
		d.setRaw(m.logs[m.logOffset].RawLine)
		m.detail = d
	} else {
		if m.anomOffset < 0 || m.anomOffset >= len(m.anomalies) {
			return nil
		}
		a := m.anomalies[m.anomOffset]
		d := newAnomalyDetail(a)
		d.setRaw(a.Features)
		m.detail = d
	}
	m.view = viewDetail
	return nil
}

func (m *Model) handleDetailKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "enter", "q":
		m.view = viewDashboard
		m.detail = nil
	case "up", "k":
		m.detail.scroll(-1)
	case "down", "j":
		m.detail.scroll(1)
	case "pgup":
		m.detail.scroll(-10)
	case "pgdown":
		m.detail.scroll(10)
	}
	return nil
}

// handleExportKey confirms or cancels the CSV export.
func (m *Model) handleExportKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "n", "q":
		m.view = viewDashboard
		m.notify = "export cancelled"
	case "enter", "y":
		m.view = viewDashboard
		logs, anomalies, dir := m.logs, m.anomalies, m.exportDir
		return func() tea.Msg {
			res, err := Export(dir, logs, anomalies, time.Now())
			return exportMsg{res: res, err: err}
		}
	}
	return nil
}

// scroll moves the focused pane.
func (m *Model) scroll(delta int) {
	if m.focusLogs {
		m.logOffset += delta
		if m.logOffset < 0 {
			m.logOffset = 0
		}
		if max := len(m.logs) - 1; m.logOffset > max && max >= 0 {
			m.logOffset = max
		}
	} else {
		m.anomOffset += delta
		if m.anomOffset < 0 {
			m.anomOffset = 0
		}
		if max := len(m.anomalies) - 1; m.anomOffset > max && max >= 0 {
			m.anomOffset = max
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
	case viewDetail:
		if m.detail != nil {
			return "\n" + m.detail.view(m.width, m.height)
		}
	case viewExportConfirm:
		return m.viewExportConfirm()
	case viewOverview:
		return m.viewOverview()
	case viewHelp:
		return m.viewHelp()
	}
	return m.viewDashboard()
}

func (m *Model) viewExportConfirm() string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("EXPORT CSV"))
	b.WriteByte('\n')
	b.WriteString(styleDim.Render("Writes two files; no existing file is overwritten."))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("  logs:      %d rows\n", len(m.logs)))
	b.WriteString(fmt.Sprintf("  anomalies: %d rows\n", len(m.anomalies)))
	b.WriteString(fmt.Sprintf("  directory: %s\n", orDash(m.exportDir)))
	b.WriteString("\n" + styleDim.Render("enter / y confirm · esc cancel"))
	return styleBorder.Padding(1, 2).Width(minInt(m.width-6, 70)).Render(b.String())
}

func (m *Model) viewOverview() string {
	header := styleTitle.Render("SECURITY OVERVIEW") + styleDim.Render("  r refresh · esc back")
	body := strings.Join(m.overview, "\n")
	if body == "" {
		body = styleDim.Render("loading…")
	}
	return "\n" + header + "\n\n" + body
}

// renderOverview formats the overview panels.
func renderOverview(sources []store.SourceCount, types []store.TypeCount) []string {
	var out []string

	out = append(out, styleAccent.Render("Top detection sources"))
	if len(sources) == 0 {
		out = append(out, styleDim.Render("  none recorded"))
	}
	maxCount := 0
	for _, s := range sources {
		if s.Count > maxCount {
			maxCount = s.Count
		}
	}
	for _, s := range sources {
		bar := strings.Repeat("█", barWidth(s.Count, maxCount, 24))
		out = append(out, fmt.Sprintf("  %-22s %4d  %s",
			truncateWidth(orDash(s.Source), 22), s.Count, styleAccent.Render(bar)))
	}

	out = append(out, "", styleAccent.Render("Detections by type"))
	if len(types) == 0 {
		out = append(out, styleDim.Render("  none recorded"))
	}
	maxType := 0
	for _, t := range types {
		if t.Count > maxType {
			maxType = t.Count
		}
	}
	for _, t := range types {
		bar := strings.Repeat("█", barWidth(t.Count, maxType, 24))
		out = append(out, fmt.Sprintf("  %-22s %4d  %s",
			truncateWidth(t.Type, 22), t.Count, styleAccent.Render(bar)))
	}
	return out
}

// barWidth scales count against max into at most width cells.
func barWidth(count, max, width int) int {
	if max <= 0 || count <= 0 {
		return 0
	}
	w := count * width / max
	if w < 1 {
		w = 1
	}
	return w
}

func shortenPath(p string) string {
	if len(p) <= 48 {
		return p
	}
	return "…" + p[len(p)-47:]
}

var _ = lipgloss.NewStyle

// newSearchInput builds the filter box.
func newSearchInput() textinput.Model {
	ti := textinput.New()
	ti.Placeholder = "filter host / event / ip / mac"
	ti.CharLimit = 64
	ti.Prompt = "/ "
	return ti
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
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

	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		m.viewLogs(logWidth, tableHeight), "  ", m.viewAnomalies(anomWidth, tableHeight)))
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
	wide := width > 90
	widths := []int{8, 14, 9, 15, 7, 6}
	headers := []string{"TIME", "HOST", "DEVICE", "EVENT", "SRC", "PORT"}
	if wide {
		widths = []int{8, 20, 10, 17, 16, 16, 6, 6}
		headers = []string{"TIME", "HOST", "DEVICE", "EVENT", "SRC", "DST", "PROTO", "PORT"}
	}

	rows := make([]string, 0, len(m.logs))
	for i, r := range m.logs {
		src := ""
		if r.SrcIP != nil {
			src = *r.SrcIP
		}
		dst := ""
		if r.DstIP != nil {
			dst = *r.DstIP
		}
		port := "—"
		if r.DstPort != nil {
			port = fmt.Sprint(*r.DstPort)
		}
		var line string
		if wide {
			line = renderRow([]string{
				r.Timestamp.Format("15:04:05"), r.Hostname, r.DeviceType, r.Event,
				src, dst, r.Proto, port,
			}, widths, false)
		} else {
			line = renderRow([]string{
				r.Timestamp.Format("15:04:05"), r.Hostname, r.DeviceType, r.Event,
				src, port,
			}, widths, false)
		}
		if i == m.logOffset {
			line = styleSelected.Render(strings.TrimRight(line, " "))
		}
		rows = append(rows, line)
	}
	if len(rows) == 0 {
		rows = []string{styleDim.Render("no log rows match")}
	}

	title := " LOG STREAM "
	if m.focusLogs {
		title = styleTitle.Render(" LOG STREAM ")
	}
	// Keep the selection visible without moving it.
	if m.logOffset < m.logTop {
		m.logTop = m.logOffset
	}
	if m.logOffset >= m.logTop+height {
		m.logTop = m.logOffset - height + 1
	}
	body, off := renderTable(headers, widths, rows, m.logTop, height)
	m.logTop = off

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
	for i, a := range m.anomalies {
		sev := severityStyle(a.Severity).Render(padWidth(a.Severity, widths[1]))
		desc := strings.TrimPrefix(a.Description, "[RULE] ")
		if a.RepeatCount > 1 {
			desc = fmt.Sprintf("%s (x%d)", desc, a.RepeatCount)
		}
		line := padWidth(a.Timestamp.Format("15:04:05"), widths[0]) + "  " +
			sev + "  " + padWidth(desc, widths[2])
		if i == m.anomOffset {
			line = styleSelected.Render(strings.TrimRight(line, " "))
		}
		rows = append(rows, line)
	}
	if len(rows) == 0 {
		rows = []string{styleDim.Render("no detections")}
	}

	title := " ANOMALIES "
	if !m.focusLogs {
		title = styleTitle.Render(" ANOMALIES ")
	}
	if m.anomOffset < m.anomTop {
		m.anomTop = m.anomOffset
	}
	if m.anomOffset >= m.anomTop+height {
		m.anomTop = m.anomOffset - height + 1
	}
	body, off := renderTable(headers, widths, rows, m.anomTop, height)
	m.anomTop = off

	inner := lipgloss.NewStyle().Width(width).Height(height + 1).Render(body)
	return styleBorder.Width(width).Render(title + "\n" + inner)
}

func (m *Model) viewFooter() string {
	keys := "q quit · p pause · / search · enter detail · o overview · e export · R rules · P parsers · ? help"
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
		"  /            filter (host, event, ip, mac, ssid, ifname)",
		"  esc          clear filter",
		"  ↑ ↓ / j k    move the selection",
		"  tab          switch focus between logs and anomalies",
		"  enter        open the selected row's detail",
		"  o            security overview",
		"  e            export visible rows to CSV",
		"  g            jump to the top of the focused pane",
		"  r            refresh now",
		"",
		styleAccent.Render("Configuration (live, no restart)"),
		"  R            rules editor",
		"  P            parser editor",
		"",
		styleAccent.Render("Rules editor"),
		"  a add · e edit · space toggle · x delete · p preview · s save · esc back",
		"",
		styleAccent.Render("Parser editor"),
		"  n new device · a add field · i assign keyword · s save · esc back",
		"",
		styleDim.Render("Press b or ? to return to the dashboard."),
	}
	box := styleBorder.Padding(1, 2).Render(strings.Join(lines, "\n"))
	return "\n" + box
}
