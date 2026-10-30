package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"siskamlan/internal/store"
	"siskamlan/internal/telegramauth"
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
	viewTelegram
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

// notifyTTL is how long a transient status message stays on screen.
const notifyTTL = 5 * time.Second

// Model is the dashboard state.
type Model struct {
	store       *store.Store
	notify      string // status line shown under the header
	notifyUntil time.Time

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
	telegram      *telegramPanel
}

// Options configure the dashboard.
type Options struct {
	Store *store.Store
	// RulesPath and ParsersPath let the editors write config files.
	RulesPath   string
	ParsersPath string
	// ExportDir is where CSV exports are written.
	ExportDir string
	// Auth is the shared Telegram access store the panel manages.
	Auth *telegramauth.Store
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
	m.telegram = newTelegramPanel(opts.Auth)
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
//
// It is the background poll, so it respects pause.
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

// setNotify shows a status message that clears itself after notifyTTL.
func (m *Model) setNotify(text string) {
	m.notify = text
	m.notifyUntil = time.Now().Add(notifyTTL)
}

// expireNotify clears a stale status message.
func (m *Model) expireNotify() {
	if m.notify != "" && !m.notifyUntil.IsZero() && time.Now().After(m.notifyUntil) {
		m.notify = ""
		m.notifyUntil = time.Time{}
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
		m.expireNotify()
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
	// ctrl+c always exits, from any screen, so there is one guaranteed way out
	// even while an editor holds unsaved changes.
	if msg.String() == "ctrl+c" {
		return m, tea.Quit
	}

	switch m.view {
	case viewRules:
		return m, m.rulesEditor.update(msg)
	case viewParsers:
		return m, m.parsersEditor.update(msg)
	case viewDetail:
		return m, m.handleDetailKey(msg)
	case viewExportConfirm:
		return m, m.handleExportKey(msg)
	case viewTelegram:
		if m.telegram.update(msg) {
			m.view = viewDashboard
		}
		return m, nil
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
	case "q":
		return m, tea.Quit
	case "p":
		m.paused = !m.paused
		if m.paused {
			m.setNotify("paused")
		} else {
			m.notify = ""
			m.notifyUntil = time.Time{}
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
	case "T":
		m.view = viewTelegram
		m.telegram.open()
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
			return centerBlock(m.detail.view(m.width, m.height), m.width, m.height)
		}
	case viewExportConfirm:
		return m.viewExportConfirm()
	case viewOverview:
		return m.viewOverview()
	case viewTelegram:
		return m.telegram.view(m.width, m.height)
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
	return centerBlock(modalBox(b.String(), minInt(m.width-6, 72)), m.width, m.height)
}

func (m *Model) viewOverview() string {
	header := styleBrand.Render("◈ SECURITY OVERVIEW") +
		styleDim.Render("   r refresh · esc back")
	body := strings.Join(m.overview, "\n")
	if body == "" {
		body = styleDim.Render("loading…")
	}
	box := modalBox(header+"\n\n"+body, m.width)
	return centerBlock(box, m.width, m.height)
}

// renderOverview formats the overview panels.
func renderOverview(sources []store.SourceCount, types []store.TypeCount) []string {
	var out []string
	rows := func(title string, labels []string, counts []int) {
		out = append(out, styleAccent.Render(title))
		if len(labels) == 0 {
			out = append(out, styleDim.Render("   none recorded"))
			return
		}
		max := 0
		widest := 0
		for i := range labels {
			if counts[i] > max {
				max = counts[i]
			}
			if w := len(labels[i]); w > widest {
				widest = w
			}
		}
		if widest > 26 {
			widest = 26
		}
		for i, label := range labels {
			bar := styleAccentHi.Render(strings.Repeat("█", barWidth(counts[i], max, 28)))
			out = append(out, "   "+
				styleText.Render(padWidth(label, widest))+"  "+
				styleAccent.Render(padWidth(strconv.Itoa(counts[i]), 5))+" "+
				bar)
		}
	}

	labels := make([]string, len(sources))
	counts := make([]int, len(sources))
	for i, sc := range sources {
		labels[i] = orDash(sc.Source)
		counts[i] = sc.Count
	}
	rows("TOP DETECTION SOURCES", labels, counts)

	out = append(out, "")
	labels = make([]string, len(types))
	counts = make([]int, len(types))
	for i, tc := range types {
		labels[i] = tc.Type
		counts[i] = tc.Count
	}
	rows("DETECTIONS BY TYPE", labels, counts)
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
	ti.Placeholder = "Search logs & anomalies…"
	ti.CharLimit = 64
	ti.Prompt = ""
	return ti
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// layout decides the responsive arrangement for the current width.
type layout struct {
	stacked  bool // narrow: anomalies below logs
	wideCols bool // wide: show dst/proto columns
	logsW    int
	anomsW   int
}

func (m *Model) layout() layout {
	l := layout{}
	l.wideCols = m.width >= 110
	if m.width < 76 {
		l.stacked = true
		return l
	}
	l.logsW = m.width * 3 / 5
	if l.logsW < 44 {
		l.logsW = 44
	}
	l.anomsW = m.width - l.logsW - 2
	if l.anomsW < 26 {
		l.anomsW = 26
		l.logsW = m.width - l.anomsW - 2
	}
	return l
}

func (m *Model) viewDashboard() string {
	if m.width <= 0 {
		m.width = 80
	}
	if m.height <= 0 {
		m.height = 24
	}

	// Chrome adapts to the terminal height: on a short terminal the stats row
	// and the bordered search box are dropped so the panes stay usable.
	compact := m.height < 20
	head := []string{m.viewHeader()}
	if !compact {
		head = append(head, m.viewStats())
	}
	head = append(head, m.viewSearchLines(compact)...)

	bodyH := m.height - len(head) - 1 // one line reserved for the footer
	if bodyH < 5 {
		bodyH = 5
	}

	var parts []string
	parts = append(parts, head...)

	l := m.layout()
	if l.stacked && bodyH >= 10 {
		logH := bodyH * 3 / 5
		anomH := bodyH - logH
		if logH < 5 {
			logH = 5
			anomH = bodyH - logH
		}
		if anomH < 5 {
			anomH = 5
			logH = bodyH - anomH
		}
		if logH < 5 {
			logH = 5
		}
		parts = append(parts, m.viewLogs(m.width-2, logH))
		if anomH >= 5 {
			parts = append(parts, m.viewAnomalies(m.width-2, anomH))
		}
	} else if l.stacked {
		// Too short to stack: show the log stream alone.
		parts = append(parts, m.viewLogs(m.width-2, bodyH))
	} else {
		parts = append(parts, lipgloss.JoinHorizontal(lipgloss.Top,
			m.viewLogs(l.logsW, bodyH), " ", m.viewAnomalies(l.anomsW, bodyH)))
	}

	parts = append(parts, m.viewFooter())
	return strings.Join(parts, "\n")
}

// viewSearchLines renders the filter box: a bordered box when tall enough,
// otherwise a single line so the panes keep their space.
func (m *Model) viewSearchLines(compact bool) []string {
	label := styleAccentHi.Render("/ ")
	body := label + m.search.View()
	if compact {
		return []string{body}
	}
	if m.searching {
		return strings.Split(stylePanelActive.Width(m.width-4).
			Padding(0, 1).Render(body), "\n")
	}
	return strings.Split(styleDim.Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorPrimary).
		Width(m.width-4).Padding(0, 1).Render(body), "\n")
}

// viewHeader is the filled brand bar.
func (m *Model) viewHeader() string {
	title := "◈ SISKAMLAN"
	subtitle := "LAN security monitoring"
	left := title
	if m.width >= 70 {
		left = title + "  " + subtitle
	}

	statusText := "● LIVE"
	statusStyle := lipgloss.NewStyle().Foreground(ColorBg).Background(ColorPrimary).Bold(true)
	if m.paused {
		statusText = "❚❚ PAUSED"
		statusStyle = lipgloss.NewStyle().Foreground(ColorBg).Background(ColorHigh).Bold(true)
	}
	if m.lastErr != nil {
		statusText = "! " + truncateWidth(m.lastErr.Error(), 40)
		statusStyle = lipgloss.NewStyle().Foreground(ColorBg).Background(ColorCritical).Bold(true)
	}

	gap := m.width - lipgloss.Width(left) - lipgloss.Width(statusText) - 2
	if gap < 1 {
		gap = 1
	}
	return styleHeaderBar.Render(left) +
		styleHeaderBar.Render(strings.Repeat(" ", gap)) +
		statusStyle.Render(" "+statusText+" ")
}

// viewStats renders the aggregate counters as chips.
//
// Chips are added in priority order and dropped once they no longer fit, so
// the line never wraps on a narrow terminal.
func (m *Model) viewStats() string {
	s := m.stats
	candidates := []string{
		styleChip.Render("Logs " + styleAccentHi.Render(commas(s.TotalLogs))),
		styleChip.Render("1h " + styleAccentHi.Render(commas(s.LogsLastHour))),
		styleChip.Render("Dev " + styleAccentHi.Render(commas(s.ActiveDevices))),
		styleChip.Render("Anom " + styleAccentHi.Render(commas(s.TotalAnomalies))),
		severityStyle("CRITICAL").Render("● " + commas(s.Critical)),
		severityStyle("HIGH").Render("◆ " + commas(s.High)),
		severityStyle("MEDIUM").Render("▲ " + commas(s.Medium)),
		severityStyle("LOW").Render("▽ " + commas(s.Low)),
	}

	var kept []string
	width := 0
	for _, c := range candidates {
		w := lipgloss.Width(c)
		if len(kept) > 0 && width+1+w > m.width {
			continue
		}
		if len(kept) == 0 && w > m.width {
			continue
		}
		kept = append(kept, c)
		width += w
		if len(kept) > 1 {
			width++
		}
	}
	return strings.Join(kept, " ")
}

func (m *Model) viewLogs(width, height int) string {
	// Panel content width: border (2) + horizontal padding (2), plus slack.
	avail := width - 6

	sets := [][]col{
		{ // widest: everything
			{"TIME", 8, false}, {"HOST", 16, true}, {"DEVICE", 10, false},
			{"EVENT", 14, true}, {"SRC IP", 15, true}, {"ENTITY", 15, true},
			{"PROTO", 5, false}, {"PORT", 5, false},
		},
		{ // no entity/proto
			{"TIME", 8, false}, {"HOST", 14, true}, {"DEVICE", 9, false},
			{"EVENT", 13, true}, {"SRC IP", 14, true}, {"PORT", 5, false},
		},
		{ // compact, still shows the source
			{"TIME", 8, false}, {"HOST", 14, true}, {"EVENT", 12, true},
			{"SRC IP", 13, true}, {"PORT", 5, false},
		},
		{ // tighter compact
			{"TIME", 8, false}, {"HOST", 12, true}, {"EVENT", 12, true},
			{"PORT", 5, false},
		},
		{ // minimal
			{"TIME", 8, false}, {"EVENT", 12, true},
		},
	}
	headers, widths, ok := fitCols(sets, avail)
	if !ok {
		headers = []string{"TIME", "EVENT"}
		widths = []int{8, maxIntOf(6, avail-10)}
	}
	ncols := len(widths)
	wide := ncols == 8
	mid := ncols == 6
	five := ncols == 5

	rows := make([]string, 0, len(m.logs))
	for i, r := range m.logs {
		src := ""
		if r.SrcIP != nil {
			src = *r.SrcIP
		}
		entity := ""
		if r.MAC != "" {
			entity = r.MAC
		} else if r.ClientMAC != "" {
			entity = r.ClientMAC
		} else if r.DstIP != nil {
			entity = *r.DstIP
		}
		port := "—"
		if r.DstPort != nil {
			port = strconv.Itoa(*r.DstPort)
		}

		// EVENT sits at index 3 for the 6- and 8-column sets, index 2 for the
		// 4/5-column sets, and index 1 for the minimal pair.
		evIdx := 3
		switch ncols {
		case 2:
			evIdx = 1
		case 4, 5:
			evIdx = 2
		}
		evW := widths[evIdx]
		ev := eventStyle(r.Event).Render(padWidth(r.Event, evW))

		var line string
		switch {
		case wide:
			line = styleDim.Render(padWidth(r.Timestamp.Format("15:04:05"), widths[0])) + "  " +
				padWidth(r.Hostname, widths[1]) + "  " +
				padWidth(deviceIcon(r.DeviceType)+" "+r.DeviceType, widths[2]) + "  " +
				ev + "  " + padWidth(src, widths[4]) + "  " +
				padWidth(entity, widths[5]) + "  " +
				padWidth(r.Proto, widths[6]) + "  " + padWidth(port, widths[7])
		case mid:
			line = styleDim.Render(padWidth(r.Timestamp.Format("15:04:05"), widths[0])) + "  " +
				padWidth(r.Hostname, widths[1]) + "  " +
				padWidth(deviceIcon(r.DeviceType)+" "+r.DeviceType, widths[2]) + "  " +
				ev + "  " + padWidth(src, widths[4]) + "  " + padWidth(port, widths[5])
		case five:
			line = styleDim.Render(padWidth(r.Timestamp.Format("15:04:05"), widths[0])) + "  " +
				padWidth(r.Hostname, widths[1]) + "  " +
				ev + "  " + padWidth(src, widths[3]) + "  " + padWidth(port, widths[4])
		case ncols == 4:
			line = styleDim.Render(padWidth(r.Timestamp.Format("15:04:05"), widths[0])) + "  " +
				padWidth(r.Hostname, widths[1]) + "  " +
				ev + "  " + padWidth(port, widths[3])
		default:
			line = styleDim.Render(padWidth(r.Timestamp.Format("15:04:05"), widths[0])) + "  " + ev
		}
		if i == m.logOffset {
			line = styleSelected.Render(strings.TrimRight(line, " "))
		}
		rows = append(rows, line)
	}
	if len(rows) == 0 {
		rows = []string{styleDim.Render("no log rows match")}
	}

	// Panel lines = border 2 + title 1 + header 1 + rule 1 + viewport.
	viewport := height - 5
	if viewport < 1 {
		viewport = 1
	}
	if m.logOffset < m.logTop {
		m.logTop = m.logOffset
	}
	if m.logOffset >= m.logTop+viewport {
		m.logTop = m.logOffset - viewport + 1
	}
	body, off := renderTable(headers, widths, rows, m.logTop, viewport)
	m.logTop = off

	title := "  LOG STREAM "
	if m.focusLogs {
		title = "▸ LOG STREAM "
	}
	return panel(title, body, width, height, m.focusLogs)
}

func (m *Model) viewAnomalies(width, height int) string {
	inner := width - 6
	sevW := 10
	// Below ~34 cells the timestamp is dropped to keep the detection readable.
	showTime := inner >= 34
	var widths []int
	var headers []string
	descW := 0
	if showTime {
		timeW := 8
		descW = inner - timeW - sevW - 4
		if descW < 10 {
			descW = 10
		}
		widths = []int{timeW, sevW, descW}
		headers = []string{"TIME", "SEVERITY", "DETECTION"}
	} else {
		descW = inner - sevW - 2
		if descW < 8 {
			descW = 8
		}
		widths = []int{sevW, descW}
		headers = []string{"SEVERITY", "DETECTION"}
	}

	rows := make([]string, 0, len(m.anomalies))
	for i, a := range m.anomalies {
		sev := severityStyle(a.Severity).Render(
			padWidth(severityIcon(a.Severity)+" "+a.Severity, sevW))
		desc := strings.TrimPrefix(a.Description, "[RULE] ")
		if a.RepeatCount > 1 {
			desc = fmt.Sprintf("%s ×%d", desc, a.RepeatCount)
		}
		var line string
		if showTime {
			line = styleDim.Render(padWidth(a.Timestamp.Format("15:04:05"), widths[0])) + "  " +
				sev + "  " + padWidth(desc, descW)
		} else {
			line = sev + "  " + padWidth(desc, descW)
		}
		if i == m.anomOffset {
			line = styleSelected.Render(strings.TrimRight(line, " "))
		}
		rows = append(rows, line)
	}
	if len(rows) == 0 {
		rows = []string{styleDim.Render("no detections")}
	}

	viewport := height - 5
	if viewport < 1 {
		viewport = 1
	}
	if m.anomOffset < m.anomTop {
		m.anomTop = m.anomOffset
	}
	if m.anomOffset >= m.anomTop+viewport {
		m.anomTop = m.anomOffset - viewport + 1
	}
	body, off := renderTable(headers, widths, rows, m.anomTop, viewport)
	m.anomTop = off

	title := "  ANOMALIES "
	if !m.focusLogs {
		title = "▸ ANOMALIES "
	}
	return panel(title, body, width, height, !m.focusLogs)
}

// viewFooter renders the key hints.
func (m *Model) viewFooter() string {
	var keys string
	if m.width >= 100 {
		keys = "q quit │ p pause │ / search │ ↑↓ move │ tab focus │ ⏎ detail │ o overview │ e export │ R rules │ P parsers │ T telegram │ ? help"
	} else {
		keys = "q quit │ p pause │ / search │ tab focus │ ⏎ detail │ R rules │ ? help"
	}
	if m.notify != "" {
		keys = styleAccentHi.Render(m.notify) + styleDim.Render(" │ ") + keys
	}
	return styleFooterBar.Render(truncateWidth(keys, m.width))
}

func (m *Model) viewHelp() string {
	section := func(name string) string { return "\n" + styleAccent.Render(name) }
	key := func(k, desc string) string {
		return "  " + styleAccentHi.Render(padWidth(k, 13)) + styleText.Render(desc)
	}
	lines := []string{
		styleBrand.Render("◈ SISKAMLAN") + styleDim.Render("  keyboard reference"),
		section("Dashboard"),
		key("q", "quit (from the dashboard)"),
		key("ctrl+c", "quit from any screen"),
		key("p", "pause / resume live refresh"),
		key("/", "filter host, event, IP, MAC, SSID, interface, timestamp"),
		key("esc", "clear the filter"),
		key("↑ ↓ j k", "move the selection"),
		key("tab", "switch focus between logs and anomalies"),
		key("enter", "open the selected row's detail"),
		key("o", "security overview"),
		key("e", "export visible rows to CSV"),
		key("g", "jump to the top"),
		key("r", "refresh now"),
		section("Configuration (live, no restart)"),
		key("R", "rules editor"),
		key("P", "parser editor"),
		key("T", "telegram access (approve / revoke chats)"),
		section("Rules editor"),
		key("a e x", "add · edit · delete"),
		key("space", "enable / disable"),
		key("p", "preview against the last 5 minutes"),
		key("s", "save and apply"),
		section("Parser editor"),
		key("n e x", "new · edit · delete device"),
		key("a", "add a field assignment"),
		key("i", "assign from a keyword in recent logs"),
		key("s", "save and apply"),
		"",
		styleDim.Render("Press b or ? to return to the dashboard."),
	}
	return centerBlock(modalBox(strings.Join(lines, "\n"), m.width), m.width, m.height)
}
