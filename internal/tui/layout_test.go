package tui

import (
	"strings"
	"testing"

	"siskamlan/internal/rules"
	"siskamlan/internal/store"
)

// stripAnsi removes SGR sequences so widths can be measured.
func stripAnsi(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case r == 0x1b:
			inEsc = true
		case inEsc && r == 'm':
			inEsc = false
		case inEsc:
			// drop
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// widestLine measures the longest rendered line in cells.
func widestLine(s string) int {
	max := 0
	for _, line := range strings.Split(s, "\n") {
		if n := len([]rune(stripAnsi(line))); n > max {
			max = n
		}
	}
	return max
}

// TestNoHorizontalOverflow renders every screen at many widths and asserts
// nothing exceeds the terminal. Wrapping corrupts the layout, so this is the
// guard for the responsive column fitting.
func TestNoHorizontalOverflow(t *testing.T) {
	widths := []int{140, 120, 100, 90, 80, 76, 72, 60, 50, 40}

	screens := map[string]func(w int) string{
		"dashboard": func(w int) string {
			m := &Model{search: newSearchInput(), view: viewDashboard,
				width: w, height: 30, focusLogs: true}
			m.stats = store.Stats{TotalLogs: 128402, LogsLastHour: 3310,
				ActiveDevices: 7, TotalAnomalies: 42, Critical: 2, High: 9}
			src := "172.20.100.25"
			dst := "172.20.0.4"
			mac := "aa:bb:cc:3d:98:00"
			port := 443
			for i := 0; i < 12; i++ {
				m.logs = append(m.logs, &store.LogEntry{
					Hostname: "firewall.monitoringsystembak", DeviceType: "firewall",
					Event: "fw_block", SrcIP: &src, DstIP: &dst,
					ClientMAC: mac, Proto: "TCP", DstPort: &port,
				})
			}
			m.anomalies = []store.AnomalyRow{
				{ID: 1, Severity: "CRITICAL", RepeatCount: 3,
					Description: "[RULE] Brute force from 172.20.100.10 — 15 fails in 30s"},
			}
			return m.viewDashboard()
		},
		"rules": func(w int) string {
			e := newRulesEditor("/tmp/nonexistent-rules.yaml", nil)
			e.rf = rules.DefaultRulesFile()
			return e.viewList(w, 26)
		},
		"parsers": func(w int) string {
			e := newParsersEditor("/tmp/nonexistent-parsers.yaml", nil)
			return e.viewList(w, 26)
		},
		"help": func(w int) string {
			m := &Model{search: newSearchInput(), width: w, height: 40}
			return m.viewHelp()
		},
		"export": func(w int) string {
			m := &Model{search: newSearchInput(), width: w, height: 30}
			m.logs = make([]*store.LogEntry, 3)
			return m.viewExportConfirm()
		},
		"overview": func(w int) string {
			m := &Model{search: newSearchInput(), width: w, height: 30}
			m.overview = renderOverview(
				[]store.SourceCount{{Source: "172.20.100.10", Count: 9}},
				[]store.TypeCount{{Type: "BRUTE_FORCE", Count: 9}})
			return m.viewOverview()
		},
		"detail": func(w int) string {
			src := "fe80::2481:d6ff:fea2:2a69"
			e := &store.LogEntry{Hostname: "lab-firewall.lab-mgmt",
				DeviceType: "firewall", Event: "fw_block", SrcIP: &src,
				RawLine: strings.Repeat("long raw line ", 20)}
			d := newLogDetail(e)
			return d.view(w, 40)
		},
	}

	for name, render := range screens {
		for _, w := range widths {
			if got := widestLine(render(w)); got > w {
				t.Errorf("%s at width %d: widest line %d (overflow)", name, w, got)
			}
		}
	}
}

// TestDashboardStacksWhenNarrow checks the panes stack instead of squeezing.
func TestDashboardStacksWhenNarrow(t *testing.T) {
	wide := &Model{search: newSearchInput(), width: 120, height: 30, focusLogs: true}
	if wide.layout().stacked {
		t.Fatal("120 cells should not stack")
	}
	narrow := &Model{search: newSearchInput(), width: 70, height: 30, focusLogs: true}
	if !narrow.layout().stacked {
		t.Fatal("70 cells should stack")
	}
}

// TestFitColsDegrades checks richer column sets win when they fit.
func TestFitColsDegrades(t *testing.T) {
	sets := [][]col{
		{{"A", 10, false}, {"B", 20, true}, {"C", 10, false}},
		{{"A", 10, false}, {"B", 8, true}},
		{{"A", 6, false}},
	}
	// Wide: all three columns, with spare width absorbed by the flex column.
	headers, widths, ok := fitCols(sets, 60)
	if !ok || len(headers) != 3 {
		t.Fatalf("wide fit = %v %v %v", headers, widths, ok)
	}
	if widths[1] <= 20 {
		t.Fatalf("flex column did not grow: %v", widths)
	}
	if rowWidth(widths) > 60 {
		t.Fatalf("row width %d exceeds 60", rowWidth(widths))
	}

	// Narrow: drop to the smallest set.
	headers, widths, ok = fitCols(sets, 12)
	if !ok || len(headers) != 1 {
		t.Fatalf("narrow fit = %v %v %v", headers, widths, ok)
	}

	// Too small for anything.
	if _, _, ok := fitCols(sets, 2); ok {
		t.Fatal("expected no fitting set for a 2-cell budget")
	}
}

// TestFitColsDistributesRemainder ensures spare cells are actually used.
func TestFitColsDistributesRemainder(t *testing.T) {
	sets := [][]col{{{"A", 10, false}, {"B", 10, true}, {"C", 10, true}}}
	_, widths, _ := fitCols(sets, 40)
	if rowWidth(widths) != 40 {
		t.Fatalf("row width = %d, want 40 (remainder not distributed)", rowWidth(widths))
	}
}

// TestSeverityIconsDistinct ensures alert levels are visually distinguishable.
func TestSeverityIconsDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, sev := range rules.Severities {
		icon := severityIcon(sev)
		if icon == "" {
			t.Errorf("%s has no icon", sev)
		}
		if prev, dup := seen[icon]; dup {
			t.Errorf("%s and %s share icon %q", prev, sev, icon)
		}
		seen[icon] = sev
	}
}

// TestCommasFormatter checks the thousands separators used in the header.
func TestCommasFormatter(t *testing.T) {
	cases := map[int]string{
		0: "0", 999: "999", 1000: "1,000", 12345: "12,345",
		128402: "128,402", -1500: "-1,500",
	}
	for in, want := range cases {
		if got := commas(in); got != want {
			t.Errorf("commas(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestPaletteMatchesOriginalTheme pins the colours ported from theme.py.
func TestPaletteMatchesOriginalTheme(t *testing.T) {
	want := map[string]string{
		"background":   "#0A0A0A",
		"surface":      "#101214",
		"text":         "#E6E6E6",
		"muted":        "#8A8A8A",
		"primary":      "#1565A8",
		"accent":       "#2B8FD6",
		"accent_light": "#5EB8F5",
		"accent_dim":   "#1E6FA8",
	}
	got := map[string]string{
		"background":   string(ColorBg),
		"surface":      string(ColorSurface),
		"text":         string(ColorText),
		"muted":        string(ColorMuted),
		"primary":      string(ColorPrimary),
		"accent":       string(ColorAccent),
		"accent_light": string(ColorAccentLight),
		"accent_dim":   string(ColorAccentDim),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}
}

// TestNoVerticalOverflow renders the dashboard at many sizes and asserts the
// frame fits the terminal. One extra row shifts everything and hides the
// header, so this guards the height arithmetic.
func TestNoVerticalOverflow(t *testing.T) {
	src := "10.0.0.1"
	port := 443
	for _, w := range []int{140, 120, 90, 72, 60} {
		for _, h := range []int{16, 18, 20, 24, 30, 40} {
			m := &Model{search: newSearchInput(), view: viewDashboard,
				width: w, height: h, focusLogs: true}
			for i := 0; i < 6; i++ {
				m.logs = append(m.logs, &store.LogEntry{
					Hostname: "h", DeviceType: "firewall", Event: "fw_block",
					SrcIP: &src, DstPort: &port,
				})
			}
			got := len(strings.Split(m.viewDashboard(), "\n"))
			if got > h {
				t.Errorf("%dx%d rendered %d lines (overflow)", w, h, got)
			}
		}
	}
}

// TestPanelExactHeight checks panel() honours the requested box height.
func TestPanelExactHeight(t *testing.T) {
	for _, h := range []int{6, 10, 20} {
		got := len(strings.Split(panel("T", "body", 40, h, false), "\n"))
		if got != h {
			t.Errorf("panel height %d rendered %d lines", h, got)
		}
	}
}
