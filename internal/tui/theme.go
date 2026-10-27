// Package tui renders the SISKAMLAN terminal dashboard.
package tui

import "github.com/charmbracelet/lipgloss"

// Palette ported from the original Textual theme (tui/theme.py): a neutral
// black base with a single blue brand hue. Severity colours stay separate so
// alert levels remain instantly recognisable.
var (
	ColorBg      = lipgloss.Color("#0A0A0A") // app background, soft black
	ColorSurface = lipgloss.Color("#101214") // raised surfaces, panel bodies
	ColorText    = lipgloss.Color("#E6E6E6") // primary text
	ColorMuted   = lipgloss.Color("#8A8A8A") // secondary text

	ColorPrimary     = lipgloss.Color("#1565A8") // main brand blue
	ColorAccent      = lipgloss.Color("#2B8FD6") // bright blue: focus, active borders
	ColorAccentLight = lipgloss.Color("#5EB8F5") // emphasis on black
	ColorAccentDim   = lipgloss.Color("#1E6FA8") // subdued blue
)

// Severity colours, matching the red/orange/yellow/green semantics of the
// original emoji markers.
var (
	ColorCritical = lipgloss.Color("#FF5F56")
	ColorHigh     = lipgloss.Color("#FF9F43")
	ColorMedium   = lipgloss.Color("#F5D76E")
	ColorLow      = lipgloss.Color("#2ECC71")
)

// Style shortcuts.
var (
	styleTitle    = lipgloss.NewStyle().Foreground(ColorText).Bold(true)
	styleAccent   = lipgloss.NewStyle().Foreground(ColorAccent).Bold(true)
	styleAccentHi = lipgloss.NewStyle().Foreground(ColorAccentLight).Bold(true)
	styleBrand    = lipgloss.NewStyle().Foreground(ColorAccent).Bold(true)
	styleDim      = lipgloss.NewStyle().Foreground(ColorMuted)
	styleText     = lipgloss.NewStyle().Foreground(ColorText)
	styleSelected = lipgloss.NewStyle().
			Background(ColorPrimary).
			Foreground(ColorText).
			Bold(true)
	styleError = lipgloss.NewStyle().Foreground(ColorCritical).Bold(true)
	styleOK    = lipgloss.NewStyle().Foreground(ColorLow).Bold(true)
	styleWarn  = lipgloss.NewStyle().Foreground(ColorHigh)

	// stylePanel is the standard bordered card.
	stylePanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorPrimary)
	// stylePanelActive highlights the focused card.
	stylePanelActive = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorAccent)
	// styleHeaderBar is the filled top bar.
	styleHeaderBar = lipgloss.NewStyle().
			Background(ColorPrimary).
			Foreground(ColorText).
			Bold(true)
	// styleFooterBar is the key-hint strip.
	styleFooterBar = lipgloss.NewStyle().
			Foreground(ColorMuted)
	styleChip = lipgloss.NewStyle().
			Background(ColorSurface).
			Foreground(ColorText).
			Padding(0, 1)
	styleBadgeFocus = lipgloss.NewStyle().
			Background(ColorAccent).
			Foreground(ColorBg).
			Bold(true).
			Padding(0, 1)
	styleBadgeIdle = lipgloss.NewStyle().
			Background(ColorSurface).
			Foreground(ColorMuted).
			Padding(0, 1)
)

// severityStyle colours a severity label.
func severityStyle(sev string) lipgloss.Style {
	switch sev {
	case "CRITICAL":
		return lipgloss.NewStyle().Foreground(ColorCritical).Bold(true)
	case "HIGH":
		return lipgloss.NewStyle().Foreground(ColorHigh).Bold(true)
	case "MEDIUM":
		return lipgloss.NewStyle().Foreground(ColorMedium).Bold(true)
	case "LOW":
		return lipgloss.NewStyle().Foreground(ColorLow).Bold(true)
	default:
		return styleDim
	}
}

// severityIcon mirrors the original emoji markers with terminal-safe glyphs.
func severityIcon(sev string) string {
	switch sev {
	case "CRITICAL":
		return "●"
	case "HIGH":
		return "◆"
	case "MEDIUM":
		return "▲"
	case "LOW":
		return "▽"
	default:
		return "○"
	}
}

// deviceIcon gives each device class a distinguishing glyph.
func deviceIcon(device string) string {
	switch device {
	case "firewall":
		return "⛨"
	case "router":
		return "⇄"
	case "switch":
		return "⇉"
	case "ap":
		return "◉"
	case "syslog":
		return "▤"
	default:
		return "·"
	}
}

// eventStyle tints events by intent so attacks stand out from routine traffic.
func eventStyle(event string) lipgloss.Style {
	switch event {
	case "fw_block", "fw_reject", "auth_failure", "deauth", "mac_flap", "stp_event":
		return lipgloss.NewStyle().Foreground(ColorHigh)
	case "fw_allow", "client_connect", "mac_learn", "dhcp_ack":
		return lipgloss.NewStyle().Foreground(ColorLow)
	case "client_disconnect", "interface_status", "port_status":
		return lipgloss.NewStyle().Foreground(ColorMuted)
	default:
		return lipgloss.NewStyle().Foreground(ColorText)
	}
}
