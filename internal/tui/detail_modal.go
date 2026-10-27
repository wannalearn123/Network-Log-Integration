package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"siskamlan/internal/store"
)

// detailModal shows every field of one log row or one anomaly.
//
// The parsed columns are the point: this is how you confirm that a parser
// profile or a newly added log source produced the values you expected.
type detailModal struct {
	title    string
	rows     [][2]string
	raw      string
	rawLabel string
	offset   int
}

// newLogDetail builds the modal for a parsed log row.
func newLogDetail(r *store.LogEntry) *detailModal {
	str := func(p *string) string {
		if p == nil || *p == "" {
			return "—"
		}
		return *p
	}
	num := func(p *int) string {
		if p == nil {
			return "—"
		}
		return strconv.Itoa(*p)
	}
	s := func(v string) string {
		if v == "" {
			return "—"
		}
		return v
	}

	return &detailModal{
		title:    fmt.Sprintf("LOG %s · %s", r.Timestamp.Format("2006-01-02 15:04:05"), s(r.Hostname)),
		rawLabel: "raw_line",
		raw:      r.RawLine,
		rows: [][2]string{
			{"timestamp", r.Timestamp.Format("2006-01-02T15:04:05Z07:00")},
			{"hostname", s(r.Hostname)},
			{"facility", s(r.Facility)},
			{"severity", s(r.Severity)},
			{"device_type", s(r.DeviceType)},
			{"event", s(r.Event)},
			{"src_ip", str(r.SrcIP)},
			{"dst_ip", str(r.DstIP)},
			{"proto", s(r.Proto)},
			{"dst_port", num(r.DstPort)},
			{"src_port", num(r.SrcPort)},
			{"action", s(r.Action)},
			{"mac", s(r.MAC)},
			{"vlan_id", num(r.VLANID)},
			{"ifname", s(r.IfName)},
			{"peer_ifname", s(r.PeerIfName)},
			{"stp_root", s(r.STPRoot)},
			{"client_mac", s(r.ClientMAC)},
			{"ssid", s(r.SSID)},
			{"radio", s(r.Radio)},
			{"reason", num(r.Reason)},
			{"signal_dbm", num(r.SignalDBM)},
			{"tx_rate_mbps", num(r.TxRateMbps)},
			{"eap_status", s(r.EAPStatus)},
			{"ospf_nbr", str(r.OSPFNbr)},
			{"gateway", str(r.Gateway)},
			{"route_dst", s(r.RouteDst)},
			{"dhcp_mac", s(r.DHCPMAC)},
			{"conntrack_count", num(r.ConntrackCt)},
		},
	}
}

// newAnomalyDetail builds the modal for a detection.
func newAnomalyDetail(a store.AnomalyRow) *detailModal {
	score := "—"
	if a.Score != nil {
		score = strconv.FormatFloat(*a.Score, 'f', 1, 64)
	}
	return &detailModal{
		title:    fmt.Sprintf("ANOMALY #%d · %s", a.ID, a.Severity),
		rawLabel: "features (jsonb)",
		raw:      a.Features,
		rows: [][2]string{
			{"id", strconv.Itoa(a.ID)},
			{"timestamp", a.Timestamp.Format("2006-01-02T15:04:05Z07:00")},
			{"severity", a.Severity},
			{"anomaly_score", score},
			{"repeat_count", strconv.Itoa(a.RepeatCount)},
			{"window_start", a.WindowStart.Format("15:04:05")},
			{"window_end", a.WindowEnd.Format("15:04:05")},
			{"description", a.Description},
		},
	}
}

// setRaw attaches the raw document shown last.
func (d *detailModal) setRaw(raw string) { d.raw = raw }

// scroll moves the modal view.
func (d *detailModal) scroll(delta int) {
	d.offset += delta
	if d.offset < 0 {
		d.offset = 0
	}
}

// view renders the modal.
func (d *detailModal) view(width, height int) string {
	maxWidth := minInt(width-6, 100)
	if maxWidth < 40 {
		maxWidth = 40
	}
	labelWidth := 0
	for _, kv := range d.rows {
		if w := lipgloss.Width(kv[0]); w > labelWidth {
			labelWidth = w
		}
	}
	valueWidth := maxWidth - labelWidth - 6

	var body []string
	for _, kv := range d.rows {
		for i, part := range wrapText(kv[1], valueWidth) {
			label := ""
			if i == 0 {
				label = kv[0]
			}
			body = append(body, styleDim.Render(padWidth(label, labelWidth))+"  "+part)
		}
	}
	if d.raw != "" {
		body = append(body, "", styleAccent.Render(d.rawLabel))
		for _, part := range wrapText(d.raw, maxWidth-6) {
			body = append(body, styleDim.Render(part))
		}
	}

	maxBody := height - 8
	if maxBody < 3 {
		maxBody = 3
	}
	if d.offset > len(body)-maxBody {
		d.offset = len(body) - maxBody
	}
	if d.offset < 0 {
		d.offset = 0
	}
	visible := body
	if len(body) > maxBody {
		end := d.offset + maxBody
		if end > len(body) {
			end = len(body)
		}
		visible = body[d.offset:end]
	}

	head := []string{
		styleTitle.Render(d.title),
		styleDim.Render("esc / enter close · ↑↓ scroll"),
		"",
	}
	out := append(head, visible...)
	return modalBox(strings.Join(out, "\n"), maxWidth)
}

// wrapText breaks s into chunks that fit width, honouring existing newlines.
func wrapText(s string, width int) []string {
	if width < 1 {
		width = 1
	}
	if s == "" {
		return []string{""}
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			out = append(out, "")
			continue
		}
		for lipgloss.Width(line) > width {
			cut := width
			if cut > len(line) {
				cut = len(line)
			}
			if idx := strings.LastIndexByte(line[:cut], ' '); idx > 0 {
				cut = idx
			}
			out = append(out, line[:cut])
			line = strings.TrimLeft(line[cut:], " ")
		}
		out = append(out, line)
	}
	return out
}
