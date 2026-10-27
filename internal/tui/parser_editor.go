package tui

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"siskamlan/internal/config"
	"siskamlan/internal/parser"
	"siskamlan/internal/store"
)

// keyword is one assignable token found in a sample raw line.
type keyword struct {
	key      string
	value    string
	guess    string // suggested target column
	strategy string
}

var kvTokenRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_-]*)=([^\s,;)\]"'{}]+)`)

// parsersEditor lists and edits config/parsers.yaml.
type parsersEditor struct {
	file  *config.File[parser.Config]
	store *store.Store

	cfg    parser.Config
	cursor int
	offset int

	status  string
	errText string

	mode       editorMode
	form       *form
	editDevice int // device index, or -1 when adding
	editField  int // field index, or -1 when adding

	rawLines []string
	tokens   []keyword
	tokCur   int
	tokErr   string
}

func newParsersEditor(path string, store *store.Store) *parsersEditor {
	f := config.NewFile[parser.Config](path)
	f.Decode = parser.DecodeConfig
	f.Validate = parser.ValidateConfig
	return &parsersEditor{file: f, store: store}
}

func (e *parsersEditor) open() {
	if err := e.file.Load(); err != nil {
		e.errText = err.Error()
		return
	}
	e.refreshFromFile()
	e.mode = modeList
	e.status = ""
	e.errText = ""
}

func (e *parsersEditor) refreshFromFile() {
	if cfg, ok := e.file.Current(); ok {
		e.cfg = cfg
	}
	if e.cursor >= len(e.cfg.Devices) {
		e.cursor = maxInt(0, len(e.cfg.Devices)-1)
	}
}

func (e *parsersEditor) update(msg tea.KeyMsg) tea.Cmd {
	switch e.mode {
	case modeForm:
		done, cancel := e.form.update(msg)
		if cancel {
			e.mode = modeList
			e.form = nil
			return nil
		}
		if done {
			e.applyForm()
		}
		return nil
	case modePreview: // reused for the keyword picker
		return e.updateKeyword(msg)
	}
	return e.updateList(msg)
}

func (e *parsersEditor) updateList(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "b":
		return func() tea.Msg { return closeEditorMsg{} }
	case "up", "k":
		if e.cursor > 0 {
			e.cursor--
		}
	case "down", "j":
		if e.cursor < len(e.cfg.Devices)-1 {
			e.cursor++
		}
	case "n":
		e.startDeviceForm(-1)
	case "e", "enter":
		if e.cursor < len(e.cfg.Devices) {
			e.startDeviceForm(e.cursor)
		}
	case "x":
		if e.cursor < len(e.cfg.Devices) {
			name := e.cfg.Devices[e.cursor].Name
			e.cfg.Devices = append(e.cfg.Devices[:e.cursor], e.cfg.Devices[e.cursor+1:]...)
			e.status = "deleted device " + name + " (unsaved)"
			if e.cursor >= len(e.cfg.Devices) {
				e.cursor = maxInt(0, len(e.cfg.Devices)-1)
			}
		}
	case "a":
		if e.cursor < len(e.cfg.Devices) {
			e.startFieldForm(e.cursor, -1)
		} else {
			e.errText = "add a device first (n)"
		}
	case "i":
		e.loadKeywords()
	case "s":
		e.save()
	}
	return nil
}

func (e *parsersEditor) startDeviceForm(idx int) {
	e.editDevice = idx
	var d parser.Device
	if idx >= 0 {
		d = e.cfg.Devices[idx]
	}
	dt := d.DeviceType
	if dt == "" {
		dt = "other"
	}
	e.form = newForm("Device profile", []formField{
		{label: "name", kind: kindText, value: orDefault(d.Name, "new-device")},
		{label: "hostname_match", kind: kindList, value: strings.Join(d.HostnameMatch, ", "),
			help: "regex list, comma-separated, matched against the hostname"},
		{label: "device_type", kind: kindEnum, value: dt,
			options: []string{"other", "router", "switch", "ap", "firewall", "syslog"}},
	})
	e.mode = modeForm
}

func (e *parsersEditor) startFieldForm(deviceIdx, fieldIdx int) {
	e.editDevice = deviceIdx
	e.editField = fieldIdx
	f := parser.FieldRule{Target: "src_ip", Strategy: "kv"}
	if fieldIdx >= 0 && deviceIdx >= 0 {
		f = e.cfg.Devices[deviceIdx].Fields[fieldIdx]
	}
	e.form = e.fieldForm(f)
	e.mode = modeForm
}

func (e *parsersEditor) fieldForm(f parser.FieldRule) *form {
	return newForm("Field assignment", []formField{
		{label: "target", kind: kindEnum, value: orDefault(f.Target, "src_ip"), options: parser.TargetColumns},
		{label: "strategy", kind: kindEnum, value: orDefault(f.Strategy, "kv"), options: parser.Strategies},
		{label: "key", kind: kindText, value: f.Key, help: "kv: the key= name to read"},
		{label: "keys", kind: kindList, value: strings.Join(f.Keys, ", "), help: "kv: fallback keys"},
		{label: "pattern", kind: kindText, value: f.Pattern, help: "regex: first capture group is used"},
		{label: "source", kind: kindText, value: f.Source, help: "word_map: column to translate"},
		{label: "map", kind: kindText, value: mapToText(f.Map), help: "word_map: from=to, from=to"},
		{label: "pos", kind: kindEnum, value: orDefault(f.Pos, "first"), options: []string{"first", "last"}},
		{label: "type", kind: kindEnum, value: orDefault(f.Type, ""), options: []string{"", "string", "int", "ip"}},
	})
}

func mapToText(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ", ")
}

func textToMap(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// applyForm stores the device or field the form was editing.
func (e *parsersEditor) applyForm() {
	v := e.form.values()
	// Field form has a "target" and "strategy" label combination; device form
	// has "hostname_match".
	if _, isDevice := v["hostname_match"]; isDevice {
		d := parser.Device{
			Name:          strings.TrimSpace(v["name"]),
			DeviceType:    v["device_type"],
			HostnameMatch: splitList(v["hostname_match"]),
		}
		if e.editDevice >= 0 && e.editDevice < len(e.cfg.Devices) {
			d.Fields = e.cfg.Devices[e.editDevice].Fields
			d.Events = e.cfg.Devices[e.editDevice].Events
			e.cfg.Devices[e.editDevice] = d
			e.status = "edited device " + d.Name + " (unsaved)"
		} else {
			e.cfg.Devices = append(e.cfg.Devices, d)
			e.cursor = len(e.cfg.Devices) - 1
			e.status = "added device " + d.Name + " (unsaved)"
		}
	} else {
		f := parser.FieldRule{
			Target:   v["target"],
			Strategy: v["strategy"],
			Key:      strings.TrimSpace(v["key"]),
			Keys:     splitList(v["keys"]),
			Pattern:  strings.TrimSpace(v["pattern"]),
			Source:   strings.TrimSpace(v["source"]),
			Map:      textToMap(v["map"]),
			Pos:      v["pos"],
			Type:     v["type"],
		}
		di := e.editDevice
		if di < 0 || di >= len(e.cfg.Devices) {
			e.errText = "no device selected"
			e.mode = modeList
			e.form = nil
			return
		}
		if e.editField >= 0 && e.editField < len(e.cfg.Devices[di].Fields) {
			e.cfg.Devices[di].Fields[e.editField] = f
		} else {
			e.cfg.Devices[di].Fields = append(e.cfg.Devices[di].Fields, f)
		}
		e.status = fmt.Sprintf("assigned %s on %s (unsaved)", f.Target, e.cfg.Devices[di].Name)
	}

	// Validate the whole document before it can be saved.
	if err := parser.ValidateConfig(e.cfg); err != nil {
		e.errText = err.Error()
	} else {
		e.errText = ""
	}
	e.mode = modeList
	e.form = nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// loadKeywords samples recent raw lines and extracts assignable tokens.
func (e *parsersEditor) loadKeywords() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lines, err := e.store.RecentRawLines(ctx, 60)
	if err != nil {
		e.errText = err.Error()
		return
	}
	e.rawLines = lines

	seen := map[string]bool{}
	e.tokens = nil
	for _, line := range lines {
		for _, m := range kvTokenRe.FindAllStringSubmatch(line, -1) {
			key, value := m[1], m[2]
			if seen[key] {
				continue
			}
			seen[key] = true
			e.tokens = append(e.tokens, keyword{
				key:      key,
				value:    value,
				guess:    guessTarget(key, value),
				strategy: "kv",
			})
		}
	}
	e.tokCur = 0
	if len(e.tokens) == 0 {
		e.tokErr = "no key=value tokens found in recent logs"
	} else {
		e.tokErr = ""
	}
	e.mode = modePreview
}

// guessTarget suggests a column from the token name and value shape.
func guessTarget(key, value string) string {
	lk := strings.ToLower(key)
	switch {
	case strings.Contains(lk, "src") && strings.Contains(lk, "ip"):
		return "src_ip"
	case strings.Contains(lk, "dst") && strings.Contains(lk, "ip"):
		return "dst_ip"
	case lk == "src" || lk == "srcip" || lk == "source":
		return "src_ip"
	case lk == "dst" || lk == "dstip" || lk == "dest":
		return "dst_ip"
	case strings.Contains(lk, "port") && strings.Contains(lk, "src"), lk == "spt":
		return "src_port"
	case strings.Contains(lk, "port"), lk == "dpt", lk == "dport":
		return "dst_port"
	case strings.Contains(lk, "proto"):
		return "proto"
	case strings.Contains(lk, "act") || strings.Contains(lk, "action"):
		return "action"
	case strings.Contains(lk, "mac"):
		if strings.Contains(lk, "client") || strings.Contains(lk, "sta") {
			return "client_mac"
		}
		return "mac"
	case strings.Contains(lk, "ssid"):
		return "ssid"
	case strings.Contains(lk, "signal"):
		return "signal_dbm"
	case strings.Contains(lk, "reason"):
		return "reason"
	case strings.Contains(lk, "vlan"):
		return "vlan_id"
	}
	if isIPv4(value) {
		return "src_ip"
	}
	if _, err := strconv.Atoi(value); err == nil {
		return "dst_port"
	}
	return "action"
}

var ipv4Shape = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

func isIPv4(v string) bool { return ipv4Shape.MatchString(v) }

// updateKeyword handles the token picker.
func (e *parsersEditor) updateKeyword(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "b":
		e.mode = modeList
		return nil
	case "up", "k":
		if e.tokCur > 0 {
			e.tokCur--
		}
	case "down", "j":
		if e.tokCur < len(e.tokens)-1 {
			e.tokCur++
		}
	case "enter", "a":
		if e.tokCur < len(e.tokens) {
			tok := e.tokens[e.tokCur]
			if e.cursor < 0 || e.cursor >= len(e.cfg.Devices) {
				e.errText = "add a device first (n)"
				e.mode = modeList
				return nil
			}
			e.startFieldForm(e.cursor, -1)
			// Pre-fill from the chosen keyword.
			vals := map[string]string{
				"target": tok.guess, "strategy": "kv", "key": tok.key,
			}
			for i := range e.form.fields {
				if v, ok := vals[e.form.fields[i].label]; ok {
					e.form.fields[i].value = v
				}
			}
		}
	}
	return nil
}

func (e *parsersEditor) save() {
	if err := e.file.Save(e.cfg, parser.EncodeConfig); err != nil {
		e.errText = err.Error()
		return
	}
	e.errText = ""
	e.status = "saved — parser reloads within 1s"
}

// view renders the parser screen.
func (e *parsersEditor) view(width, height int) string {
	switch e.mode {
	case modeForm:
		return "\n" + e.form.view(width)
	case modePreview:
		return e.viewKeywords(width, height)
	}
	return e.viewList(width, height)
}

func (e *parsersEditor) viewList(width, height int) string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("PARSERS") + styleDim.Render("  config/parsers.yaml — new log types, no rebuild"))
	b.WriteByte('\n')
	b.WriteString(styleDim.Render("n new · e edit · a add field · i assign keyword · x delete · s save · esc back"))
	b.WriteByte('\n')

	headers := []string{"NAME", "HOST MATCH", "TYPE", "FIELDS"}
	widths := []int{18, 30, 10, 6}
	rows := make([]string, 0, len(e.cfg.Devices))
	for i, d := range e.cfg.Devices {
		line := renderRow([]string{d.Name, strings.Join(d.HostnameMatch, ","), d.DeviceType,
			strconv.Itoa(len(d.Fields))}, widths, false)
		if i == e.cursor {
			line = styleSelected.Render(padWidth(d.Name, widths[0])) + "  " +
				padWidth(strings.Join(d.HostnameMatch, ","), widths[1]) + "  " +
				padWidth(d.DeviceType, widths[2]) + "  " + strconv.Itoa(len(d.Fields))
		}
		rows = append(rows, line)
	}
	if len(rows) == 0 {
		rows = []string{styleDim.Render("no device profiles — press n to add one")}
	}

	tableHeight := height - 8
	if tableHeight < 4 {
		tableHeight = 4
	}
	body, off := renderTable(headers, widths, rows, e.offset, tableHeight)
	e.offset = off

	b.WriteString(styleBorder.Width(width - 2).Render(body))
	b.WriteByte('\n')
	b.WriteString(e.statusLine())
	return b.String()
}

func (e *parsersEditor) viewKeywords(width, height int) string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("ASSIGN FROM KEYWORD"))
	b.WriteByte('\n')
	b.WriteString(styleDim.Render("pick a token found in recent logs, then choose its target column"))
	b.WriteByte('\n')
	if e.tokErr != "" {
		b.WriteString(styleError.Render(e.tokErr))
		b.WriteByte('\n')
	}
	if len(e.tokens) == 0 {
		b.WriteString("\n" + styleDim.Render("esc to return"))
		return styleBorder.Padding(1, 2).Render(b.String())
	}

	visible := height - 8
	if visible < 3 {
		visible = 3
	}
	start := 0
	if e.tokCur >= visible {
		start = e.tokCur - visible + 1
	}
	for i := start; i < len(e.tokens) && i < start+visible; i++ {
		t := e.tokens[i]
		line := fmt.Sprintf("%-16s = %-24s → %s", truncateWidth(t.key, 16),
			truncateWidth(t.value, 24), t.guess)
		if i == e.tokCur {
			line = styleSelected.Render(line)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString("\n" + styleDim.Render("enter assign · ↑↓ move · esc cancel"))
	return styleBorder.Padding(1, 2).Width(minInt(width-4, 90)).Render(b.String())
}

func (e *parsersEditor) statusLine() string {
	switch {
	case e.errText != "":
		return styleError.Render("error: " + truncateWidth(e.errText, 110))
	case e.status != "":
		return styleAccent.Render(e.status)
	default:
		return styleDim.Render("changes are not written until you press s")
	}
}
