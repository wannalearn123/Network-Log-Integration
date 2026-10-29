package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"siskamlan/internal/config"
	"siskamlan/internal/parser"
	"siskamlan/internal/store"
)

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

	// selectedFile is a path to a .log file in data/syslog/
	// when set, loadCandidates reads from that file instead of the DB.
	selectedFile string

	rawLines   []string
	candidates []candidate
	tokCur     int
	tokErr     string

	// sample holds the newest raw lines, shown on the list screen so the
	// operator can see what is arriving before writing a profile.
	sample    []string
	sampleErr string
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
	e.loadFileSample()
	e.mode = modeList
	e.status = ""
	e.errText = ""
}

// loadFileSample reads the tail (3-5 lines) of the selected file in
// data/syslog/. If no file is selected it shows nothing yet.
func (e *parsersEditor) loadFileSample() {
	e.sample = nil
	e.sampleErr = ""
	if e.selectedFile == "" {
		return
	}
	raw, err := os.ReadFile(e.selectedFile)
	if err != nil {
		e.sampleErr = err.Error()
		return
	}
	lines := strings.Split(string(raw), "\n")
	start := 0
	if len(lines) > 3 {
		start = len(lines) - 3 // take last 3 lines (tail)
	}
	for i := start; i < len(lines) && len(e.sample) < 5; i++ {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			e.sample = append(e.sample, line)
		}
	}
	if len(e.sample) == 0 {
		e.sampleErr = "file is empty"
	}
}

func (e *parsersEditor) refreshFromFile() {
	if cfg, ok := e.file.Current(); ok {
		e.cfg = cfg
	}
	if e.cursor >= len(e.cfg.Devices) {
		e.cursor = maxInt(0, len(e.cfg.Devices)-1)
	}
}

// updateForm handles the assignment form.
//
// Cycling the strategy rebuilds the form around the new strategy, so the
// inputs on screen always match what the parser will read. Without this the
// operator picks "regex" and still only sees key/keys, which is how a rule
// ends up with a pattern that was never typed.
func (e *parsersEditor) updateForm(msg tea.KeyMsg) tea.Cmd {
	strategyBefore := ""
	if f := fieldByLabel(e.form, "strategy"); f != nil {
		strategyBefore = f.value
	}
	done, cancel := e.form.update(msg)
	if cancel {
		e.mode = modeList
		e.form = nil
		return nil
	}
	if done {
		e.applyForm()
		return nil
	}
	if f := fieldByLabel(e.form, "strategy"); f != nil && f.value != strategyBefore {
		e.rebuildFieldForm()
	}
	return nil
}

// rebuildFieldForm swaps in the inputs for the newly selected strategy while
// carrying over the values that still apply.
func (e *parsersEditor) rebuildFieldForm() {
	v := e.form.values()
	strategy := v["strategy"]
	next := e.fieldForm(parser.FieldRule{
		Target:   v["target"],
		Strategy: strategy,
		Key:      strings.TrimSpace(v["key"]),
		Keys:     splitList(v["keys"]),
		Pattern:  strings.TrimSpace(v["pattern"]),
		Source:   strings.TrimSpace(v["source"]),
		Map:      textToMap(v["map"]),
		Pos:      v["pos"],
		Type:     v["type"],
	})
	// Keep the cursor on the strategy row so ←→ keeps cycling.
	for i := range next.fields {
		if next.fields[i].label == "strategy" {
			next.cursor = i
			break
		}
	}
	e.form = next
}

func (e *parsersEditor) update(msg tea.KeyMsg) tea.Cmd {
	switch e.mode {
	case modeForm:
		return e.updateForm(msg)
	case modePreview: // reused for the candidate picker
		return e.updateKeyword(msg)
	}
	return e.updateList(msg)
}

func (e *parsersEditor) updateList(msg tea.KeyMsg) tea.Cmd {
	files, _ := filepath.Glob("data/syslog/*.log")
	if len(files) == 0 {
		files, _ = filepath.Glob("/mnt/DATA/PROJECT/Monitoring System.bak/data/syslog/*.log")
	}
	switch msg.String() {
	case "esc", "b":
		if e.selectedFile != "" {
			e.selectedFile = ""
			e.loadFileSample()
			e.cursor = 0
			return nil
		}
		return func() tea.Msg { return closeEditorMsg{} }
	case "up", "k":
		if e.cursor > 0 {
			e.cursor--
		}
	case "down", "j":
		if e.selectedFile == "" && len(files) > 0 {
			if e.cursor < len(files)-1 {
				e.cursor++
			}
		} else if e.cursor < len(e.cfg.Devices)-1 {
			e.cursor++
		}
	case "n":
		e.startDeviceForm(-1)
	case "e", "enter":
		if e.selectedFile == "" && len(files) > 0 {
			// Select a file from the list
			e.selectedFile = files[e.cursor]
			e.loadFileSample()
			e.mode = modeList
			e.status = "selected file " + filepath.Base(e.selectedFile) + " (tail shown)"
		} else if e.selectedFile != "" && e.cursor < len(e.cfg.Devices) {
			e.startDeviceForm(e.cursor)
		} else if e.selectedFile != "" {
			// No device to edit; move cursor
			e.cursor++
		} else if e.cursor < len(e.cfg.Devices) {
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
		e.loadCandidates()
	case "p":
		e.showPreview()
	case "r":
		e.open()
		e.status = "reloaded " + time.Now().Format("15:04:05")
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
	suggest := ""
	if e.selectedFile != "" {
		suggest = hostnameSuggest(e.selectedFile)
	}
	hm := strings.Join(d.HostnameMatch, ", ")
	if hm == "" && suggest != "" {
		// Seed from the file the operator is looking at; a profile with no
		// hostname_match silently never matches, which is the single most
		// common way a parser appears "broken".
		hm = suggest
	}
	e.form = newForm("Device profile", []formField{
		{label: "name", kind: kindText, value: orDefault(d.Name, "new-device"),
			help: "a label only — used in messages, not for matching"},
		{label: "hostname_match", kind: kindList, value: hm,
			help: "REQUIRED: regex list, comma-separated, tested against hostname; first match wins"},
		{label: "device_type", kind: kindEnum, value: dt,
			options: []string{"other", "router", "switch", "ap", "firewall", "syslog"},
			help:    "sets the device_type column and enables built-in heuristics"},
	})
	e.form.subtitle = "hostname_match decides whether this profile runs at all; without it nothing is applied."
	e.mode = modeForm
}

// hostnameSuggest derives a hostname_match regex from a sample line so the
// operator starts from a value that actually matches the file in front of
// them instead of an empty field.
func hostnameSuggest(file string) string {
	base := filepath.Base(file)
	base = strings.TrimSuffix(base, ".log")
	// data/syslog/<hostname>.log -> ^<hostname>$ escaped for regex.
	if base == "" {
		return ""
	}
	return "^" + regexp.QuoteMeta(base) + "$"
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

// fieldForm builds the assignment form for one field rule.
//
// Only the inputs the chosen strategy actually reads are shown. The old form
// listed key/keys/pattern/source/map/pos for every strategy, which is how a
// `kv` rule ended up carrying a `pos` and a switch MAC got saved as
// `key: Host` — a combination the parser silently ignores.
func (e *parsersEditor) fieldForm(f parser.FieldRule) *form {
	strategy := orDefault(f.Strategy, "kv")
	fields := []formField{
		{label: "target", kind: kindEnum, value: orDefault(f.Target, "src_ip"), options: parser.TargetColumns,
			help: "the column this value is written to"},
		{label: "strategy", kind: kindEnum, value: strategy, options: parser.Strategies,
			help: "kv: key=value · regex: capture group 1 · word_map: translate · positional: first/last token"},
	}
	switch strategy {
	case "kv":
		fields = append(fields,
			formField{label: "key", kind: kindText, value: f.Key,
				help: "the KEY in KEY=value — not a bare word like 'Host'"},
			formField{label: "keys", kind: kindList, value: strings.Join(f.Keys, ", "),
				help: "fallback keys, tried in order"},
		)
	case "regex":
		fields = append(fields,
			formField{label: "pattern", kind: kindText, value: f.Pattern,
				help: "capture group 1 is the value; anchor on surrounding words"},
		)
	case "word_map":
		fields = append(fields,
			formField{label: "source", kind: kindText, value: f.Source,
				help: "existing column to translate"},
			formField{label: "map", kind: kindText, value: mapToText(f.Map),
				help: "from=to, from=to"},
		)
	case "positional":
		fields = append(fields,
			formField{label: "pos", kind: kindEnum, value: orDefault(f.Pos, "first"), options: []string{"first", "last"},
				help: "take the first or last value-like token in the line"},
		)
	}
	fields = append(fields, formField{label: "type", kind: kindEnum, value: orDefault(f.Type, ""),
		options: []string{"", "string", "int", "ip"},
		help:    "coerce the value; empty keeps the extracted text"})

	fm := newForm("Field assignment", fields)
	fm.subtitle = "Only the inputs for the chosen strategy are shown; ←→ on strategy rebuilds this form."
	return fm
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
		hm := splitList(v["hostname_match"])
		if len(hm) == 0 {
			// Refuse rather than save a profile that can never match: it
			// looks correct in the list but does nothing to incoming lines.
			e.errText = "hostname_match is required — a profile without it never matches any host"
			e.mode = modeList
			e.form = nil
			return
		}
		d := parser.Device{
			Name:          strings.TrimSpace(v["name"]),
			DeviceType:    v["device_type"],
			HostnameMatch: hm,
		}
		if d.Name == "" {
			e.errText = "name is required"
			e.mode = modeList
			e.form = nil
			return
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
		// Build only the inputs the chosen strategy reads, so a rule never
		// carries meaningless fields (kv + pos, regex + key, ...).
		f := parser.FieldRule{
			Target:   v["target"],
			Strategy: v["strategy"],
		}
		switch f.Strategy {
		case "kv":
			f.Key = strings.TrimSpace(v["key"])
			f.Keys = splitList(v["keys"])
		case "regex":
			f.Pattern = strings.TrimSpace(v["pattern"])
		case "word_map":
			f.Source = strings.TrimSpace(v["source"])
			f.Map = textToMap(v["map"])
		case "positional":
			f.Pos = v["pos"]
		}
		f.Type = v["type"]

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

	e.errText = e.validateCfg()
	e.mode = modeList
	e.form = nil
}

// validateCfg returns the config error text, or "" when the document is
// valid. It is used after every edit so a bad rule is reported immediately
// instead of at save time.
func (e *parsersEditor) validateCfg() string {
	if err := parser.ValidateConfig(e.cfg); err != nil {
		return err.Error()
	}
	return ""
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

// loadCandidates reads the selected file and derives every field rule the
// editor can offer for it.
//
// It is no longer kv-only: vendors such as switches, routers, and APs emit
// prose like `Host aabb.ccdd.eeff learned on Gi0/2 vlan 12`, which has no
// `=` at all. Those lines are covered by the anchored regex extractors and
// by positional fallbacks, so the picker is never empty.
func (e *parsersEditor) loadCandidates() {
	if e.selectedFile == "" {
		e.tokErr = "select a file first (up/down on list, enter)"
		return
	}
	raw, err := os.ReadFile(e.selectedFile)
	if err != nil {
		e.errText = err.Error()
		return
	}
	e.rawLines = strings.Split(string(raw), "\n")

	// Sample a spread of lines rather than only the head: vendor logs
	// interleave several message shapes and the head may miss them.
	lines := sampleLines(e.rawLines, 400)
	e.candidates = buildCandidates(lines)

	e.tokCur = 0
	if len(e.candidates) == 0 {
		e.tokErr = "no assignable values found — the file may be empty or unrecognised"
	} else {
		e.tokErr = ""
	}
	e.mode = modePreview
}

// sampleLines returns up to max non-empty lines, evenly spread across the
// file so every message shape has a chance to contribute candidates.
func sampleLines(all []string, max int) []string {
	var clean []string
	for _, l := range all {
		if l = strings.TrimSpace(l); l != "" {
			clean = append(clean, l)
		}
	}
	if len(clean) <= max {
		return clean
	}
	out := make([]string, 0, max)
	step := float64(len(clean)) / float64(max)
	for i := 0; i < max; i++ {
		out = append(out, clean[int(float64(i)*step)])
	}
	return out
}

// guessTarget suggests a column from the token name and value shape.
//
// A wrong guess is worse than no guess: the operator accepts the pre-filled
// form, and the value lands in a column nothing reads. So the name is matched
// from most to least specific, and the fallback leaves the column alone
// rather than defaulting to src_ip/action.
func guessTarget(key, value string) string {
	lk := strings.ToLower(strings.TrimSpace(key))

	// Network identity keys first: they must win over the port/action rules.
	switch {
	case lk == "gateway" || lk == "gw" || lk == "nexthop" || lk == "next-hop":
		return "gateway"
	case strings.Contains(lk, "dst") && strings.Contains(lk, "addr"),
		lk == "dst" || lk == "dstip" || lk == "dst_ip" || lk == "dest" ||
			lk == "daddr" || lk == "to":
		return "dst_ip"
	case strings.Contains(lk, "src") && strings.Contains(lk, "addr"),
		lk == "src" || lk == "srcip" || lk == "src_ip" || lk == "source" ||
			lk == "saddr" || lk == "from":
		return "src_ip"
	case lk == "spt" || lk == "sport" || lk == "srcport" || lk == "src-port":
		return "src_port"
	case lk == "dpt" || lk == "dport" || lk == "dstport" || lk == "dst-port":
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
	case strings.Contains(lk, "signal") || strings.Contains(lk, "rssi"):
		return "signal_dbm"
	case strings.Contains(lk, "reason"):
		return "reason"
	case strings.Contains(lk, "vlan"):
		return "vlan_id"
	case strings.Contains(lk, "ifname") || lk == "interface" || lk == "iface" || lk == "port-name":
		return "ifname"
	}

	// Shape-based fallback, only for unambiguous shapes. A bare integer is
	// NOT a port: it is far more often an id, a count, or a status.
	switch {
	case isIPv4(value):
		return "src_ip"
	case ipv4Shape.MatchString(value) && strings.Contains(value, "/"):
		return "route_dst"
	}
	return ""
}

var ipv4Shape = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

func isIPv4(v string) bool { return ipv4Shape.MatchString(v) }

// updateKeyword handles the candidate picker.
//
// Selecting a candidate opens the assignment form pre-filled with that
// candidate's actual strategy, key/pattern, and type, with a live preview of
// the value it extracts — so the saved rule is one the parser can execute.
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
		if e.tokCur < len(e.candidates)-1 {
			e.tokCur++
		}
	case "enter", "a":
		if e.tokCur < len(e.candidates) {
			cand := e.candidates[e.tokCur]
			if e.cursor < 0 || e.cursor >= len(e.cfg.Devices) {
				e.errText = "add a device first (n)"
				e.mode = modeList
				return nil
			}
			if cand.needsTarget {
				// The value's column could not be inferred. Open the form so
				// the operator picks one; guessing here is how a value ends
				// up in a column nothing reads.
				e.startFieldForm(e.cursor, -1)
				fieldByLabel(e.form, "strategy").value = cand.strategy
				e.rebuildFieldForm()
				if f := fieldByLabel(e.form, "pos"); f != nil {
					f.value = cand.pos
				}
				if f := fieldByLabel(e.form, "type"); f != nil && cand.typ != "" {
					f.value = cand.typ
				}
				e.form.subtitle = fmt.Sprintf("pick a target column for %q — %s",
					cand.sample, cand.origin)
				return nil
			}
			if err := e.addCandidateRule(e.cursor, cand); err != nil {
				e.errText = err.Error()
				e.mode = modeList
				return nil
			}
			e.startFieldForm(e.cursor, len(e.cfg.Devices[e.cursor].Fields)-1)
			e.form.subtitle = fmt.Sprintf("from %s · preview: %s → %s",
				cand.origin, cand.target, cand.preview())
		}
	}
	return nil
}

// addCandidateRule appends the rule a candidate describes and immediately
// verifies it against the sampled lines. A rule that matches nothing is
// rejected instead of being saved as a silent no-op.
func (e *parsersEditor) addCandidateRule(deviceIdx int, cand candidate) error {
	if deviceIdx < 0 || deviceIdx >= len(e.cfg.Devices) {
		return fmt.Errorf("no device selected")
	}
	rule := cand.rule()
	if err := parser.ValidateConfig(parser.Config{
		Version: e.cfg.Version,
		Devices: []parser.Device{{
			Name:          e.cfg.Devices[deviceIdx].Name,
			HostnameMatch: []string{"."},
			Fields:        []parser.FieldRule{rule},
		}},
	}); err != nil {
		return fmt.Errorf("rule rejected: %w", err)
	}
	if err := verifyRule(rule, e.sample); err != nil {
		return err
	}
	e.cfg.Devices[deviceIdx].Fields = append(e.cfg.Devices[deviceIdx].Fields, rule)
	e.status = fmt.Sprintf("assigned %s via %s on %s (unsaved)",
		rule.Target, rule.Strategy, e.cfg.Devices[deviceIdx].Name)
	return nil
}

// showPreview parses the selected file's first sample line with the current
// unsaved config and reports the result in the status line.
//
// The pane already shows this live; `p` also validates the document, so a
// broken rule cannot be previewed as if it worked.
func (e *parsersEditor) showPreview() {
	if e.selectedFile == "" {
		e.errText = "select a file first (up/down on the file list, enter)"
		return
	}
	if len(e.sample) == 0 {
		e.errText = "no sample lines in " + filepath.Base(e.selectedFile)
		return
	}
	if msg := e.validateCfg(); msg != "" {
		e.errText = msg
		return
	}
	rows, err := previewLine(e.cfg, e.sample[0])
	if err != nil {
		e.errText = err.Error()
		return
	}
	if len(rows) == 0 {
		e.errText = "profile produced no columns for this line"
		return
	}
	e.errText = ""
	e.status = fmt.Sprintf("preview: %d columns from %s (%d device profiles)",
		len(rows), filepath.Base(e.selectedFile), len(e.cfg.Devices))
}

func (e *parsersEditor) save() {
	// Refuse to write a document the parser would reject; the file keeps the
	// last good contents and the editor shows why.
	if msg := e.validateCfg(); msg != "" {
		e.errText = "not saved — " + msg
		return
	}
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
	b.WriteString(truncateWidth(styleBrand.Render("◈ PARSERS")+
		styleDim.Render("   config/parsers.yaml — new log types, no rebuild"), width-1))
	b.WriteByte('\n')

	// Discover files in data/syslog/
	files, _ := filepath.Glob("data/syslog/*.log")
	if len(files) == 0 {
		files, _ = filepath.Glob("/mnt/DATA/PROJECT/Monitoring System.bak/data/syslog/*.log")
	}

	if e.selectedFile == "" && len(files) > 0 {
		// File selection mode: show available log files
		hint := "enter select file · n new device · s save · r reload · esc back"
		if width < 78 {
			hint = "enter file · n device · s save · esc"
		}
		b.WriteString(styleDim.Render(truncateWidth(hint, width-1)))
		b.WriteByte('\n')

		rows := make([]string, len(files))
		for i, f := range files {
			line := filepath.Base(f) + "  (press enter to view tail)"
			if i == e.cursor {
				rows[i] = styleSelected.Render(line)
			} else {
				rows[i] = styleDim.Render(line)
			}
		}
		if len(rows) == 0 {
			rows = []string{styleDim.Render("no .log files in data/syslog/")}
		}

		tableHeight := height - 6
		if tableHeight < 4 {
			tableHeight = 4
		}
		body, off := renderTable([]string{"FILE"}, []int{width - 8}, rows, e.offset, tableHeight)
		e.offset = off
		b.WriteString(panel("", body, width, tableHeight+4, true))
		b.WriteByte('\n')
		b.WriteString(e.statusLine(width))
		return b.String()
	}

	// Device/profile mode: show devices and selected file's tail
	hint := "n new · e edit · a add field · i pick from file · p preview · x delete · s save · r reload · esc back"
	if width < 78 {
		hint = "n new · e edit · a field · i pick · p preview · s save · esc"
	}
	b.WriteString(styleDim.Render(truncateWidth(hint, width-1)))
	b.WriteByte('\n')

	avail := width - 8
	sets := [][]col{
		{{"NAME", 16, true}, {"HOST MATCH", 24, true}, {"TYPE", 10, false}, {"FIELDS", 6, false}, {"MATCHES", 7, false}},
		{{"NAME", 16, true}, {"HOST MATCH", 18, true}, {"FIELDS", 6, false}, {"MATCHES", 7, false}},
		{{"NAME", 16, true}, {"HOST MATCH", 14, true}},
	}
	headers, widths, ok := fitCols(sets, avail)
	if !ok {
		headers = []string{"NAME"}
		widths = []int{maxIntOf(10, avail)}
	}
	rows := make([]string, 0, len(e.cfg.Devices))
	for i, d := range e.cfg.Devices {
		cells := make([]string, len(headers))
		for j, h := range headers {
			switch h {
			case "NAME":
				cells[j] = d.Name
			case "HOST MATCH":
				hm := strings.Join(d.HostnameMatch, ",")
				if hm == "" {
					// An empty matcher means the profile is inert; say so
					// rather than showing a blank cell.
					hm = "! never matches"
				}
				cells[j] = hm
			case "TYPE":
				cells[j] = d.DeviceType
			case "FIELDS":
				cells[j] = strconv.Itoa(len(d.Fields))
			case "MATCHES":
				cells[j] = e.matchMark(d)
			}
		}
		rows = append(rows, styledRow(cells, widths, i == e.cursor))
	}
	if len(rows) == 0 {
		rows = []string{
			styleDim.Render("no profiles — the built-in parser is handling every line"),
			styleDim.Render("n adds an override profile · select a file first (press r to see files)"),
		}
	}

	// Reserve room for the raw-line sample from the selected file
	sampleRows := len(e.sampleView(width, 5))
	tableHeight := height - 8 - sampleRows
	if tableHeight < 4 {
		tableHeight = 4
	}
	body, off := renderTable(headers, widths, rows, e.offset, tableHeight)
	e.offset = off

	b.WriteString(panel("", body, width, tableHeight+4, true))
	b.WriteByte('\n')
	for _, line := range e.sampleView(width, 5) {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString(e.statusLine(width))
	return b.String()
}

// matchMark reports whether the cursor's profile matches the hostnames in
// the selected file, so an inert profile is visible at a glance.
func (e *parsersEditor) matchMark(d parser.Device) string {
	if len(d.HostnameMatch) == 0 {
		return "no"
	}
	if len(e.sample) == 0 {
		return "?"
	}
	cfg := parser.Config{Version: 1, Devices: []parser.Device{{
		Name:          d.Name,
		HostnameMatch: d.HostnameMatch,
		DeviceType:    d.DeviceType,
		Fields:        d.Fields,
		Events:        d.Events,
	}}}
	p, err := parser.NewParser(&cfg)
	if err != nil {
		return "err"
	}
	for _, line := range e.sample {
		base := parser.Parse(line)
		if base == nil {
			continue
		}
		out := p.Parse(line)
		if out != nil && (out.DeviceType != base.DeviceType || len(entryRows(out)) > len(entryRows(base))) {
			return "yes"
		}
	}
	return "no"
}

// sampleView renders the preview pane: the newest raw lines from the
// selected file, and what the current (unsaved) profile makes of the first
// one. It always returns at least one line so the layout stays stable.
func (e *parsersEditor) sampleView(width, max int) []string {
	title := "RECENT RAW"
	note := "   newest first, from logs.raw_line"
	if e.selectedFile != "" {
		title = "SAMPLE → PARSED"
		note = "   " + filepath.Base(e.selectedFile)
	}
	out := []string{styleAccent.Render(title) + styleDim.Render(note)}

	if e.selectedFile != "" {
		switch {
		case e.sampleErr != "":
			out = append(out, styleError.Render(truncateWidth("! "+e.sampleErr, width-1)))
		case len(e.sample) == 0:
			out = append(out, styleDim.Render("   file is empty"))
		default:
			// Show the parsed result, not just the raw text: this is the
			// difference between guessing and knowing the rule works.
			rows, err := previewLine(e.cfg, e.sample[0])
			if err != nil {
				out = append(out, styleError.Render(truncateWidth("! preview: "+err.Error(), width-1)))
			}
			out = append(out, styleDim.Render(truncateWidth("   ↳ "+cleanRawLine(e.sample[0]), width-1)))
			if len(rows) == 0 {
				out = append(out, styleDim.Render("   (profile produced no columns)"))
			}
			for _, r := range rows {
				if len(out) > max {
					break
				}
				out = append(out, styleText.Render(truncateWidth(
					fmt.Sprintf("     %-14s %s", r.column, r.value), width-1)))
			}
		}
		return out
	}

	if e.store == nil {
		return out
	}
	switch {
	case e.sampleErr != "":
		out = append(out, styleError.Render(truncateWidth("! "+e.sampleErr, width-1)))
	case len(e.sample) == 0:
		out = append(out, styleDim.Render("   nothing ingested yet — check the pipeline and data/syslog"))
	default:
		for _, line := range e.sample {
			if len(out) > max {
				break
			}
			out = append(out, styleDim.Render(truncateWidth("   "+cleanRawLine(line), width-1)))
		}
	}
	return out
}

// cleanRawLine makes a raw log line safe to draw: tabs and control characters
// would otherwise break column alignment or the terminal.
func cleanRawLine(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			// drop control characters
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (e *parsersEditor) viewKeywords(width, height int) string {
	var b strings.Builder
	b.WriteString(styleBrand.Render("◈ ASSIGN FROM SAMPLE LINES"))
	b.WriteByte('\n')
	b.WriteString(styleDim.Render("pick a value found in the selected file; the rule and its extraction are shown"))
	b.WriteByte('\n')
	if e.tokErr != "" {
		b.WriteString(styleError.Render(e.tokErr))
		b.WriteByte('\n')
	}
	if len(e.candidates) == 0 {
		b.WriteString("\n" + styleDim.Render("esc to return"))
		return modalBox(b.String(), 80)
	}

	visible := height - 8
	if visible < 3 {
		visible = 3
	}
	start := 0
	if e.tokCur >= visible {
		start = e.tokCur - visible + 1
	}
	for i := start; i < len(e.candidates) && i < start+visible; i++ {
		c := e.candidates[i]
		// Show strategy and target so the operator sees what will be saved,
		// not just a pretty value.
		target := c.target
		if target == "" {
			target = "(pick one)"
		}
		line := fmt.Sprintf("%-9s %-12s %-30s → %s", c.strategy, target,
			truncateWidth(c.label, 30), truncateWidth(c.preview(), 20))
		if i == e.tokCur {
			line = styleSelected.Render(line)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString("\n" + styleDim.Render("enter assign · ↑↓ move · esc cancel"))
	return modalBox(b.String(), minInt(width-6, 100))
}

func (e *parsersEditor) statusLine(width int) string {
	switch {
	case e.errText != "":
		return styleError.Render(truncateWidth("error: "+e.errText, width-1))
	case e.status != "":
		return styleAccent.Render(truncateWidth(e.status, width-1))
	default:
		return styleDim.Render(truncateWidth("changes are not written until you press s", width-1))
	}
}
