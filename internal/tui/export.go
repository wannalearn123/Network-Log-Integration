package tui

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"siskamlan/internal/store"
)

// logHeader is the CSV column order for exported logs.
var logHeader = []string{
	"timestamp", "hostname", "facility", "severity", "device_type", "event",
	"src_ip", "dst_ip", "proto", "dst_port", "src_port", "action",
	"mac", "vlan_id", "ifname", "peer_ifname", "stp_root",
	"client_mac", "ssid", "radio", "reason", "signal_dbm", "tx_rate_mbps",
	"eap_status", "ospf_nbr", "gateway", "route_dst", "dhcp_mac",
	"conntrack_count", "raw_line",
}

// anomalyHeader is the CSV column order for exported anomalies.
var anomalyHeader = []string{
	"id", "timestamp", "window_start", "window_end", "severity",
	"anomaly_score", "repeat_count", "type", "entity", "description",
}

// ExportResult describes files written by an export.
type ExportResult struct {
	LogPath     string
	AnomalyPath string
	LogRows     int
	AnomalyRows int
}

// Export writes the supplied rows to two timestamped CSV files under dir.
//
// Files are created only when called, so cancelling the confirmation prompt
// writes nothing. Existing files are never overwritten: a numeric suffix is
// added when the name is taken.
func Export(dir string, logs []*store.LogEntry, anomalies []store.AnomalyRow,
	stamp time.Time) (ExportResult, error) {

	if dir == "" {
		dir = "exports"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ExportResult{}, fmt.Errorf("export: create %s: %w", dir, err)
	}
	name := "logs-" + stamp.Format("20060102-150405")

	logPath, err := unusedPath(dir, name, ".csv")
	if err != nil {
		return ExportResult{}, err
	}
	anomPath, err := unusedPath(dir, name+"-anomalies", ".csv")
	if err != nil {
		return ExportResult{}, err
	}

	if err := writeLogCSV(logPath, logs); err != nil {
		return ExportResult{}, err
	}
	if err := writeAnomalyCSV(anomPath, anomalies); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{
		LogPath: logPath, AnomalyPath: anomPath,
		LogRows: len(logs), AnomalyRows: len(anomalies),
	}, nil
}

// unusedPath finds a free filename, appending -1, -2 ... when needed.
func unusedPath(dir, base, ext string) (string, error) {
	for i := 0; i < 1000; i++ {
		candidate := filepath.Join(dir, base+ext)
		if i > 0 {
			candidate = filepath.Join(dir, base+"-"+strconv.Itoa(i)+ext)
		}
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		} else if err != nil {
			return "", fmt.Errorf("export: stat %s: %w", candidate, err)
		}
	}
	return "", fmt.Errorf("export: no free filename for %s in %s", base, dir)
}

// writeLogCSV streams log rows to path.
func writeLogCSV(path string, logs []*store.LogEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("export: create %s: %w", path, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write(logHeader); err != nil {
		return fmt.Errorf("export: write header: %w", err)
	}
	for _, e := range logs {
		if err := w.Write(logRecord(e)); err != nil {
			return fmt.Errorf("export: write row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("export: flush %s: %w", path, err)
	}
	return f.Sync()
}

// logRecord renders one entry in logHeader order.
func logRecord(e *store.LogEntry) []string {
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	num := func(p *int) string {
		if p == nil {
			return ""
		}
		return strconv.Itoa(*p)
	}
	return []string{
		e.Timestamp.Format(time.RFC3339),
		e.Hostname, e.Facility, e.Severity, e.DeviceType, e.Event,
		str(e.SrcIP), str(e.DstIP), e.Proto, num(e.DstPort), num(e.SrcPort),
		e.Action,
		e.MAC, num(e.VLANID), e.IfName, e.PeerIfName, e.STPRoot,
		e.ClientMAC, e.SSID, e.Radio, num(e.Reason), num(e.SignalDBM),
		num(e.TxRateMbps), e.EAPStatus, str(e.OSPFNbr), str(e.Gateway),
		e.RouteDst, e.DHCPMAC, num(e.ConntrackCt),
		e.RawLine,
	}
}

// writeAnomalyCSV streams detections to path.
func writeAnomalyCSV(path string, anomalies []store.AnomalyRow) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("export: create %s: %w", path, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write(anomalyHeader); err != nil {
		return fmt.Errorf("export: write header: %w", err)
	}
	for _, a := range anomalies {
		score := ""
		if a.Score != nil {
			score = strconv.FormatFloat(*a.Score, 'f', -1, 64)
		}
		rec := []string{
			strconv.Itoa(a.ID),
			a.Timestamp.Format(time.RFC3339),
			a.WindowStart.Format(time.RFC3339),
			a.WindowEnd.Format(time.RFC3339),
			a.Severity, score,
			strconv.Itoa(a.RepeatCount),
			jsonField(a.Features, "type"),
			jsonField(a.Features, "entity"),
			a.Description,
		}
		if err := w.Write(rec); err != nil {
			return fmt.Errorf("export: write row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("export: flush %s: %w", path, err)
	}
	return f.Sync()
}

// jsonField reads one key out of the stored features document.
func jsonField(features, key string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(features), &m); err != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
