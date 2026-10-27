package tui

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siskamlan/internal/store"
)

// sampleLogs builds a couple of entries covering pointer and string columns.
func sampleLogs() []*store.LogEntry {
	src := "10.0.0.5"
	v6 := "2001:db8::1"
	port := 443
	return []*store.LogEntry{
		{
			Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			Hostname:  "fw-1", Facility: "user", Severity: "info",
			DeviceType: "firewall", Event: "fw_block",
			SrcIP: &src, DstPort: &port, Action: "deny",
			RawLine: "raw line one",
		},
		{
			Timestamp: time.Date(2026, 1, 2, 3, 4, 6, 0, time.UTC),
			Hostname:  "fw-1", DeviceType: "firewall", Event: "fw_block",
			SrcIP: &v6, RawLine: "raw, line, with commas",
		},
	}
}

func sampleAnomalies() []store.AnomalyRow {
	score := 0.5
	return []store.AnomalyRow{
		{
			ID: 3, Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			WindowStart: time.Date(2026, 1, 2, 3, 3, 35, 0, time.UTC),
			WindowEnd:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			Severity:    "HIGH", Score: &score, RepeatCount: 2,
			Description: "[RULE] Port scan from 10.0.0.5",
			Features:    `{"type":"PORT_SCAN","entity":"10.0.0.5"}`,
		},
	}
}

// TestExportWritesBothFiles checks headers, row counts and values.
func TestExportWritesBothFiles(t *testing.T) {
	dir := t.TempDir()
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	res, err := Export(dir, sampleLogs(), sampleAnomalies(), stamp)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if res.LogRows != 2 || res.AnomalyRows != 1 {
		t.Fatalf("counts = %d/%d, want 2/1", res.LogRows, res.AnomalyRows)
	}
	for _, p := range []string{res.LogPath, res.AnomalyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing output %s: %v", p, err)
		}
	}

	logs := readCSV(t, res.LogPath)
	if len(logs) != 3 {
		t.Fatalf("log rows = %d, want header + 2", len(logs))
	}
	if strings.Join(logs[0], ",") != strings.Join(logHeader, ",") {
		t.Fatalf("log header = %v", logs[0])
	}
	// src_ip is column 6, and the second row carries an IPv6 address.
	if logs[1][6] != "10.0.0.5" {
		t.Fatalf("row 1 src_ip = %q", logs[1][6])
	}
	if logs[2][6] != "2001:db8::1" {
		t.Fatalf("row 2 src_ip = %q (IPv6 must survive export)", logs[2][6])
	}
	// A raw line containing commas must stay a single field.
	if !strings.Contains(logs[2][len(logHeader)-1], "raw, line, with commas") {
		t.Fatalf("raw_line not preserved: %q", logs[2][len(logHeader)-1])
	}

	anoms := readCSV(t, res.AnomalyPath)
	if len(anoms) != 2 {
		t.Fatalf("anomaly rows = %d, want header + 1", len(anoms))
	}
	if strings.Join(anoms[0], ",") != strings.Join(anomalyHeader, ",") {
		t.Fatalf("anomaly header = %v", anoms[0])
	}
	// type and entity are extracted from the features document.
	if anoms[1][7] != "PORT_SCAN" || anoms[1][8] != "10.0.0.5" {
		t.Fatalf("features columns = %q / %q", anoms[1][7], anoms[1][8])
	}
}

// TestExportNeverOverwrites checks a repeated export gets a suffix.
func TestExportNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	first, err := Export(dir, sampleLogs(), sampleAnomalies(), stamp)
	if err != nil {
		t.Fatalf("first export: %v", err)
	}
	second, err := Export(dir, sampleLogs(), sampleAnomalies(), stamp)
	if err != nil {
		t.Fatalf("second export: %v", err)
	}
	if first.LogPath == second.LogPath {
		t.Fatalf("second export reused %s", first.LogPath)
	}
	if !strings.Contains(filepath.Base(second.LogPath), "-1") {
		t.Fatalf("expected a numeric suffix, got %s", second.LogPath)
	}
}

// TestExportEmptyRowsStillWritesHeaders checks empty exports are valid CSVs.
func TestExportEmptyRowsStillWritesHeaders(t *testing.T) {
	dir := t.TempDir()
	res, err := Export(dir, nil, nil, time.Now())
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	logs := readCSV(t, res.LogPath)
	if len(logs) != 1 || strings.Join(logs[0], ",") != strings.Join(logHeader, ",") {
		t.Fatalf("expected header only, got %v", logs)
	}
	if res.LogRows != 0 || res.AnomalyRows != 0 {
		t.Fatalf("counts = %d/%d, want 0/0", res.LogRows, res.AnomalyRows)
	}
}

// TestExportCreatesDirectory checks the target directory is created.
func TestExportCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "exports")
	if _, err := Export(dir, sampleLogs(), nil, time.Now()); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("directory not created: %v", err)
	}
}

// readCSV loads a file for assertions.
func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return rows
}
