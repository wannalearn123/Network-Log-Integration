package store

import (
	"context"
	"fmt"
	"time"
)

// LogRow is the flattened shape the dashboard renders.
type LogRow struct {
	Timestamp  time.Time
	Hostname   string
	DeviceType string
	Event      string
	SrcIP      string
	DstIP      string
	Proto      string
	DstPort    *int
	Entity     string
}

// AnomalyRow is the flattened anomaly shape the dashboard renders.
type AnomalyRow struct {
	ID          int
	Timestamp   time.Time
	Severity    string
	Description string
	RepeatCount int
}

// Stats holds the header counters.
type Stats struct {
	TotalLogs      int
	LogsLastHour   int
	ActiveDevices  int
	TotalAnomalies int
	AnomaliesHour  int
	Critical       int
	High           int
	Medium         int
	Low            int
}

// RecentLogs returns the newest rows, optionally filtered by a substring.
func (s *Store) RecentLogs(ctx context.Context, limit int, search string) ([]LogRow, error) {
	if limit <= 0 {
		limit = 200
	}
	query := `SELECT timestamp, COALESCE(hostname,''), COALESCE(device_type,''),
	                 COALESCE(event,''), COALESCE(host(src_ip),''), COALESCE(host(dst_ip),''),
	                 COALESCE(proto,''), dst_port,
	                 COALESCE(client_mac, mac, host(dst_ip), '')
	          FROM logs`
	args := []any{}
	if search != "" {
		query += ` WHERE hostname ILIKE $1 OR event ILIKE $1 OR device_type ILIKE $1
		             OR host(src_ip) ILIKE $1 OR host(dst_ip) ILIKE $1
		             OR mac ILIKE $1 OR client_mac ILIKE $1 OR ssid ILIKE $1`
		args = append(args, "%"+search+"%")
	}
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT %d", limit)

	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: recent logs: %w", err)
	}
	defer rows.Close()

	out := make([]LogRow, 0, limit)
	for rows.Next() {
		var r LogRow
		if err := rows.Scan(&r.Timestamp, &r.Hostname, &r.DeviceType, &r.Event,
			&r.SrcIP, &r.DstIP, &r.Proto, &r.DstPort, &r.Entity); err != nil {
			return nil, fmt.Errorf("store: scan recent log: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecentAnomalies returns the newest detections, optionally filtered.
func (s *Store) RecentAnomalies(ctx context.Context, limit int, search string) ([]AnomalyRow, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, timestamp, COALESCE(severity,''), COALESCE(description,''),
	                 COALESCE((features->>'repeat_count')::int, 1)
	          FROM anomalies`
	args := []any{}
	if search != "" {
		query += ` WHERE description ILIKE $1 OR severity ILIKE $1`
		args = append(args, "%"+search+"%")
	}
	query += fmt.Sprintf(" ORDER BY id DESC LIMIT %d", limit)

	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: recent anomalies: %w", err)
	}
	defer rows.Close()

	out := make([]AnomalyRow, 0, limit)
	for rows.Next() {
		var r AnomalyRow
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.Severity, &r.Description, &r.RepeatCount); err != nil {
			return nil, fmt.Errorf("store: scan recent anomaly: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Stats computes the header counters in one round trip.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	err := s.Pool.QueryRow(ctx, `
		SELECT
		  (SELECT COUNT(*) FROM logs),
		  (SELECT COUNT(*) FROM logs WHERE timestamp >= NOW() - INTERVAL '1 hour'),
		  (SELECT COUNT(DISTINCT hostname) FROM logs WHERE timestamp >= NOW() - INTERVAL '5 minutes'),
		  (SELECT COUNT(*) FROM anomalies),
		  (SELECT COUNT(*) FROM anomalies WHERE timestamp >= NOW() - INTERVAL '1 hour'),
		  (SELECT COUNT(*) FROM anomalies WHERE severity = 'CRITICAL'),
		  (SELECT COUNT(*) FROM anomalies WHERE severity = 'HIGH'),
		  (SELECT COUNT(*) FROM anomalies WHERE severity = 'MEDIUM'),
		  (SELECT COUNT(*) FROM anomalies WHERE severity = 'LOW')
	`).Scan(&st.TotalLogs, &st.LogsLastHour, &st.ActiveDevices,
		&st.TotalAnomalies, &st.AnomaliesHour,
		&st.Critical, &st.High, &st.Medium, &st.Low)
	if err != nil {
		return Stats{}, fmt.Errorf("store: stats: %w", err)
	}
	return st, nil
}

// RecentRawLines returns distinct recent raw lines, for the parser editor.
func (s *Store) RecentRawLines(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT raw_line FROM (
			SELECT DISTINCT ON (left(raw_line, 60)) raw_line, timestamp
			FROM logs WHERE raw_line IS NOT NULL AND raw_line <> ''
			ORDER BY left(raw_line, 60), timestamp DESC
		) t ORDER BY timestamp DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: recent raw lines: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, fmt.Errorf("store: scan raw line: %w", err)
		}
		out = append(out, line)
	}
	return out, rows.Err()
}
