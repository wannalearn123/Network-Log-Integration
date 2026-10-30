package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// AnomalyRow is the flattened anomaly shape the dashboard renders.
type AnomalyRow struct {
	ID          int
	Timestamp   time.Time
	Severity    string
	Description string
	RepeatCount int
	WindowStart time.Time
	WindowEnd   time.Time
	Score       *float64
	Features    string
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

// SourceCount is one entry in the security overview.
type SourceCount struct {
	Source string
	Count  int
}

// TypeCount is one entry in the detection breakdown.
type TypeCount struct {
	Type  string
	Count int
}

// timestampText renders a TIMESTAMPTZ exactly as the dashboard displays it
// ("2006-01-02 15:04:05"). Casting through to_char keeps the filter working on
// a plain substring: "2026-10-29", "14:2" and "2026-10-29 14:23" all match,
// without the TUI having to parse the term into a range.
const timestampText = `to_char(timestamp, 'YYYY-MM-DD HH24:MI:SS')`

// recentLogsSelect mirrors buildWindowSelect but omits the time filter and uses
// the caller's ordering, so the dashboard can page through history.
func recentLogsSelect(withFilter bool, limit int) string {
	var b strings.Builder
	b.WriteString("SELECT ")
	for i, c := range LogColumns {
		if i > 0 {
			b.WriteString(", ")
		}
		if inetColumns[c] {
			b.WriteString("host(" + c + ") AS " + c)
		} else {
			b.WriteString(c)
		}
	}
	b.WriteString(" FROM logs")
	if withFilter {
		b.WriteString(` WHERE hostname ILIKE $1 OR event ILIKE $1 OR device_type ILIKE $1
		             OR host(src_ip) ILIKE $1 OR host(dst_ip) ILIKE $1
		             OR mac ILIKE $1 OR client_mac ILIKE $1 OR ssid ILIKE $1
		             OR ifname ILIKE $1 OR proto ILIKE $1
		             OR ` + timestampText + ` ILIKE $1`)
	}
	fmt.Fprintf(&b, " ORDER BY timestamp DESC LIMIT %d", limit)
	return b.String()
}

// RecentLogs returns the newest rows, optionally filtered by a substring.
func (s *Store) RecentLogs(ctx context.Context, limit int, search string) ([]*LogEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	query := recentLogsSelect(search != "", limit)
	args := []any{}
	if search != "" {
		args = append(args, "%"+search+"%")
	}

	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: recent logs: %w", err)
	}
	defer rows.Close()

	out := make([]*LogEntry, 0, limit)
	for rows.Next() {
		e := &LogEntry{}
		sc := newRowScanner(e)
		if err := rows.Scan(sc.dest()...); err != nil {
			return nil, fmt.Errorf("store: scan recent log: %w", err)
		}
		sc.collect()
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecentAnomalies returns the newest detections, optionally filtered.
func (s *Store) RecentAnomalies(ctx context.Context, limit int, search string) ([]AnomalyRow, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, timestamp, COALESCE(severity,''), COALESCE(description,''),
	                 COALESCE((features->>'repeat_count')::int, 1),
	                 window_start, window_end, anomaly_score,
	                 COALESCE(features::text, '{}')
	          FROM anomalies`
	args := []any{}
	if search != "" {
		query += ` WHERE description ILIKE $1 OR severity ILIKE $1
		           OR ` + timestampText + ` ILIKE $1`
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
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.Severity, &r.Description,
			&r.RepeatCount, &r.WindowStart, &r.WindowEnd, &r.Score, &r.Features); err != nil {
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

// TopSources returns the entities that triggered the most detections.
func (s *Store) TopSources(ctx context.Context, limit int) ([]SourceCount, error) {
	if limit <= 0 {
		limit = 5
	}
	rows, err := s.Pool.Query(ctx, fmt.Sprintf(`
		SELECT features->>'entity' AS entity, COUNT(*) AS n
		FROM anomalies
		WHERE features->>'entity' IS NOT NULL
		GROUP BY entity ORDER BY n DESC LIMIT %d`, limit))
	if err != nil {
		return nil, fmt.Errorf("store: top sources: %w", err)
	}
	defer rows.Close()

	var out []SourceCount
	for rows.Next() {
		var sc SourceCount
		if err := rows.Scan(&sc.Source, &sc.Count); err != nil {
			return nil, fmt.Errorf("store: scan top source: %w", err)
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// DetectionBreakdown returns counts grouped by detection type.
func (s *Store) DetectionBreakdown(ctx context.Context) ([]TypeCount, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT COALESCE(features->>'type', 'UNKNOWN') AS t, COUNT(*) AS n
		FROM anomalies GROUP BY t ORDER BY n DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: detection breakdown: %w", err)
	}
	defer rows.Close()

	var out []TypeCount
	for rows.Next() {
		var tc TypeCount
		if err := rows.Scan(&tc.Type, &tc.Count); err != nil {
			return nil, fmt.Errorf("store: scan detection type: %w", err)
		}
		out = append(out, tc)
	}
	return out, rows.Err()
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

// LastLogTime returns the newest log timestamp, or the zero time when the
// table is empty. /status uses it to show whether data is still flowing.
func (s *Store) LastLogTime(ctx context.Context) (time.Time, error) {
	var t *time.Time
	if err := s.Pool.QueryRow(ctx, `SELECT MAX(timestamp) FROM logs`).Scan(&t); err != nil {
		return time.Time{}, fmt.Errorf("store: last log time: %w", err)
	}
	if t == nil {
		return time.Time{}, nil
	}
	return *t, nil
}

// AnomalyCounts returns detections in the last hour and the last 24 hours.
func (s *Store) AnomalyCounts(ctx context.Context) (hour, day int, err error) {
	err = s.Pool.QueryRow(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour'),
		  COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours')
		FROM anomalies`).Scan(&hour, &day)
	if err != nil {
		return 0, 0, fmt.Errorf("store: anomaly counts: %w", err)
	}
	return hour, day, nil
}
