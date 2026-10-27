package store

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// inetColumns are cast explicitly so Go sees plain strings instead of a
// driver-specific network type. host() strips any netmask.
var inetColumns = map[string]bool{
	"src_ip": true, "dst_ip": true, "ospf_nbr": true, "gateway": true,
}

// placeholder renders "$n", adding ::inet for network columns.
func placeholder(col string, idx int) string {
	if inetColumns[col] {
		return fmt.Sprintf("$%d::inet", idx)
	}
	return "$" + strconv.Itoa(idx)
}

var insertPrefix = buildInsertPrefix()

func buildInsertPrefix() string {
	cols := make([]string, len(LogColumns))
	rows := make([]string, len(LogColumns))
	for i, c := range LogColumns {
		cols[i] = c
		rows[i] = placeholder(c, i+1)
	}
	return "INSERT INTO logs (" + strings.Join(cols, ", ") + ") VALUES "
}

// InsertLogBatch writes entries in a single statement. A batch of one uses the
// same path so behaviour is identical regardless of size.
func (s *Store) InsertLogBatch(ctx context.Context, entries []*LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	var b strings.Builder
	b.WriteString(insertPrefix)
	args := make([]any, 0, len(entries)*len(LogColumns))
	argIdx := 1
	for i, e := range entries {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteByte('(')
		for j, col := range LogColumns {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString(placeholder(col, argIdx))
			argIdx++
		}
		b.WriteByte(')')
		args = append(args, e.values()...)
	}

	if _, err := s.Pool.Exec(ctx, b.String(), args...); err != nil {
		return fmt.Errorf("store: insert %d log rows: %w", len(entries), err)
	}
	return nil
}

// InsertLogEntry writes a single row.
func (s *Store) InsertLogEntry(ctx context.Context, entry *LogEntry) error {
	return s.InsertLogBatch(ctx, []*LogEntry{entry})
}

var windowSelect = buildWindowSelect()

func buildWindowSelect() string {
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
	b.WriteString(" FROM logs WHERE timestamp >= NOW() - make_interval(secs => $1) AND timestamp <= NOW() ORDER BY timestamp")
	return b.String()
}

// rowScanner scans every `logs` column, tolerating NULL for string columns
// (which the parser stores as NULL when a field is absent).
type rowScanner struct {
	e          *LogEntry
	hostname   *string
	facility   *string
	severity   *string
	deviceType *string
	event      *string
	proto      *string
	action     *string
	mac        *string
	ifname     *string
	peerIfname *string
	stpRoot    *string
	clientMAC  *string
	ssid       *string
	radio      *string
	eapStatus  *string
	routeDst   *string
	dhcpMAC    *string
	rawLine    *string
}

func newRowScanner(e *LogEntry) *rowScanner {
	return &rowScanner{e: e}
}

// dest returns scan targets in LogColumns order.
func (r *rowScanner) dest() []any {
	e := r.e
	return []any{
		&e.Timestamp, &r.hostname, &r.facility, &r.severity,
		&r.deviceType, &r.event, &e.SrcIP, &e.DstIP,
		&r.proto, &e.DstPort,
		&e.SrcPort, &r.action,
		&r.mac, &e.VLANID, &r.ifname, &r.peerIfname, &r.stpRoot,
		&r.clientMAC, &r.ssid, &r.radio, &e.Reason, &e.SignalDBM,
		&e.TxRateMbps, &r.eapStatus,
		&e.OSPFNbr, &e.Gateway, &r.routeDst, &r.dhcpMAC, &e.ConntrackCt,
		&r.rawLine,
	}
}

// collect copies the nullable strings into the entry.
func (r *rowScanner) collect() {
	e := r.e
	e.Hostname = deref(r.hostname)
	e.Facility = deref(r.facility)
	e.Severity = deref(r.severity)
	e.DeviceType = deref(r.deviceType)
	e.Event = deref(r.event)
	e.Proto = deref(r.proto)
	e.Action = deref(r.action)
	e.MAC = deref(r.mac)
	e.IfName = deref(r.ifname)
	e.PeerIfName = deref(r.peerIfname)
	e.STPRoot = deref(r.stpRoot)
	e.ClientMAC = deref(r.clientMAC)
	e.SSID = deref(r.ssid)
	e.Radio = deref(r.radio)
	e.EAPStatus = deref(r.eapStatus)
	e.RouteDst = deref(r.routeDst)
	e.DHCPMAC = deref(r.dhcpMAC)
	e.RawLine = deref(r.rawLine)
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// QueryWindow returns the parsed rows inside the last windowSeconds.
func (s *Store) QueryWindow(ctx context.Context, windowSeconds int) ([]*LogEntry, error) {
	rows, err := s.Pool.Query(ctx, windowSelect, windowSeconds)
	if err != nil {
		return nil, fmt.Errorf("store: query window: %w", err)
	}
	defer rows.Close()

	out := make([]*LogEntry, 0, 128)
	for rows.Next() {
		e := &LogEntry{}
		sc := newRowScanner(e)
		if err := rows.Scan(sc.dest()...); err != nil {
			return nil, fmt.Errorf("store: scan window row: %w", err)
		}
		sc.collect()
		out = append(out, e)
	}
	return out, rows.Err()
}

// InsertAnomaly stores a detection and returns its id.
func (s *Store) InsertAnomaly(ctx context.Context, a Anomaly, windowSeconds int) (int, error) {
	var id int
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO anomalies (timestamp, window_start, window_end,
		                       anomaly_score, features, severity, description)
		VALUES (NOW(), NOW() - make_interval(secs => $1), NOW(),
		        $2, $3::jsonb, $4, $5)
		RETURNING id`,
		windowSeconds, a.AnomalyScore, string(a.Features), a.Severity, a.Description,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: insert anomaly: %w", err)
	}
	return id, nil
}

// BumpAnomaly merges a repeat detection into an existing row.
func (s *Store) BumpAnomaly(ctx context.Context, anomalyID, repeatCount int) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE anomalies
		SET window_end = NOW(),
		    features = COALESCE(features, '{}'::jsonb)
		               || jsonb_build_object('repeat_count', $1::int, 'last_seen', NOW()::text)
		WHERE id = $2`, repeatCount, anomalyID)
	if err != nil {
		return fmt.Errorf("store: bump anomaly %d: %w", anomalyID, err)
	}
	return nil
}

// GetCooldown returns the merge state for a signature, or nil when absent.
func (s *Store) GetCooldown(ctx context.Context, signature string) (*Cooldown, error) {
	c := &Cooldown{}
	err := s.Pool.QueryRow(ctx, `
		SELECT anomaly_id, repeat_count, EXTRACT(EPOCH FROM (NOW() - last_seen))
		FROM detection_cooldowns WHERE signature = $1`, signature,
	).Scan(&c.AnomalyID, &c.RepeatCount, &c.AgeSeconds)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get cooldown: %w", err)
	}
	return c, nil
}

// SaveCooldown upserts the merge state for a signature.
func (s *Store) SaveCooldown(ctx context.Context, signature string, anomalyID, repeatCount int) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO detection_cooldowns (signature, anomaly_id, repeat_count, last_seen)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (signature) DO UPDATE
		SET anomaly_id = EXCLUDED.anomaly_id,
		    repeat_count = EXCLUDED.repeat_count,
		    last_seen = NOW()`,
		signature, anomalyID, repeatCount)
	if err != nil {
		return fmt.Errorf("store: save cooldown: %w", err)
	}
	return nil
}

// PruneHistory applies retention. Zero days disables a table's retention.
func (s *Store) PruneHistory(ctx context.Context, logDays, anomalyDays int) error {
	if logDays < 0 || anomalyDays < 0 {
		return fmt.Errorf("store: retention days must be nonnegative")
	}
	if logDays > 0 {
		if _, err := s.Pool.Exec(ctx, `DELETE FROM logs WHERE timestamp < NOW() - make_interval(days => $1)`, logDays); err != nil {
			return fmt.Errorf("store: prune logs: %w", err)
		}
	}
	if anomalyDays > 0 {
		if _, err := s.Pool.Exec(ctx, `DELETE FROM anomalies WHERE timestamp < NOW() - make_interval(days => $1)`, anomalyDays); err != nil {
			return fmt.Errorf("store: prune anomalies: %w", err)
		}
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM detection_cooldowns WHERE last_seen < NOW() - INTERVAL '1 day'`); err != nil {
		return fmt.Errorf("store: prune cooldowns: %w", err)
	}
	return nil
}
