package store

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// testStore connects using PG* env. PostgreSQL is required: these tests verify
// real SQL behaviour, and skipping silently would hide schema or query bugs.
func testStore(t *testing.T) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s, err := Open(ctx, OptionsFromEnv())
	if err != nil {
		t.Fatalf("PostgreSQL is required for store tests (start it with "+
			"`docker compose up -d postgres`): %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func randTag() string {
	return fmt.Sprintf("gotest-%d-%d", time.Now().UnixNano(), rand.Intn(100000))
}

// TestQueryWindowScansNullColumns inserts a row with every optional column
// NULL and reads it back. This is the exact case that previously broke the
// detector with "cannot scan NULL into *string".
func TestQueryWindowScansNullColumns(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tag := randTag()

	entry := &LogEntry{
		Timestamp:  time.Now().UTC(),
		Hostname:   tag,
		Facility:   "user",
		Severity:   "info",
		DeviceType: "other",
		Event:      "unknown",
		RawLine:    "a line with almost no structure",
	}
	if err := s.InsertLogEntry(ctx, entry); err != nil {
		t.Fatalf("insert: %v", err)
	}
	t.Cleanup(func() {
		s.Pool.Exec(context.Background(), "DELETE FROM logs WHERE hostname = $1", tag)
	})

	rows, err := s.QueryWindow(ctx, 120)
	if err != nil {
		t.Fatalf("QueryWindow: %v", err)
	}

	var found *LogEntry
	for _, r := range rows {
		if r.Hostname == tag {
			found = r
			break
		}
	}
	if found == nil {
		t.Fatal("inserted row not returned by QueryWindow")
	}
	if found.SrcIP != nil || found.MAC != "" || found.ClientMAC != "" {
		t.Fatalf("NULL columns decoded incorrectly: %+v", found)
	}
	if found.RawLine != entry.RawLine {
		t.Fatalf("raw_line = %q, want %q", found.RawLine, entry.RawLine)
	}
}

// TestInsertBatchAndRoundTrip writes several rows in one statement.
func TestInsertBatchAndRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tag := randTag()

	src := "203.0.113.77"
	port := 443
	batch := []*LogEntry{
		{Timestamp: time.Now().UTC(), Hostname: tag, DeviceType: "firewall", Event: "fw_block",
			SrcIP: &src, DstPort: &port, RawLine: "one"},
		{Timestamp: time.Now().UTC(), Hostname: tag, DeviceType: "firewall", Event: "fw_block",
			SrcIP: &src, DstPort: &port, RawLine: "two"},
	}
	if err := s.InsertLogBatch(ctx, batch); err != nil {
		t.Fatalf("insert batch: %v", err)
	}
	t.Cleanup(func() {
		s.Pool.Exec(context.Background(), "DELETE FROM logs WHERE hostname = $1", tag)
	})

	rows, err := s.QueryWindow(ctx, 120)
	if err != nil {
		t.Fatalf("QueryWindow: %v", err)
	}
	n := 0
	for _, r := range rows {
		if r.Hostname == tag {
			n++
			if r.SrcIP == nil || *r.SrcIP != src {
				t.Fatalf("src_ip = %v, want %s", r.SrcIP, src)
			}
			if r.DstPort == nil || *r.DstPort != port {
				t.Fatalf("dst_port = %v, want %d", r.DstPort, port)
			}
		}
	}
	if n != 2 {
		t.Fatalf("found %d rows, want 2", n)
	}
}

// TestAnomalyAndCooldownRoundTrip covers the detection write path.
func TestAnomalyAndCooldownRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	features := []byte(`{"type":"GOTEST","entity":"x","repeat_count":1}`)
	id, err := s.InsertAnomaly(ctx, Anomaly{
		Severity: "HIGH", Description: "[RULE] test anomaly", Features: features,
	}, 30)
	if err != nil {
		t.Fatalf("InsertAnomaly: %v", err)
	}
	t.Cleanup(func() {
		s.Pool.Exec(context.Background(), "DELETE FROM anomalies WHERE id = $1", id)
	})

	sig := fmt.Sprintf("GOTEST|%d", id)
	if err := s.SaveCooldown(ctx, sig, id, 1); err != nil {
		t.Fatalf("SaveCooldown: %v", err)
	}
	t.Cleanup(func() {
		s.Pool.Exec(context.Background(), "DELETE FROM detection_cooldowns WHERE signature = $1", sig)
	})

	cd, err := s.GetCooldown(ctx, sig)
	if err != nil {
		t.Fatalf("GetCooldown: %v", err)
	}
	if cd == nil || cd.AnomalyID != id || cd.RepeatCount != 1 {
		t.Fatalf("cooldown = %+v, want id=%d repeat=1", cd, id)
	}

	if err := s.BumpAnomaly(ctx, id, 5); err != nil {
		t.Fatalf("BumpAnomaly: %v", err)
	}
	if err := s.SaveCooldown(ctx, sig, id, 5); err != nil {
		t.Fatalf("SaveCooldown bump: %v", err)
	}
	cd, _ = s.GetCooldown(ctx, sig)
	if cd == nil || cd.RepeatCount != 5 {
		t.Fatalf("cooldown after bump = %+v, want repeat=5", cd)
	}
}

// TestInsertLargeBatchChunksAboveParameterLimit is the regression test for the
// 65535 bind-parameter limit: a batch larger than one statement allows must
// still be written completely.
func TestInsertLargeBatchChunksAboveParameterLimit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tag := randTag()

	// Comfortably above maxRowsPerInsert so chunking must happen.
	n := maxRowsPerInsert*2 + 17
	batch := make([]*LogEntry, n)
	now := time.Now().UTC()
	for i := range batch {
		batch[i] = &LogEntry{
			Timestamp: now, Hostname: tag, DeviceType: "other",
			Event: "unknown", RawLine: "bulk",
		}
	}

	if err := s.InsertLogBatch(ctx, batch); err != nil {
		t.Fatalf("InsertLogBatch(%d rows): %v", n, err)
	}
	t.Cleanup(func() {
		s.Pool.Exec(context.Background(), "DELETE FROM logs WHERE hostname = $1", tag)
	})

	var count int
	if err := s.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM logs WHERE hostname = $1", tag).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != n {
		t.Fatalf("inserted %d rows, want %d — chunking lost data", count, n)
	}
}

// TestMaxRowsPerInsertFitsParameterLimit guards the derivation.
func TestMaxRowsPerInsertFitsParameterLimit(t *testing.T) {
	if maxRowsPerInsert*len(LogColumns) > maxBindParams {
		t.Fatalf("%d rows x %d cols exceeds %d parameters",
			maxRowsPerInsert, len(LogColumns), maxBindParams)
	}
	if maxRowsPerInsert < 100 {
		t.Fatalf("maxRowsPerInsert = %d is suspiciously small", maxRowsPerInsert)
	}
}

// TestMigrateIsIdempotent checks repeated migrations do not error or leak locks.
func TestMigrateIsIdempotent(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("migrate #%d: %v", i+1, err)
		}
	}
}

// TestMalformedAddressDoesNotPoisonBatch is the regression test for IPv6
// fragments such as "fe80": an invalid inet value must be stored as NULL
// rather than failing the whole statement.
func TestMalformedAddressDoesNotPoisonBatch(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tag := randTag()

	bad := "fe80" // what the old parser produced for IPv6
	good := "10.1.2.3"
	port := 443
	batch := []*LogEntry{
		{Timestamp: time.Now().UTC(), Hostname: tag, DeviceType: "firewall",
			Event: "fw_block", SrcIP: &bad, DstPort: &port, RawLine: "bad row"},
		{Timestamp: time.Now().UTC(), Hostname: tag, DeviceType: "firewall",
			Event: "fw_block", SrcIP: &good, DstPort: &port, RawLine: "good row"},
	}
	if err := s.InsertLogBatch(ctx, batch); err != nil {
		t.Fatalf("batch failed on a malformed address: %v", err)
	}
	t.Cleanup(func() {
		s.Pool.Exec(context.Background(), "DELETE FROM logs WHERE hostname = $1", tag)
	})

	var total, withNull int
	if err := s.Pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE src_ip IS NULL)
		FROM logs WHERE hostname = $1`, tag).Scan(&total, &withNull); err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 2 {
		t.Fatalf("rows = %d, want 2 — the batch was rejected", total)
	}
	if withNull != 1 {
		t.Fatalf("NULL src_ip rows = %d, want 1 (the malformed one)", withNull)
	}
}

// TestIPv6AddressIsStored checks a real IPv6 address round-trips as inet.
func TestIPv6AddressIsStored(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tag := randTag()

	v6 := "fe80::2481:d6ff:fea2:2a69"
	entry := &LogEntry{Timestamp: time.Now().UTC(), Hostname: tag,
		DeviceType: "firewall", Event: "fw_block", SrcIP: &v6, RawLine: "ipv6 row"}
	if err := s.InsertLogEntry(ctx, entry); err != nil {
		t.Fatalf("insert IPv6: %v", err)
	}
	t.Cleanup(func() {
		s.Pool.Exec(context.Background(), "DELETE FROM logs WHERE hostname = $1", tag)
	})

	var stored string
	if err := s.Pool.QueryRow(ctx,
		"SELECT host(src_ip) FROM logs WHERE hostname = $1", tag).Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored != v6 {
		t.Fatalf("src_ip = %q, want %q", stored, v6)
	}
}

// TestBatchIsAtomic checks a failing batch leaves nothing behind.
func TestBatchIsAtomic(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tag := randTag()

	// An out-of-range port violates a CHECK constraint, failing the statement.
	port := 70000
	batch := []*LogEntry{
		{Timestamp: time.Now().UTC(), Hostname: tag, DstPort: &port, RawLine: "invalid"},
	}
	if err := s.InsertLogBatch(ctx, batch); err == nil {
		t.Fatal("expected the constraint violation to fail the batch")
	}
	t.Cleanup(func() {
		s.Pool.Exec(context.Background(), "DELETE FROM logs WHERE hostname = $1", tag)
	})

	var count int
	if err := s.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM logs WHERE hostname = $1", tag).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("%d rows committed from a failed batch; it must be atomic", count)
	}
}

// TestTopSourcesAndBreakdown covers the security-overview queries.
func TestTopSourcesAndBreakdown(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tag := randTag()

	// Three anomalies: two PORT_SCAN for one entity, one FLOOD with no entity.
	type seed struct {
		features string
		severity string
		desc     string
	}
	seeds := []seed{
		{`{"type":"` + tag + `_SCAN","entity":"10.9.9.9","repeat_count":1}`, "HIGH", tag + " a"},
		{`{"type":"` + tag + `_SCAN","entity":"10.9.9.9","repeat_count":1}`, "HIGH", tag + " b"},
		{`{"type":"` + tag + `_FLOOD","entity":null,"repeat_count":1}`, "MEDIUM", tag + " c"},
	}
	var ids []int
	for _, sd := range seeds {
		id, err := s.InsertAnomaly(ctx, Anomaly{
			Severity: sd.severity, Description: sd.desc, Features: []byte(sd.features),
		}, 30)
		if err != nil {
			t.Fatalf("insert anomaly: %v", err)
		}
		ids = append(ids, id)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			s.Pool.Exec(context.Background(), "DELETE FROM anomalies WHERE id = $1", id)
		}
	})

	// BSD: overview queries are global, so assert our rows appear correctly
	// rather than assuming they are the only ones.
	sources, err := s.TopSources(ctx, 50)
	if err != nil {
		t.Fatalf("TopSources: %v", err)
	}
	found := false
	for _, sc := range sources {
		if sc.Source == "10.9.9.9" && sc.Count >= 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("10.9.9.9 missing from top sources: %+v", sources)
	}

	types, err := s.DetectionBreakdown(ctx)
	if err != nil {
		t.Fatalf("DetectionBreakdown: %v", err)
	}
	seen := map[string]int{}
	for _, tc := range types {
		seen[tc.Type] = tc.Count
	}
	if seen[tag+"_SCAN"] < 2 || seen[tag+"_FLOOD"] < 1 {
		t.Fatalf("breakdown missing our types: %+v", seen)
	}
}

// TestRecentAnomaliesIncludesFeatures checks the detail columns are populated.
func TestRecentAnomaliesIncludesFeatures(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tag := randTag()

	id, err := s.InsertAnomaly(ctx, Anomaly{
		Severity: "LOW", Description: tag,
		Features: []byte(`{"type":"TEST","entity":"10.0.0.1","repeat_count":1}`),
	}, 30)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	t.Cleanup(func() {
		s.Pool.Exec(context.Background(), "DELETE FROM anomalies WHERE id = $1", id)
	})

	rows, err := s.RecentAnomalies(ctx, 50, tag)
	if err != nil {
		t.Fatalf("RecentAnomalies: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if !strings.Contains(r.Features, `"type": "TEST"`) && !strings.Contains(r.Features, `"type":"TEST"`) {
		t.Fatalf("features not populated: %q", r.Features)
	}
	if r.WindowStart.IsZero() || r.WindowEnd.IsZero() {
		t.Fatalf("window times not populated: %+v", r)
	}
}

// TestRecentLogsFiltersByTimestamp checks the dashboard filter matches the
// rendered timestamp, not just the textual columns. Search terms are derived
// from the database's own rendering so the test is timezone-independent.
func TestRecentLogsFiltersByTimestamp(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tag := randTag()

	ts := time.Date(2021, 3, 14, 15, 9, 26, 0, time.UTC)
	entry := &LogEntry{
		Timestamp: ts, Hostname: tag, Facility: "user", Severity: "info",
		DeviceType: "other", Event: "unknown", RawLine: "timestamp filter fixture",
	}
	if err := s.InsertLogEntry(ctx, entry); err != nil {
		t.Fatalf("insert: %v", err)
	}
	t.Cleanup(func() {
		s.Pool.Exec(context.Background(), "DELETE FROM logs WHERE hostname = $1", tag)
	})

	// The pane renders timestamps with this same expression, so matching any
	// slice of it is what a user typing into the filter box actually does.
	var rendered string
	if err := s.Pool.QueryRow(ctx,
		`SELECT `+timestampText+` FROM logs WHERE hostname = $1`, tag).Scan(&rendered); err != nil {
		t.Fatalf("render timestamp: %v", err)
	}
	if len(rendered) != len("2006-01-02 15:04:05") {
		t.Fatalf("rendered timestamp = %q, want YYYY-MM-DD HH24:MI:SS", rendered)
	}

	cases := []struct {
		name, search string
		want         bool
	}{
		{"full date", rendered[:10], true},
		{"date and clock", rendered[:16], true},
		{"clock only", rendered[11:17], true},
		{"seconds precision", rendered[11:], true},
		{"wrong hour", "23:59:59", false},
		{"wrong date", "1999-12-31", false},
	}

	for _, c := range cases {
		rows, err := s.RecentLogs(ctx, 300, c.search)
		if err != nil {
			t.Fatalf("%s: RecentLogs: %v", c.name, err)
		}
		found := false
		for _, r := range rows {
			if r.Hostname == tag {
				found = true
				break
			}
		}
		if found != c.want {
			t.Errorf("%s: search %q found = %v, want %v", c.name, c.search, found, c.want)
		}
	}
}

// TestRecentAnomaliesFiltersByTimestamp checks the anomaly pane honours the
// same timestamp substring as the log pane.
func TestRecentAnomaliesFiltersByTimestamp(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tag := randTag()

	id, err := s.InsertAnomaly(ctx, Anomaly{
		Severity: "LOW", Description: tag,
		Features: []byte(`{"type":"TEST","entity":"10.0.0.2","repeat_count":1}`),
	}, 30)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	t.Cleanup(func() {
		s.Pool.Exec(context.Background(), "DELETE FROM anomalies WHERE id = $1", id)
	})

	var day string
	if err := s.Pool.QueryRow(ctx,
		`SELECT to_char(timestamp, 'YYYY-MM-DD') FROM anomalies WHERE id = $1`, id).Scan(&day); err != nil {
		t.Fatalf("render date: %v", err)
	}

	// Match on the stored timestamp's own date: the pane must return the row.
	rows, err := s.RecentAnomalies(ctx, 200, day)
	if err != nil {
		t.Fatalf("RecentAnomalies(%q): %v", day, err)
	}
	found := false
	for _, r := range rows {
		if r.ID == id {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("anomaly %d not matched by its own date %q", id, day)
	}

	// A date that cannot be the stored one must exclude it.
	other := "1999-12-31"
	if day == other {
		other = "1999-12-30"
	}
	rows, err = s.RecentAnomalies(ctx, 200, other)
	if err != nil {
		t.Fatalf("RecentAnomalies(%q): %v", other, err)
	}
	for _, r := range rows {
		if r.ID == id {
			t.Fatalf("anomaly %d matched unrelated date %q", id, other)
		}
	}
}
