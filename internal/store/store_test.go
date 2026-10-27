package store

import (
	"context"
	"fmt"
	"math/rand"
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
