package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"siskamlan/internal/store"
)

// fakeLogStore records insert calls and can be told to fail batches.
type fakeLogStore struct {
	batches    [][]*store.LogEntry
	singles    []*store.LogEntry
	failBatch  bool
	failSingle bool
}

func (f *fakeLogStore) InsertLogBatch(ctx context.Context, entries []*store.LogEntry) error {
	if f.failBatch {
		return errors.New("batch failed")
	}
	f.batches = append(f.batches, entries)
	return nil
}

func (f *fakeLogStore) InsertLogEntry(ctx context.Context, entry *store.LogEntry) error {
	if f.failSingle {
		return errors.New("row failed")
	}
	f.singles = append(f.singles, entry)
	return nil
}

func newIngester(st logStore) *Ingester {
	return &Ingester{Store: st}
}

// TestIngestBatchesOnFlush writes buffered rows in one call.
func TestIngestBatchesOnFlush(t *testing.T) {
	fake := &fakeLogStore{}
	in := newIngester(fake)

	in.add("2026-01-02T03:04:05+00:00 host tag: hello")
	in.add("2026-01-02T03:04:06+00:00 host tag: world")

	if err := in.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(fake.batches) != 1 || len(fake.batches[0]) != 2 {
		t.Fatalf("batches = %d (rows %d), want 1 batch of 2", len(fake.batches), rowsIn(fake.batches))
	}
	if in.Total() != 2 {
		t.Fatalf("total = %d, want 2", in.Total())
	}
	if len(in.batch) != 0 {
		t.Fatalf("batch not cleared after flush: %d", len(in.batch))
	}
}

// TestIngestEmptyFlushIsNoop avoids issuing empty statements.
func TestIngestEmptyFlushIsNoop(t *testing.T) {
	fake := &fakeLogStore{}
	in := newIngester(fake)
	if err := in.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(fake.batches) != 0 {
		t.Fatalf("empty flush issued %d statements", len(fake.batches))
	}
}

// TestIngestFallsBackToRowByRow checks one poison row cannot drop the batch.
func TestIngestFallsBackToRowByRow(t *testing.T) {
	fake := &fakeLogStore{failBatch: true}
	in := newIngester(fake)

	for i := 0; i < 3; i++ {
		in.add("2026-01-02T03:04:05+00:00 host tag: hello")
	}
	if err := in.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(fake.singles) != 3 {
		t.Fatalf("row-by-row inserts = %d, want 3", len(fake.singles))
	}
	if in.Total() != 3 {
		t.Fatalf("total = %d, want 3", in.Total())
	}
}

// TestIngestAllRowsFailRejectsBatch surfaces a total failure.
func TestIngestAllRowsFailRejectsBatch(t *testing.T) {
	fake := &fakeLogStore{failBatch: true, failSingle: true}
	in := newIngester(fake)
	in.add("2026-01-02T03:04:05+00:00 host tag: hello")
	if err := in.flush(context.Background()); err == nil {
		t.Fatal("expected an error when every row fails")
	}
}

// TestIngestDropsOversizeLines rejects pathological input before parsing.
func TestIngestDropsOversizeLines(t *testing.T) {
	fake := &fakeLogStore{}
	in := newIngester(fake)

	in.add(strings.Repeat("a", MaxLineBytes+1))
	if len(in.batch) != 0 {
		t.Fatalf("oversize line was buffered")
	}
	if in.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", in.Dropped())
	}
}

// TestIngestEvictsOldestAtCapacity bounds memory, dropping oldest first.
func TestIngestEvictsOldestAtCapacity(t *testing.T) {
	fake := &fakeLogStore{}
	in := newIngester(fake)

	// Pre-fill to the cap without parsing MaxBatch log lines.
	in.batch = make([]*store.LogEntry, MaxBatch)
	for i := range in.batch {
		in.batch[i] = &store.LogEntry{RawLine: "old"}
	}
	in.add("2026-01-02T03:04:05+00:00 host tag: newest")

	if len(in.batch) != MaxBatch {
		t.Fatalf("batch length = %d, want %d", len(in.batch), MaxBatch)
	}
	if in.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", in.Dropped())
	}
	last := in.batch[len(in.batch)-1]
	if !strings.Contains(last.RawLine, "newest") {
		t.Fatalf("newest row not retained: %q", last.RawLine)
	}
}

// TestIngestIgnoresEmptyLines avoids recording blank input.
func TestIngestIgnoresEmptyLines(t *testing.T) {
	fake := &fakeLogStore{}
	in := newIngester(fake)
	in.add("")
	in.add("\n")
	if len(in.batch) != 0 {
		t.Fatalf("blank lines were buffered: %d", len(in.batch))
	}
}

// TestIngestOnBatchCallback reports progress.
func TestIngestOnBatchCallback(t *testing.T) {
	fake := &fakeLogStore{}
	in := newIngester(fake)
	var inserted, total int
	in.OnBatch = func(i, tot, dropped int) { inserted, total = i, tot }

	in.add("2026-01-02T03:04:05+00:00 host tag: hello")
	if err := in.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if inserted != 1 || total != 1 {
		t.Fatalf("callback = (%d,%d), want (1,1)", inserted, total)
	}
}

// TestIngestRunFlushesOnCancel ensures buffered rows are not lost on shutdown.
func TestIngestRunFlushesOnCancel(t *testing.T) {
	fake := &fakeLogStore{}
	in := newIngester(fake)

	ctx, cancel := context.WithCancel(context.Background())
	in.add("2026-01-02T03:04:05+00:00 host tag: buffered")
	cancel()

	ch := make(chan string)
	close(ch)
	if err := in.Run(ctx, ch); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fake.batches) != 1 || len(fake.batches[0]) != 1 {
		t.Fatalf("buffered row not flushed on cancel: %+v", fake.batches)
	}
}

func rowsIn(batches [][]*store.LogEntry) int {
	n := 0
	for _, b := range batches {
		n += len(b)
	}
	return n
}

// blockingStore hangs on insert until its context is cancelled, simulating an
// unreachable database during shutdown.
type blockingStore struct{ released chan struct{} }

func (b *blockingStore) InsertLogBatch(ctx context.Context, entries []*store.LogEntry) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.released:
		return nil
	}
}

func (b *blockingStore) InsertLogEntry(ctx context.Context, entry *store.LogEntry) error {
	return b.InsertLogBatch(ctx, []*store.LogEntry{entry})
}

// TestShutdownFlushDoesNotHang is the regression test for an unbounded shutdown
// flush: quitting must not block forever when the database stops responding.
func TestShutdownFlushDoesNotHang(t *testing.T) {
	store := &blockingStore{released: make(chan struct{})}
	defer close(store.released)

	in := &Ingester{Store: store, ShutdownTimeout: 100 * time.Millisecond}
	in.add("2026-01-02T03:04:05+00:00 host tag: buffered")

	done := make(chan error, 1)
	go func() { done <- in.flushShutdown() }()

	select {
	case err := <-done:
		// A failed shutdown flush is logged, not propagated, so exit is clean.
		if err != nil {
			t.Fatalf("flushShutdown returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("flushShutdown blocked past its deadline; quitting would hang")
	}
}

// TestShutdownFlushTimeoutIsBounded guards the constant against drift.
func TestShutdownFlushTimeoutIsBounded(t *testing.T) {
	if ShutdownFlushTimeout <= 0 || ShutdownFlushTimeout > 15*time.Second {
		t.Fatalf("ShutdownFlushTimeout = %s, want a short positive bound", ShutdownFlushTimeout)
	}
}
