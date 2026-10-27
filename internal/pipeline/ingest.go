package pipeline

import (
	"context"
	"errors"
	"log"
	"time"

	"siskamlan/internal/parser"
	"siskamlan/internal/store"
)

// Ingest batching parameters, mirroring the Python ingest worker.
const (
	// FlushInterval caps how long rows wait before a write.
	FlushInterval = 1 * time.Second
	// MaxBatch bounds memory; the oldest rows are dropped on backpressure.
	MaxBatch = 10000
	// MaxLineBytes rejects pathologically long lines (1MB, as the C collector).
	MaxLineBytes = 1024 * 1024
)

// Ingester consumes parsed lines and writes them to PostgreSQL in batches.
type Ingester struct {
	Store *store.Store
	// Parsers, if set, supplies the hot-reloadable parser.
	Parsers *ParserProvider
	// OnBatch, if set, is called after each successful write.
	OnBatch func(inserted, total, dropped int)

	total   int
	dropped int
	batch   []*store.LogEntry
}

// Run reads lines from in until it closes or ctx is cancelled.
func (i *Ingester) Run(ctx context.Context, in <-chan string) error {
	ticker := time.NewTicker(FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Flush whatever is buffered so a clean stop does not lose rows.
			return i.flush(context.Background())
		case line, ok := <-in:
			if !ok {
				return i.flush(context.Background())
			}
			i.add(line)
		case <-ticker.C:
			// Pick up parser config edits without restarting the process.
			if i.Parsers != nil {
				i.Parsers.Reload()
			}
			if err := i.flush(ctx); err != nil {
				return err
			}
		}
	}
}

// add parses one raw line and buffers the resulting row.
func (i *Ingester) add(line string) {
	if len(line) > MaxLineBytes {
		i.dropped++
		return
	}
	var e *parser.Entry
	if i.Parsers != nil {
		e = i.Parsers.Parse(line)
	} else {
		e = parser.Parse(line)
	}
	if e == nil {
		return
	}
	i.batch = append(i.batch, ToStore(e))
	// Drop oldest first, matching the Python bounded deque.
	for len(i.batch) > MaxBatch {
		i.batch = i.batch[1:]
		i.dropped++
	}
}

// flush persists the buffered rows.
func (i *Ingester) flush(ctx context.Context) error {
	if len(i.batch) == 0 {
		return nil
	}
	entries := i.batch
	i.batch = nil

	err := i.Store.InsertLogBatch(ctx, entries)
	if err == nil {
		i.total += len(entries)
		if i.OnBatch != nil {
			i.OnBatch(len(entries), i.total, i.dropped)
		}
		return nil
	}

	// A batch can fail on a single bad row. Fall back to row-by-row so one
	// malformed entry cannot discard an entire window of logs.
	log.Printf("ingest: batch of %d failed (%v) — retrying row by row", len(entries), err)
	var rowErrs int
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := i.Store.InsertLogEntry(ctx, e); err != nil {
			rowErrs++
			i.dropped++
		} else {
			i.total++
		}
	}
	if rowErrs == len(entries) {
		return errors.New("ingest: every row in the batch failed")
	}
	if i.OnBatch != nil {
		i.OnBatch(len(entries)-rowErrs, i.total, i.dropped)
	}
	return nil
}

// Total reports rows written so far.
func (i *Ingester) Total() int { return i.total }

// Dropped reports rows discarded so far.
func (i *Ingester) Dropped() int { return i.dropped }
