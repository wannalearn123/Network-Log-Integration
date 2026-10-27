package pipeline

import (
	"context"
	"testing"
	"time"
)

// TestSupervisorStopsWhenIngestFails verifies a failing worker cancels the
// others instead of leaving a half-dead pipeline running.
func TestSupervisorStopsWhenIngestFails(t *testing.T) {
	dir := t.TempDir()

	fake := &fakeLogStore{failBatch: true, failSingle: true}
	sup := New(Config{
		Store:     nil, // replaced below via the ingester
		SyslogDir: dir,
		StateFile: dir + "/state/offsets.json",
	})
	sup.ingester.Store = fake
	// The detector would query a nil store; keep it out of this test.
	sup.detector = &Detector{Store: newFakeDetectorStore(), Rules: testRulesFile(t)}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	// Feed a line so the ingester attempts a write that fails.
	sup.lines <- "2026-01-02T03:04:05+00:00 host tag: hello"

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("supervisor returned nil despite a failing worker")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("supervisor did not stop after a worker failed")
	}
}

// TestSupervisorStopsOnContextCancel checks a clean shutdown returns nil.
func TestSupervisorStopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	sup := New(Config{
		SyslogDir: dir,
		StateFile: dir + "/state/offsets.json",
	})
	sup.ingester.Store = &fakeLogStore{}
	sup.detector = &Detector{Store: newFakeDetectorStore(), Rules: testRulesFile(t)}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("clean cancel returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not stop on cancel")
	}
}

// TestSupervisorStatsExposesCounters checks the dashboard counters.
func TestSupervisorStatsExposesCounters(t *testing.T) {
	sup := New(Config{SyslogDir: t.TempDir()})
	sup.ingester.Store = &fakeLogStore{}
	sup.ingester.add("2026-01-02T03:04:05+00:00 host tag: hello")
	if err := sup.ingester.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	total, dropped := sup.Stats()
	if total != 1 || dropped != 0 {
		t.Fatalf("Stats() = (%d,%d), want (1,0)", total, dropped)
	}
}
