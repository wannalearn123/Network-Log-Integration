package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startTailer runs a tailer and returns its channel plus a stop function that
// waits for the goroutine to exit, so temp directories clean up reliably.
func startTailer(t *testing.T, tl *Tailer) (<-chan string, func()) {
	t.Helper()
	out := make(chan string, 100)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tl.Run(ctx, out)
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("tailer did not stop")
		}
	}
	return out, stop
}

// waitLine waits for one line or fails the test.
func waitLine(t *testing.T, out <-chan string, timeout time.Duration) string {
	t.Helper()
	select {
	case line := <-out:
		return line
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a line")
		return ""
	}
}

func TestTailerPartialLineAndRotation(t *testing.T) {
	dir := t.TempDir()
	tl := &Tailer{
		Dir: dir, StateFile: filepath.Join(dir, "state", "offsets.json"),
		PollInterval: 20 * time.Millisecond, SaveInterval: 50 * time.Millisecond,
	}
	out, stop := startTailer(t, tl)
	defer stop()

	time.Sleep(80 * time.Millisecond) // initial discovery settles

	path := filepath.Join(dir, "device.log")
	if err := os.WriteFile(path, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)

	select {
	case line := <-out:
		t.Fatalf("emitted an incomplete line: %q", line)
	default:
	}

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(" completed\n")
	f.Close()

	if got := waitLine(t, out, 2*time.Second); got != "partial completed" {
		t.Fatalf("line = %q, want %q", got, "partial completed")
	}

	// Rotation: rename the old file away and start a fresh one.
	if err := os.Rename(path, filepath.Join(dir, "device.old")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("rotated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := waitLine(t, out, 2*time.Second); got != "rotated" {
		t.Fatalf("rotation line = %q, want %q", got, "rotated")
	}
}

func TestTailerResumesFromOffset(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state", "offsets.json")
	path := filepath.Join(dir, "device.log")
	if err := os.WriteFile(path, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out1, stop1 := startTailer(t, &Tailer{
		Dir: dir, StateFile: state,
		PollInterval: 20 * time.Millisecond, SaveInterval: 30 * time.Millisecond,
	})
	time.Sleep(200 * time.Millisecond)
	stop1()

	select {
	case line := <-out1:
		t.Fatalf("pre-existing data emitted at startup: %q", line)
	default:
	}

	// Append while stopped, then resume: only the new line appears.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("second\n")
	f.Close()

	out2, stop2 := startTailer(t, &Tailer{
		Dir: dir, StateFile: state,
		PollInterval: 20 * time.Millisecond, SaveInterval: 30 * time.Millisecond,
	})
	defer stop2()

	if got := waitLine(t, out2, 2*time.Second); got != "second" {
		t.Fatalf("resumed line = %q, want %q", got, "second")
	}
}

func TestTailerTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.log")
	if err := os.WriteFile(path, []byte("a longer original line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, stop := startTailer(t, &Tailer{
		Dir: dir, StateFile: filepath.Join(dir, "state", "offsets.json"),
		PollInterval: 20 * time.Millisecond, SaveInterval: 30 * time.Millisecond,
	})
	defer stop()
	time.Sleep(120 * time.Millisecond)

	// Truncate in place to a shorter file; a size-based tailer must notice.
	if err := os.WriteFile(path, []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := waitLine(t, out, 2*time.Second); got != "new" {
		t.Fatalf("post-truncation line = %q, want %q", got, "new")
	}
}

func TestTailerNewFileReadFromStart(t *testing.T) {
	dir := t.TempDir()
	out, stop := startTailer(t, &Tailer{
		Dir: dir, StateFile: filepath.Join(dir, "state", "offsets.json"),
		PollInterval: 20 * time.Millisecond, SaveInterval: 30 * time.Millisecond,
	})
	defer stop()
	time.Sleep(100 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(dir, "new.log"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := waitLine(t, out, 2*time.Second); got != "hello" {
		t.Fatalf("new-file line = %q, want %q", got, "hello")
	}
}

// TestTailerPreservesPartialLineAcrossRestart verifies the persisted offset
// lags the buffered partial line, so a restart re-reads rather than loses it.
func TestTailerPreservesPartialLineAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state", "offsets.json")
	path := filepath.Join(dir, "device.log")
	if err := os.WriteFile(path, []byte("complete\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out1, stop1 := startTailer(t, &Tailer{
		Dir: dir, StateFile: state,
		PollInterval: 20 * time.Millisecond, SaveInterval: 25 * time.Millisecond,
	})
	time.Sleep(60 * time.Millisecond)
	// A line without a trailing newline stays buffered, unemitted.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("partial line")
	f.Close()
	time.Sleep(150 * time.Millisecond)
	stop1()

	select {
	case line := <-out1:
		t.Fatalf("emitted an unterminated line: %q", line)
	default:
	}

	// Complete the line while stopped; a correct restart re-reads it whole.
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(" finished\n")
	f.Close()

	out2, stop2 := startTailer(t, &Tailer{
		Dir: dir, StateFile: state,
		PollInterval: 20 * time.Millisecond, SaveInterval: 25 * time.Millisecond,
	})
	defer stop2()

	if got := waitLine(t, out2, 2*time.Second); got != "partial line finished" {
		t.Fatalf("restart line = %q, want %q", got, "partial line finished")
	}
}

// TestTailerDropsOversizePartialLine ensures a newline-free file cannot grow
// memory without bound, and reading resumes after the next newline.
func TestTailerDropsOversizePartialLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.log")
	var errs []error
	out, stop := startTailer(t, &Tailer{
		Dir: dir, StateFile: filepath.Join(dir, "state", "offsets.json"),
		PollInterval: 20 * time.Millisecond, SaveInterval: 25 * time.Millisecond,
		OnError: func(e error) { errs = append(errs, e) },
	})
	defer stop()
	time.Sleep(80 * time.Millisecond)

	f, _ := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	f.Write([]byte(strings.Repeat("x", MaxPartialLine+1024)))
	f.Write([]byte("\nafter\n"))
	f.Close()

	if got := waitLine(t, out, 3*time.Second); got != "after" {
		t.Fatalf("line after oversize = %q, want %q", got, "after")
	}
	if len(errs) == 0 {
		t.Fatal("expected an oversize-line warning")
	}
}
