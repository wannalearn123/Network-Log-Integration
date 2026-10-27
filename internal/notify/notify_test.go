package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newTestNotifier builds a notifier pointed at a stub server.
func newTestNotifier(t *testing.T, server *httptest.Server) *Notifier {
	t.Helper()
	n := &Notifier{
		client:      server.Client(),
		queue:       make(chan string, queueSize),
		enabled:     true,
		minSev:      "HIGH",
		token:       "test-token",
		chatIDs:     []string{"123"},
		apiBase:     server.URL,
		maxAttempts: 2,
		backoff:     func(int) time.Duration { return time.Millisecond },
	}
	return n
}

// okServer accepts every send and records how many arrived.
func okServer(t *testing.T, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
}

// TestSendDelivers verifies a successful delivery.
func TestSendDelivers(t *testing.T) {
	var hits int32
	srv := okServer(t, &hits)
	defer srv.Close()

	n := newTestNotifier(t, srv)
	if !n.sendAll("hello") {
		t.Fatal("sendAll reported failure for a 200 ok response")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("requests = %d, want 1", hits)
	}
}

// TestSeverityGate blocks alerts below the configured minimum.
func TestSeverityGate(t *testing.T) {
	n := &Notifier{enabled: true, minSev: "HIGH", queue: make(chan string, 1)}
	n.Send("LOW", "should be dropped", 1)
	n.Send("MEDIUM", "should be dropped", 2)
	if len(n.queue) != 0 {
		t.Fatalf("below-minimum alerts were queued: %d", len(n.queue))
	}
}

// TestDisabledIsNoop checks NOTIFY_TELEGRAM off means nothing is queued.
func TestDisabledIsNoop(t *testing.T) {
	n := &Notifier{enabled: false, minSev: "LOW", queue: make(chan string, 1)}
	n.Send("CRITICAL", "x", 1)
	if len(n.queue) != 0 {
		t.Fatal("disabled notifier queued an alert")
	}
}

// TestQueueFullDrops checks bounded-queue behaviour under pressure.
func TestQueueFullDrops(t *testing.T) {
	n := &Notifier{enabled: true, minSev: "LOW", queue: make(chan string, 1)}
	n.once.Do(func() {}) // prevent a worker from draining the queue
	n.Send("HIGH", "first", 1)
	n.Send("HIGH", "second", 2) // must not block or panic
	if len(n.queue) != 1 {
		t.Fatalf("queue length = %d, want 1", len(n.queue))
	}
}

// TestRetryExhaustion checks failing sends stop after maxAttempts.
func TestRetryExhaustion(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := newTestNotifier(t, srv)
	n.maxAttempts = 3
	n.deliver("trouble")

	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

// TestRetrySucceedsAfterFailure stops retrying once a send works.
func TestRetrySucceedsAfterFailure(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			http.Error(w, "transient", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()

	n := newTestNotifier(t, srv)
	n.maxAttempts = 3
	n.deliver("eventually")

	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("attempts = %d, want 2 (stop after success)", got)
	}
}

// TestUnconfiguredFails checks a missing token is reported, not sent.
func TestUnconfiguredFails(t *testing.T) {
	var hits int32
	srv := okServer(t, &hits)
	defer srv.Close()

	n := &Notifier{
		client: srv.Client(), queue: make(chan string, 1),
		enabled: true, minSev: "LOW", apiBase: srv.URL,
		maxAttempts: 1, backoff: func(int) time.Duration { return 0 },
	}
	if n.sendAll("x") {
		t.Fatal("sendAll succeeded without a token")
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("a request was made without a token")
	}
}

// TestMinSeverityDefaults checks an invalid NOTIFY_MIN_SEVERITY falls back.
func TestMinSeverityDefaults(t *testing.T) {
	t.Setenv("NOTIFY_MIN_SEVERITY", "garbage")
	if got := envMinSeverity(); got != "HIGH" {
		t.Fatalf("min severity = %q, want HIGH", got)
	}
	t.Setenv("NOTIFY_MIN_SEVERITY", "medium")
	if got := envMinSeverity(); got != "MEDIUM" {
		t.Fatalf("min severity = %q, want MEDIUM", got)
	}
}

// TestEnabledParsing checks the master switch values.
func TestEnabledParsing(t *testing.T) {
	for _, v := range []string{"1", "true", "YES"} {
		t.Setenv("NOTIFY_TELEGRAM", v)
		if !envEnabled() {
			t.Errorf("%q should enable notifications", v)
		}
	}
	for _, v := range []string{"", "0", "off", "no"} {
		t.Setenv("NOTIFY_TELEGRAM", v)
		if envEnabled() {
			t.Errorf("%q should disable notifications", v)
		}
	}
}

// TestNewReadsChatIDs checks comma-separated chat IDs are split and trimmed.
func TestNewReadsChatIDs(t *testing.T) {
	t.Setenv("TELEGRAM_CHAT_ID", " 111 , 222 ,,333 ")
	t.Setenv("TELEGRAM_BOT_TOKEN", "tok")
	t.Setenv("NOTIFY_TELEGRAM", "1")
	n := New()
	if len(n.chatIDs) != 3 {
		t.Fatalf("chat IDs = %v, want 3", n.chatIDs)
	}
	if n.chatIDs[0] != "111" || n.chatIDs[2] != "333" {
		t.Fatalf("chat IDs not trimmed: %v", n.chatIDs)
	}
	if !n.Enabled() {
		t.Fatal("notifier should be enabled")
	}
}
