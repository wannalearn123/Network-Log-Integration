package telegrambot

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"siskamlan/internal/telegramauth"
)

// fakeAPI records every sendMessage the bot makes.
type fakeAPI struct {
	mu   sync.Mutex
	sent []sentMsg
}

type sentMsg struct {
	ChatID string
	Text   string
}

func (f *fakeAPI) handler(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	if strings.HasSuffix(r.URL.Path, "/sendMessage") {
		var m struct {
			ChatID string `json:"chat_id"`
			Text   string `json:"text"`
		}
		_ = json.Unmarshal(raw, &m)
		f.mu.Lock()
		f.sent = append(f.sent, sentMsg{m.ChatID, m.Text})
		f.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
}

func (f *fakeAPI) last() sentMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return sentMsg{}
	}
	return f.sent[len(f.sent)-1]
}

func newBot(t *testing.T, status StatusFunc) (*Bot, *fakeAPI, *telegramauth.Store) {
	t.Helper()
	api := &fakeAPI{}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	t.Cleanup(srv.Close)
	auth := telegramauth.Open(filepath.Join(t.TempDir(), "telegram_auth.json"))
	b, err := New(Options{Token: "tok", APIBase: srv.URL, Auth: auth, Status: status})
	if err != nil {
		t.Fatal(err)
	}
	return b, api, auth
}

func msg(chat int64, text string) update {
	u := update{UpdateID: 1}
	u.Message = &struct {
		Text string `json:"text"`
		Chat struct {
			ID    int64  `json:"id"`
			Title string `json:"title"`
			First string `json:"first_name"`
			User  string `json:"username"`
		} `json:"chat"`
	}{Text: text}
	u.Message.Chat.ID = chat
	u.Message.Chat.User = "alice"
	return u
}

func TestUnknownChatGetsOnlyStartPrompt(t *testing.T) {
	b, api, _ := newBot(t, func(context.Context) Status { return Status{PipelineRunning: true} })
	b.handle(context.Background(), msg(42, "/status"))
	got := api.last()
	if got.ChatID != "42" || !strings.Contains(got.Text, "/start") {
		t.Fatalf("unknown chat got %+v, want /start prompt", got)
	}
	if strings.Contains(got.Text, "Pipeline") {
		t.Fatal("unknown chat received status data")
	}
}

func TestCaptchaFlowAuthorizes(t *testing.T) {
	b, api, auth := newBot(t, nil)
	ctx := context.Background()

	b.handle(ctx, msg(42, "/start"))
	pending, _ := auth.PendingRequests()
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	code := pending[0].Code

	b.handle(ctx, msg(42, strings.ToLower(code)))
	if ok, _ := auth.IsAuthorized("42"); !ok {
		t.Fatalf("chat not authorized; last reply: %q", api.last().Text)
	}
	if !strings.Contains(api.last().Text, "granted") {
		t.Fatalf("no grant confirmation: %q", api.last().Text)
	}
}

func TestWrongCodeIsRejected(t *testing.T) {
	b, api, auth := newBot(t, nil)
	ctx := context.Background()
	b.handle(ctx, msg(42, "/start"))
	b.handle(ctx, msg(42, "ZZZZZZ"))
	if ok, _ := auth.IsAuthorized("42"); ok {
		t.Fatal("wrong code authorized the chat")
	}
	if !strings.Contains(api.last().Text, "Wrong") && !strings.Contains(api.last().Text, "No active") {
		t.Fatalf("unexpected reply: %q", api.last().Text)
	}
}

func TestAuthorizedChatGetsStatus(t *testing.T) {
	status := func(context.Context) Status {
		return Status{PipelineRunning: true, DBReachable: true, Anomalies1h: 3, Anomalies24h: 9,
			LastIngest: time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)}
	}
	b, api, auth := newBot(t, status)
	ctx := context.Background()
	b.handle(ctx, msg(42, "/start"))
	pending, _ := auth.PendingRequests()
	b.handle(ctx, msg(42, pending[0].Code))

	b.handle(ctx, msg(42, "/status"))
	got := api.last().Text
	for _, want := range []string{"Pipeline: running", "Database: reachable", "3 in the last hour", "9 in 24h"} {
		if !strings.Contains(got, want) {
			t.Errorf("status missing %q:\n%s", want, got)
		}
	}
}

func TestStatusReportsDatabaseDown(t *testing.T) {
	status := func(context.Context) Status {
		return Status{PipelineRunning: true, DBError: "connection refused"}
	}
	b, api, auth := newBot(t, status)
	ctx := context.Background()
	b.handle(ctx, msg(42, "/start"))
	pending, _ := auth.PendingRequests()
	b.handle(ctx, msg(42, pending[0].Code))
	b.handle(ctx, msg(42, "/status"))
	if !strings.Contains(api.last().Text, "unreachable (connection refused)") {
		t.Fatalf("db outage not reported: %q", api.last().Text)
	}
}

func TestCommandSuffixAndCase(t *testing.T) {
	if got := command("/Status@SiskamlanBot extra"); got != "/status" {
		t.Fatalf("command = %q, want /status", got)
	}
}

func TestNewRequiresTokenAndAuth(t *testing.T) {
	if _, err := New(Options{Auth: telegramauth.Open("x")}); err == nil {
		t.Fatal("missing token accepted")
	}
	if _, err := New(Options{Token: "t"}); err == nil {
		t.Fatal("missing auth store accepted")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	// The stub holds each poll open until release is closed, like a real
	// long-poll. release must close before srv.Close, which waits on handlers.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	auth := telegramauth.Open(filepath.Join(t.TempDir(), "a.json"))
	b, _ := New(Options{Token: "tok", APIBase: srv.URL, Auth: auth})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	close(release)
	srv.Close()
}

// TestNewRejectsMalformedAPIBase pins the bug where an inline comment in .env
// became part of the URL and every poll failed silently in a retry loop.
func TestNewRejectsMalformedAPIBase(t *testing.T) {
	auth := telegramauth.Open(filepath.Join(t.TempDir(), "a.json"))
	bad := []string{"https://api.telegram.org   # optional override", "api.telegram.org", "ftp://x"}
	for _, base := range bad {
		if _, err := New(Options{Token: "t", APIBase: base, Auth: auth}); err == nil {
			t.Errorf("APIBase %q accepted", base)
		}
	}
	if _, err := New(Options{Token: "t", APIBase: "", Auth: auth}); err != nil {
		t.Fatalf("empty base should use the default: %v", err)
	}
}
