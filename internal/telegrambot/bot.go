// Package telegrambot runs the Telegram command loop: it admits new chats with
// a dashboard-issued code and answers /status for authorized chats.
//
// Unknown chats receive only the /start prompt. They never see status or
// alert data, so the bot cannot be used to probe the system.
package telegrambot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"siskamlan/internal/telegramauth"
)

const (
	defaultAPIBase = "https://api.telegram.org"
	pollTimeout    = 25 // seconds, long-poll
	requestTimeout = 35 * time.Second
	maxBackoff     = 30 * time.Second
)

// Status is the snapshot /status reports. Filled by the caller so this
// package does not depend on the store or the pipeline.
type Status struct {
	PipelineRunning bool
	DBReachable     bool
	DBError         string
	LastIngest      time.Time
	Anomalies1h     int
	Anomalies24h    int
}

// StatusFunc gathers a fresh Status for each /status request.
type StatusFunc func(ctx context.Context) Status

// Bot is the Telegram command loop.
type Bot struct {
	token   string
	apiBase string
	client  *http.Client
	auth    *telegramauth.Store
	status  StatusFunc
	offset  int64
}

// Options configure a Bot. Token and Auth are required.
type Options struct {
	Token   string
	APIBase string
	Auth    *telegramauth.Store
	Status  StatusFunc
}

// New builds a Bot. It does not start polling; call Run.
func New(opts Options) (*Bot, error) {
	if strings.TrimSpace(opts.Token) == "" {
		return nil, errors.New("telegrambot: token required")
	}
	if opts.Auth == nil {
		return nil, errors.New("telegrambot: auth store required")
	}
	base := strings.TrimRight(opts.APIBase, "/")
	if base == "" {
		base = defaultAPIBase
	}
	if u, err := url.Parse(base); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("telegrambot: invalid API base %q (want an http(s) URL)", base)
	}
	return &Bot{
		token:   opts.Token,
		apiBase: base,
		client:  &http.Client{Timeout: requestTimeout},
		auth:    opts.Auth,
		status:  opts.Status,
	}, nil
}

type update struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		Text string `json:"text"`
		Chat struct {
			ID    int64  `json:"id"`
			Title string `json:"title"`
			First string `json:"first_name"`
			User  string `json:"username"`
		} `json:"chat"`
	} `json:"message"`
}

// Run polls until ctx is cancelled. Transient API errors back off and retry;
// the loop never exits on its own.
func (b *Bot) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		updates, err := b.getUpdates(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("telegram: poll failed: %v (retry in %s)", err, backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = time.Second
		for _, u := range updates {
			b.offset = u.UpdateID + 1
			if u.Message != nil {
				b.handle(ctx, u)
			}
		}
	}
}

func (b *Bot) getUpdates(ctx context.Context) ([]update, error) {
	body, _ := json.Marshal(map[string]any{
		"offset":  b.offset,
		"timeout": pollTimeout,
	})
	var out struct {
		OK          bool     `json:"ok"`
		Description string   `json:"description"`
		Result      []update `json:"result"`
	}
	if err := b.call(ctx, "getUpdates", body, &out); err != nil {
		return nil, err
	}
	if !out.OK {
		return nil, fmt.Errorf("telegram: %s", out.Description)
	}
	return out.Result, nil
}

// handle routes one message. Authorization is checked before any command.
func (b *Bot) handle(ctx context.Context, u update) {
	chatID := fmt.Sprint(u.Message.Chat.ID)
	text := strings.TrimSpace(u.Message.Text)
	name := chatName(u)

	ok, err := b.auth.IsAuthorized(chatID)
	if err != nil {
		log.Printf("telegram: auth check: %v", err)
		return
	}
	if !ok {
		b.handleUnknown(ctx, chatID, name, text)
		return
	}

	switch command(text) {
	case "/status":
		b.sendStatus(ctx, chatID)
	case "/start":
		b.say(ctx, chatID, "You already have access. Send /status to check the system.")
	default:
		b.say(ctx, chatID, "Send /status to check the system.")
	}
}

// handleUnknown admits a chat through the captcha, or tells it how.
func (b *Bot) handleUnknown(ctx context.Context, chatID, name, text string) {
	if command(text) == "/start" {
		_, err := b.auth.RequestCode(chatID, name)
		switch {
		case err == nil:
			b.say(ctx, chatID, "Access needs approval. Ask the operator for the code shown on the SISKAMLAN dashboard, then send it here. The code expires in 2 minutes.")
		case errors.Is(err, telegramauth.ErrPendingFull):
			b.say(ctx, chatID, "Too many requests are waiting. Try again later.")
		default:
			log.Printf("telegram: request code: %v", err)
			b.say(ctx, chatID, "Could not start the approval. Try again later.")
		}
		return
	}

	if len(text) == telegramauth.CodeLength && !strings.HasPrefix(text, "/") {
		err := b.auth.Verify(chatID, strings.ToUpper(text))
		switch {
		case err == nil:
			b.say(ctx, chatID, "Access granted. Send /status to check the system.")
		case errors.Is(err, telegramauth.ErrWrongCode):
			b.say(ctx, chatID, "Wrong code.")
		case errors.Is(err, telegramauth.ErrLocked):
			b.say(ctx, chatID, "Too many wrong attempts. Wait a few minutes, then send /start again.")
		case errors.Is(err, telegramauth.ErrNoPending):
			b.say(ctx, chatID, "No active request. Send /start to get a new code.")
		default:
			log.Printf("telegram: verify: %v", err)
			b.say(ctx, chatID, "Could not check the code. Try again.")
		}
		return
	}

	b.say(ctx, chatID, "Send /start to request access.")
}

func (b *Bot) sendStatus(ctx context.Context, chatID string) {
	if b.status == nil {
		b.say(ctx, chatID, "Status is unavailable.")
		return
	}
	s := b.status(ctx)
	var lines []string
	lines = append(lines, "SISKAMLAN status")
	if s.PipelineRunning {
		lines = append(lines, "Pipeline: running")
	} else {
		lines = append(lines, "Pipeline: NOT running")
	}
	if s.DBReachable {
		lines = append(lines, "Database: reachable")
	} else {
		lines = append(lines, "Database: unreachable ("+s.DBError+")")
	}
	if s.LastIngest.IsZero() {
		lines = append(lines, "Last ingest: none yet")
	} else {
		lines = append(lines, "Last ingest: "+s.LastIngest.Format("2006-01-02 15:04:05"))
	}
	lines = append(lines, fmt.Sprintf("Anomalies: %d in the last hour, %d in 24h", s.Anomalies1h, s.Anomalies24h))
	b.say(ctx, chatID, strings.Join(lines, "\n"))
}

// command returns the bare command, dropping any @botname suffix.
func command(text string) string {
	first := strings.Fields(text)
	if len(first) == 0 {
		return ""
	}
	c := first[0]
	if i := strings.Index(c, "@"); i > 0 {
		c = c[:i]
	}
	return strings.ToLower(c)
}

func chatName(u update) string {
	m := u.Message
	if m.Chat.Title != "" {
		return m.Chat.Title
	}
	if m.Chat.User != "" {
		return "@" + m.Chat.User
	}
	return m.Chat.First
}

// say sends a plain text message. Failures are logged, never retried: a lost
// reply is recoverable by the requester sending again.
func (b *Bot) say(ctx context.Context, chatID, text string) {
	body, _ := json.Marshal(map[string]string{"chat_id": chatID, "text": text})
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := b.call(ctx, "sendMessage", body, &out); err != nil {
		log.Printf("telegram: send to %s: %v", chatID, err)
		return
	}
	if !out.OK {
		log.Printf("telegram: send to %s rejected: %s", chatID, out.Description)
	}
}

func (b *Bot) call(ctx context.Context, method string, body []byte, out any) error {
	url := fmt.Sprintf("%s/bot%s/%s", b.apiBase, b.token, method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Description string `json:"description"`
		}
		_ = json.Unmarshal(raw, &e)
		return fmt.Errorf("telegram HTTP %d: %s", resp.StatusCode, e.Description)
	}
	return json.Unmarshal(raw, out)
}
