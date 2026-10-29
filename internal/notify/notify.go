// Package notify delivers anomaly alerts to Telegram.
//
// It never returns errors to the caller: a failed notification must never
// interrupt detection. Delivery runs on a background worker with a bounded
// queue and exponential backoff, so a slow bot cannot stall the pipeline.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPIBase = "https://api.telegram.org"
	requestTimeout = 5 * time.Second
	queueSize      = 1000
	maxAttempts    = 4
)

var sevRank = map[string]int{"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

// Notifier is a Telegram alert sender. The zero value is not usable; use New.
type Notifier struct {
	client  *http.Client
	queue   chan string
	once    sync.Once
	enabled bool
	minSev  string
	token   string
	apiBase string
	// recipients returns the chats allowed to receive alerts. It is read on
	// every send so newly approved or revoked chats take effect immediately.
	recipients func() ([]string, error)

	// maxAttempts and backoff are overridable so tests need not sleep.
	maxAttempts int
	backoff     func(attempt int) time.Duration
}

// New builds a notifier from the environment. When notifications are disabled
// or unconfigured, Send is a no-op. recipients supplies the authorized chats.
func New(recipients func() ([]string, error)) *Notifier {
	n := &Notifier{
		client:     &http.Client{Timeout: requestTimeout},
		queue:      make(chan string, queueSize),
		enabled:    envEnabled(),
		minSev:     envMinSeverity(),
		token:      strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")),
		apiBase:    strings.TrimRight(getenv("TELEGRAM_API_BASE", defaultAPIBase), "/"),
		recipients: recipients,

		maxAttempts: maxAttempts,
		backoff:     func(attempt int) time.Duration { return time.Duration(1<<attempt) * time.Second },
	}
	return n
}

// Enabled reports whether alerts would be delivered.
func (n *Notifier) Enabled() bool { return n != nil && n.enabled }

func envEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NOTIFY_TELEGRAM"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func envMinSeverity() string {
	v := strings.ToUpper(strings.TrimSpace(os.Getenv("NOTIFY_MIN_SEVERITY")))
	if _, ok := sevRank[v]; ok {
		return v
	}
	return "HIGH"
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Send queues an alert for a fresh anomaly. It returns immediately.
func (n *Notifier) Send(severity, description string, anomalyID int) {
	if !n.Enabled() {
		return
	}
	if sevRank[severity] < sevRank[n.minSev] {
		return
	}
	n.once.Do(func() { go n.worker() })

	text := fmt.Sprintf("🚨 SISKAMLAN ALERT [%s]\nTime: %s\nID: %d\n%s",
		severity, time.Now().Format("2006-01-02 15:04:05"), anomalyID, description)

	select {
	case n.queue <- text:
	default:
		log.Print("notify: alert queue full — dropping notification")
	}
}

// worker drains the queue until the process exits.
func (n *Notifier) worker() {
	for text := range n.queue {
		n.deliver(text)
	}
}

// deliver retries with exponential backoff.
func (n *Notifier) deliver(text string) {
	attempts := n.maxAttempts
	if attempts <= 0 {
		attempts = maxAttempts
	}
	backoff := n.backoff
	if backoff == nil {
		backoff = func(a int) time.Duration { return time.Duration(1<<a) * time.Second }
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if n.sendAll(text) {
			return
		}
		if attempt < attempts-1 {
			time.Sleep(backoff(attempt))
		}
	}
	log.Printf("notify: dropping alert after %d delivery attempts", attempts)
}

// sendAll posts to every configured chat.
func (n *Notifier) sendAll(text string) bool {
	if n.token == "" || n.recipients == nil {
		log.Print("notify: Telegram not configured (missing TELEGRAM_BOT_TOKEN or auth provider) — skipping")
		return false
	}
	chatIDs, err := n.recipients()
	if err != nil {
		log.Printf("notify: load authorized chats: %v", err)
		return false
	}
	if len(chatIDs) == 0 {
		log.Print("notify: no authorized Telegram chats yet — alert not delivered")
		return false
	}
	url := fmt.Sprintf("%s/bot%s/sendMessage", n.apiBase, n.token)

	okAll := true
	for _, chatID := range chatIDs {
		body, err := json.Marshal(map[string]string{"chat_id": chatID, "text": text})
		if err != nil {
			okAll = false
			continue
		}
		resp, err := n.client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("notify: send failed for %s: %v", chatID, err)
			okAll = false
			continue
		}
		var payload struct {
			OK          bool   `json:"ok"`
			Description string `json:"description"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&payload)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("notify: Telegram HTTP %d for %s", resp.StatusCode, chatID)
			okAll = false
			continue
		}
		if decErr != nil || !payload.OK {
			log.Printf("notify: Telegram error for %s: %s", chatID, payload.Description)
			okAll = false
		}
	}
	return okAll
}
