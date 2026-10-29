// Package telegramauth decides which Telegram chats may use the bot.
//
// Access is granted by a captcha: an unknown chat sends /start, the system
// generates a code and shows it on the operator's dashboard, and the requester
// types it back. The operator reads the code from the TUI and passes it to the
// requester in person, so nobody can self-enrol without someone seeing the
// dashboard.
//
// State lives in a single JSON file so the bot and the TUI can run in separate
// processes and still share one view of who is authorized.
package telegramauth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"siskamlan/internal/config"
)

const (
	// CodeLength is the number of characters in a captcha.
	CodeLength = 6
	// codeAlphabet omits look-alikes (0/O, 1/I/L) so codes read back cleanly.
	codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	// CodeTTL is how long a pending code stays valid.
	CodeTTL = 2 * time.Minute
	// MaxFailures wrong attempts lock a chat out for LockoutFor.
	MaxFailures = 3
	LockoutFor  = 5 * time.Minute
	// MaxPending bounds the pending list so /start spam cannot grow the file.
	MaxPending = 50
)

// Errors returned by Verify and RequestCode.
var (
	ErrNoPending   = errors.New("no pending request for this chat")
	ErrExpired     = errors.New("code expired")
	ErrLocked      = errors.New("too many wrong attempts")
	ErrWrongCode   = errors.New("wrong code")
	ErrPendingFull = errors.New("too many pending requests")
	ErrAlreadyAuth = errors.New("chat already authorized")
)

// Chat is an authorized chat.
type Chat struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ApprovedAt time.Time `json:"approved_at"`
}

// Pending is an unverified request waiting for its code.
type Pending struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	RequestedAt time.Time `json:"requested_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Failures    int       `json:"failures"`
	LockedUntil time.Time `json:"locked_until,omitempty"`
}

type fileFormat struct {
	Authorized []Chat    `json:"authorized"`
	Pending    []Pending `json:"pending"`
}

// Store is the file-backed auth state. Every mutation is written atomically
// before it returns, and reads re-check the file so a change made by another
// process is seen without a restart.
type Store struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
}

// Open binds a Store to path. The file is created on first write.
func Open(path string) *Store {
	return &Store{path: path, now: time.Now}
}

// lock serialises access within this process and across processes. The bot
// and the TUI run as separate processes and both write the same file, so an
// advisory flock on a sidecar file is what keeps a read-modify-write atomic.
func (s *Store) lock() func() {
	s.mu.Lock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return s.mu.Unlock
	}
	f, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return s.mu.Unlock
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		s.mu.Unlock()
	}
}

// AuthorizedIDs returns the IDs of authorized chats, for alert fan-out.
func (s *Store) AuthorizedIDs() ([]string, error) {
	chats, err := s.Authorized()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(chats))
	for _, c := range chats {
		ids = append(ids, c.ID)
	}
	return ids, nil
}

// load reads the file. A missing file is an empty state.
func (s *Store) load() (fileFormat, error) {
	var ff fileFormat
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return ff, nil
	}
	if err != nil {
		return ff, fmt.Errorf("telegramauth: read %s: %w", s.path, err)
	}
	if len(raw) == 0 {
		return ff, nil
	}
	if err := json.Unmarshal(raw, &ff); err != nil {
		return ff, fmt.Errorf("telegramauth: decode %s: %w", s.path, err)
	}
	return ff, nil
}

func (s *Store) save(ff fileFormat) error {
	sort.Slice(ff.Authorized, func(i, j int) bool { return ff.Authorized[i].ID < ff.Authorized[j].ID })
	sort.Slice(ff.Pending, func(i, j int) bool { return ff.Pending[i].RequestedAt.Before(ff.Pending[j].RequestedAt) })
	raw, err := json.MarshalIndent(ff, "", "  ")
	if err != nil {
		return err
	}
	return config.WriteAtomic(s.path, append(raw, '\n'))
}

// prune drops expired pending requests that were never completed.
func (s *Store) prune(ff *fileFormat) {
	now := s.now()
	kept := ff.Pending[:0]
	for _, p := range ff.Pending {
		if now.Before(p.ExpiresAt) {
			kept = append(kept, p)
		}
	}
	ff.Pending = kept
}

// IsAuthorized reports whether chatID may use the bot.
func (s *Store) IsAuthorized(chatID string) (bool, error) {
	unlock := s.lock()
	defer unlock()
	ff, err := s.load()
	if err != nil {
		return false, err
	}
	for _, c := range ff.Authorized {
		if c.ID == chatID {
			return true, nil
		}
	}
	return false, nil
}

// RequestCode creates a pending request for an unknown chat and returns the
// code to show on the dashboard. A chat that already has a live request gets
// its existing code back, so repeated /start does not reshuffle it.
func (s *Store) RequestCode(chatID, name string) (Pending, error) {
	unlock := s.lock()
	defer unlock()
	ff, err := s.load()
	if err != nil {
		return Pending{}, err
	}
	for _, c := range ff.Authorized {
		if c.ID == chatID {
			return Pending{}, ErrAlreadyAuth
		}
	}
	s.prune(&ff)
	for i, p := range ff.Pending {
		if p.ID == chatID {
			if p.Name == "" && name != "" {
				ff.Pending[i].Name = name
				if err := s.save(ff); err != nil {
					return Pending{}, err
				}
			}
			return ff.Pending[i], nil
		}
	}
	if len(ff.Pending) >= MaxPending {
		return Pending{}, ErrPendingFull
	}

	code, err := newCode()
	if err != nil {
		return Pending{}, err
	}
	now := s.now()
	p := Pending{
		ID:          chatID,
		Name:        name,
		Code:        code,
		RequestedAt: now,
		ExpiresAt:   now.Add(CodeTTL),
	}
	ff.Pending = append(ff.Pending, p)
	if err := s.save(ff); err != nil {
		return Pending{}, err
	}
	return p, nil
}

// Verify checks a code typed by the requester. On success the chat moves from
// pending to authorized. Each wrong answer counts toward a lockout.
func (s *Store) Verify(chatID, input string) error {
	unlock := s.lock()
	defer unlock()
	ff, err := s.load()
	if err != nil {
		return err
	}
	s.prune(&ff)

	idx := -1
	for i, p := range ff.Pending {
		if p.ID == chatID {
			idx = i
			break
		}
	}
	if idx < 0 {
		_ = s.save(ff)
		return ErrNoPending
	}
	p := &ff.Pending[idx]
	now := s.now()

	if now.Before(p.LockedUntil) {
		return ErrLocked
	}
	if input != p.Code {
		p.Failures++
		if p.Failures >= MaxFailures {
			p.Failures = 0
			p.LockedUntil = now.Add(LockoutFor)
			if err := s.save(ff); err != nil {
				return err
			}
			return ErrLocked
		}
		if err := s.save(ff); err != nil {
			return err
		}
		return ErrWrongCode
	}

	ff.Authorized = append(ff.Authorized, Chat{ID: chatID, Name: p.Name, ApprovedAt: now})
	ff.Pending = append(ff.Pending[:idx], ff.Pending[idx+1:]...)
	return s.save(ff)
}

// Authorized returns every authorized chat, sorted by ID.
func (s *Store) Authorized() ([]Chat, error) {
	unlock := s.lock()
	defer unlock()
	ff, err := s.load()
	return ff.Authorized, err
}

// PendingRequests returns live pending requests, sorted by request time.
func (s *Store) PendingRequests() ([]Pending, error) {
	unlock := s.lock()
	defer unlock()
	ff, err := s.load()
	if err != nil {
		return nil, err
	}
	s.prune(&ff)
	return ff.Pending, nil
}

// Revoke removes a chat's access.
func (s *Store) Revoke(chatID string) error {
	return s.edit(func(ff *fileFormat) bool {
		for i, c := range ff.Authorized {
			if c.ID == chatID {
				ff.Authorized = append(ff.Authorized[:i], ff.Authorized[i+1:]...)
				return true
			}
		}
		return false
	})
}

// Reject discards a pending request, for example after the operator sees an
// unexpected chat in the dashboard.
func (s *Store) Reject(chatID string) error {
	return s.edit(func(ff *fileFormat) bool {
		for i, p := range ff.Pending {
			if p.ID == chatID {
				ff.Pending = append(ff.Pending[:i], ff.Pending[i+1:]...)
				return true
			}
		}
		return false
	})
}

// edit applies a change under the lock and only writes when change reports it.
func (s *Store) edit(change func(*fileFormat) bool) error {
	unlock := s.lock()
	defer unlock()
	ff, err := s.load()
	if err != nil {
		return err
	}
	if !change(&ff) {
		return nil
	}
	return s.save(ff)
}

// newCode returns a random captcha from codeAlphabet using crypto/rand.
func newCode() (string, error) {
	max := big.NewInt(int64(len(codeAlphabet)))
	out := make([]byte, CodeLength)
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("telegramauth: random code: %w", err)
		}
		out[i] = codeAlphabet[n.Int64()]
	}
	return string(out), nil
}
