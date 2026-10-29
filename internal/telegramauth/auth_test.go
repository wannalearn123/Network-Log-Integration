package telegramauth

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s := Open(filepath.Join(t.TempDir(), "telegram_auth.json"))
	clock := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	return s, &clock
}

func TestRequestCodeIsStableAndWellFormed(t *testing.T) {
	s, _ := newTestStore(t)
	p1, err := s.RequestCode("111", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.Code) != CodeLength {
		t.Fatalf("code length = %d", len(p1.Code))
	}
	for _, r := range p1.Code {
		if !strings.ContainsRune(codeAlphabet, r) {
			t.Fatalf("code %q has disallowed rune %q", p1.Code, r)
		}
	}
	p2, _ := s.RequestCode("111", "alice")
	if p2.Code != p1.Code {
		t.Fatal("repeated /start reshuffled the code")
	}
}

func TestVerifyAuthorizes(t *testing.T) {
	s, _ := newTestStore(t)
	p, _ := s.RequestCode("111", "alice")
	if err := s.Verify("111", p.Code); err != nil {
		t.Fatalf("correct code rejected: %v", err)
	}
	ok, err := s.IsAuthorized("111")
	if err != nil || !ok {
		t.Fatalf("chat not authorized after verify: %v", err)
	}
	pending, _ := s.PendingRequests()
	if len(pending) != 0 {
		t.Fatalf("pending not cleared: %d", len(pending))
	}
}

func TestWrongCodeLocksOut(t *testing.T) {
	s, clock := newTestStore(t)
	p, _ := s.RequestCode("111", "alice")
	wrong := "ZZZZZZ"
	if wrong == p.Code {
		wrong = "YYYYYY"
	}
	for i := 0; i < MaxFailures-1; i++ {
		if err := s.Verify("111", wrong); !errors.Is(err, ErrWrongCode) {
			t.Fatalf("attempt %d: %v, want ErrWrongCode", i, err)
		}
	}
	if err := s.Verify("111", wrong); !errors.Is(err, ErrLocked) {
		t.Fatalf("after %d failures: %v, want ErrLocked", MaxFailures, err)
	}
	if err := s.Verify("111", p.Code); !errors.Is(err, ErrLocked) {
		t.Fatalf("correct code during lockout: %v, want ErrLocked", err)
	}
	// Lockout is 5 min but the code lives 2 min, so the request has expired
	// by the time the lockout ends and the chat must start over.
	*clock = clock.Add(LockoutFor + time.Second)
	if err := s.Verify("111", p.Code); !errors.Is(err, ErrNoPending) {
		t.Fatalf("after lockout expiry: %v, want ErrNoPending", err)
	}
}

func TestCodeExpires(t *testing.T) {
	s, clock := newTestStore(t)
	p, _ := s.RequestCode("111", "alice")
	*clock = clock.Add(CodeTTL + time.Second)
	if err := s.Verify("111", p.Code); !errors.Is(err, ErrNoPending) {
		t.Fatalf("expired code: %v, want ErrNoPending", err)
	}
	pending, _ := s.PendingRequests()
	if len(pending) != 0 {
		t.Fatal("expired request still listed")
	}
}

func TestPendingCapacity(t *testing.T) {
	s, _ := newTestStore(t)
	for i := 0; i < MaxPending; i++ {
		if _, err := s.RequestCode(string(rune('a'+i%26))+strings.Repeat("x", i), ""); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if _, err := s.RequestCode("overflow", ""); !errors.Is(err, ErrPendingFull) {
		t.Fatalf("over capacity: %v, want ErrPendingFull", err)
	}
}

func TestRevokeAndReject(t *testing.T) {
	s, _ := newTestStore(t)
	p, _ := s.RequestCode("111", "alice")
	_ = s.Verify("111", p.Code)
	if err := s.Revoke("111"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.IsAuthorized("111"); ok {
		t.Fatal("revoked chat still authorized")
	}
	if _, err := s.RequestCode("222", "bob"); err != nil {
		t.Fatal(err)
	}
	if err := s.Reject("222"); err != nil {
		t.Fatal(err)
	}
	if pending, _ := s.PendingRequests(); len(pending) != 0 {
		t.Fatal("rejected request still pending")
	}
}

func TestAlreadyAuthorizedCannotRequest(t *testing.T) {
	s, _ := newTestStore(t)
	p, _ := s.RequestCode("111", "alice")
	_ = s.Verify("111", p.Code)
	if _, err := s.RequestCode("111", "alice"); !errors.Is(err, ErrAlreadyAuth) {
		t.Fatalf("got %v, want ErrAlreadyAuth", err)
	}
}

func TestStateSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telegram_auth.json")
	a := Open(path)
	p, _ := a.RequestCode("111", "alice")
	_ = a.Verify("111", p.Code)

	b := Open(path)
	if ok, _ := b.IsAuthorized("111"); !ok {
		t.Fatal("authorization lost across reopen (second process would not see it)")
	}
}
