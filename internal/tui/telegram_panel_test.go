package tui

import (
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"siskamlan/internal/telegramauth"
)

func newPanelWithAuth(t *testing.T) (*telegramPanel, *telegramauth.Store) {
	t.Helper()
	auth := telegramauth.Open(filepath.Join(t.TempDir(), "telegram_auth.json"))
	p := newTelegramPanel(auth)
	return p, auth
}

// TestTelegramPanelShowsPendingCode checks the operator sees the code the
// requester has to type back.
func TestTelegramPanelShowsPendingCode(t *testing.T) {
	p, auth := newPanelWithAuth(t)
	req, err := auth.RequestCode("42", "alice")
	if err != nil {
		t.Fatal(err)
	}
	p.open()
	out := p.view(110, 40)
	if !strings.Contains(out, req.Code) {
		t.Fatalf("pending code %q not shown:\n%s", req.Code, out)
	}
	if !strings.Contains(out, "PENDING REQUESTS") || !strings.Contains(out, "AUTHORIZED CHATS") {
		t.Fatal("panel sections missing")
	}
}

// TestTelegramPanelRevokeRemovesAccess checks x on an approved chat revokes it
// from the shared auth file, the same file the bot reads.
func TestTelegramPanelRevokeRemovesAccess(t *testing.T) {
	p, auth := newPanelWithAuth(t)
	req, _ := auth.RequestCode("42", "alice")
	if err := auth.Verify("42", req.Code); err != nil {
		t.Fatal(err)
	}
	p.open()
	if p.rowCount() != 1 {
		t.Fatalf("rows = %d, want 1", p.rowCount())
	}
	p.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	if ok, _ := auth.IsAuthorized("42"); ok {
		t.Fatal("revoke did not remove authorization")
	}
}

// TestTelegramPanelRejectPending checks x on a pending request discards it so
// its code can no longer be used.
func TestTelegramPanelRejectPending(t *testing.T) {
	p, auth := newPanelWithAuth(t)
	req, _ := auth.RequestCode("42", "alice")
	p.open()
	p.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	if err := auth.Verify("42", req.Code); err == nil {
		t.Fatal("rejected request's code still accepted")
	}
}

// TestTelegramPanelEscCloses checks esc returns to the dashboard.
func TestTelegramPanelEscCloses(t *testing.T) {
	p, _ := newPanelWithAuth(t)
	if !p.update(tea.KeyMsg{Type: tea.KeyEsc}) {
		t.Fatal("esc did not close the panel")
	}
}
