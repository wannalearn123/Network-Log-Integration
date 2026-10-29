package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"siskamlan/internal/telegramauth"
)

// telegramPanel lists pending captcha requests and authorized Telegram chats.
// The operator reads a pending code here and gives it to the requester, who
// types it into the bot. Revoke removes a chat's access.
type telegramPanel struct {
	auth    *telegramauth.Store
	pending []telegramauth.Pending
	chats   []telegramauth.Chat
	cursor  int
	status  string
	err     error
}

func newTelegramPanel(auth *telegramauth.Store) *telegramPanel {
	return &telegramPanel{auth: auth}
}

// open reloads both lists from the shared auth file.
func (p *telegramPanel) open() {
	p.reload()
	p.cursor = 0
	p.status = ""
}

func (p *telegramPanel) reload() {
	if p.auth == nil {
		p.err = fmt.Errorf("telegram auth not configured")
		return
	}
	pending, err := p.auth.PendingRequests()
	if err != nil {
		p.err = err
		return
	}
	chats, err := p.auth.Authorized()
	if err != nil {
		p.err = err
		return
	}
	p.err = nil
	p.pending = pending
	p.chats = chats
	if n := p.rowCount(); p.cursor >= n {
		p.cursor = maxInt(0, n-1)
	}
}

// rowCount is pending requests followed by authorized chats.
func (p *telegramPanel) rowCount() int { return len(p.pending) + len(p.chats) }

// update handles keys. It returns true when the panel should close.
func (p *telegramPanel) update(msg tea.KeyMsg) (close bool) {
	switch msg.String() {
	case "esc", "b", "T":
		return true
	case "up", "k":
		if p.cursor > 0 {
			p.cursor--
		}
	case "down", "j":
		if p.cursor < p.rowCount()-1 {
			p.cursor++
		}
	case "r":
		p.reload()
		p.status = "refreshed " + time.Now().Format("15:04:05")
	case "x", "d":
		p.removeSelected()
	}
	return false
}

// removeSelected rejects a pending request, or revokes an authorized chat.
func (p *telegramPanel) removeSelected() {
	if p.auth == nil || p.rowCount() == 0 {
		return
	}
	if p.cursor < len(p.pending) {
		id := p.pending[p.cursor].ID
		if err := p.auth.Reject(id); err != nil {
			p.status = "reject failed: " + err.Error()
			return
		}
		p.status = "rejected chat " + id
	} else {
		c := p.chats[p.cursor-len(p.pending)]
		if err := p.auth.Revoke(c.ID); err != nil {
			p.status = "revoke failed: " + err.Error()
			return
		}
		p.status = "revoked chat " + c.ID
	}
	p.reload()
}

// view renders the panel in the same card style as the other editors.
func (p *telegramPanel) view(width, height int) string {
	var b strings.Builder
	b.WriteString(styleBrand.Render("◈ TELEGRAM ACCESS"))
	b.WriteString(styleDim.Render("   r refresh · x reject/revoke · esc back"))
	b.WriteString("\n")
	b.WriteString(styleDim.Render("Give a pending code to the requester; they type it into the bot."))
	b.WriteString("\n\n")

	if p.err != nil {
		b.WriteString(styleError.Render("! " + p.err.Error()))
		b.WriteString("\n")
	}

	row := 0
	line := func(selected bool, text string) {
		if selected {
			text = styleSelected.Render(text)
		}
		b.WriteString(text + "\n")
	}

	b.WriteString(styleAccent.Render("PENDING REQUESTS") + "\n")
	if len(p.pending) == 0 {
		b.WriteString(styleDim.Render("   none waiting") + "\n")
	}
	now := time.Now()
	for _, pr := range p.pending {
		left := pr.ExpiresAt.Sub(now).Round(time.Second)
		text := fmt.Sprintf("   %s  %-20s  %-12s  %s left",
			styleAccentHi.Render(pr.Code), truncateWidth(pr.Name, 20), pr.ID, shortDur(left))
		if pr.Failures > 0 {
			text += styleWarn.Render(fmt.Sprintf("  %d wrong", pr.Failures))
		}
		line(row == p.cursor, text)
		row++
	}

	b.WriteString("\n" + styleAccent.Render("AUTHORIZED CHATS") + "\n")
	if len(p.chats) == 0 {
		b.WriteString(styleDim.Render("   none yet — approve a request above") + "\n")
	}
	for _, c := range p.chats {
		text := fmt.Sprintf("   %-20s  %-12s  approved %s",
			truncateWidth(c.Name, 20), c.ID, c.ApprovedAt.Format("2006-01-02 15:04"))
		line(row == p.cursor, text)
		row++
	}

	if p.status != "" {
		b.WriteString("\n" + styleDim.Render(p.status))
	}
	return centerBlock(modalBox(b.String(), minInt(width-4, 96)), width, height)
}

// shortDur formats a remaining duration compactly, never negative.
func shortDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	return fmt.Sprintf("%d:%02d", int(d.Minutes()), int(d.Seconds())%60)
}
