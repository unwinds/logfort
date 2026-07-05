package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const telegramAPIBase = "https://api.telegram.org"

type telegramNotifier struct {
	token   string
	chatID  string
	apiBase string
	client  *http.Client
}

// NewTelegram returns a Notifier that sends messages via the Telegram Bot API.
func NewTelegram(token, chatID string) Notifier {
	return &telegramNotifier{
		token:   token,
		chatID:  chatID,
		apiBase: telegramAPIBase,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (t *telegramNotifier) Name() string { return "telegram" }

func (t *telegramNotifier) Send(ctx context.Context, msg Message) error {
	text := "<b>" + escapeHTML(msg.Title) + "</b>\n" + escapeHTML(msg.Body)
	payload := map[string]any{
		"chat_id":    t.chatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	status, body, err := postJSON(ctx, t.client, t.apiBase+"/bot"+t.token+"/sendMessage", payload)
	if err != nil {
		return err
	}
	// Telegram always answers with {"ok":bool,...}; description carries the
	// actionable reason ("chat not found", "bot was blocked by the user", …).
	var tgResp struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(body, &tgResp)
	if status >= 400 || !tgResp.OK {
		if tgResp.Description != "" {
			return fmt.Errorf("telegram returned HTTP %d: %s", status, tgResp.Description)
		}
		return httpError("telegram", status, body)
	}
	return nil
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
