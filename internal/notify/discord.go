package notify

import (
	"context"
	"net/http"
	"time"
)

type discordNotifier struct {
	url    string
	client *http.Client
}

// NewDiscord returns a Notifier that POSTs a Discord webhook embed.
func NewDiscord(url string) Notifier {
	return &discordNotifier{
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (d *discordNotifier) Name() string { return "discord" }

func (d *discordNotifier) Send(ctx context.Context, msg Message) error {
	embed := map[string]any{
		"title":       msg.Title,
		"description": msg.Body,
		"color":       0xFF4444,
		"timestamp":   time.Unix(msg.TS, 0).UTC().Format(time.RFC3339),
	}
	payload := map[string]any{
		"embeds": []any{embed},
	}
	// Success is 204 No Content (webhook execute without ?wait=true).
	status, body, err := postJSON(ctx, d.client, d.url, payload)
	if err != nil {
		return err
	}
	if status >= 400 {
		return httpError("discord", status, body)
	}
	return nil
}
