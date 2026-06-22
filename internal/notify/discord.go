package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord returned HTTP %d", resp.StatusCode)
	}
	return nil
}
