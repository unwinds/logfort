package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type webhookNotifier struct {
	url    string
	client *http.Client
}

// NewWebhook returns a Notifier that POSTs a JSON payload to url.
func NewWebhook(url string) Notifier {
	return &webhookNotifier{
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *webhookNotifier) Name() string { return "webhook" }

func (w *webhookNotifier) Send(ctx context.Context, msg Message) error {
	payload := map[string]any{
		"title":      msg.Title,
		"body":       msg.Body,
		"ip":         msg.IP,
		"event_type": msg.EventType,
		"country":    msg.Country,
		"ts":         msg.TS,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}
