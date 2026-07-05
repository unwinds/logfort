package notify

import (
	"context"
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
	status, body, err := postJSON(ctx, w.client, w.url, payload)
	if err != nil {
		return err
	}
	if status >= 400 {
		return httpError("webhook", status, body)
	}
	return nil
}
