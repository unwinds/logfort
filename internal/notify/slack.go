package notify

import (
	"context"
	"net/http"
	"time"
)

type slackNotifier struct {
	url    string
	client *http.Client
}

// NewSlack returns a Notifier that posts to a Slack incoming webhook.
func NewSlack(url string) Notifier {
	return &slackNotifier{
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *slackNotifier) Name() string { return "slack" }

func (s *slackNotifier) Send(ctx context.Context, msg Message) error {
	// Incoming webhooks accept mrkdwn in "text"; errors come back as a plain
	// text body ("invalid_token", "no_service", …) with a 4xx status.
	payload := map[string]any{
		"text": "*" + msg.Title + "*\n" + msg.Body,
	}
	status, body, err := postJSON(ctx, s.client, s.url, payload)
	if err != nil {
		return err
	}
	if status >= 400 {
		return httpError("slack", status, body)
	}
	return nil
}
