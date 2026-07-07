package notify

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

type ntfyNotifier struct {
	url    string // full topic URL, e.g. https://ntfy.sh/my-topic
	token  string // optional access token (Bearer)
	client *http.Client
}

// NewNtfy returns a Notifier that publishes to an ntfy topic URL.
// token is optional and used as a Bearer credential for protected topics.
func NewNtfy(url, token string) Notifier {
	return &ntfyNotifier{
		url:    url,
		token:  token,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *ntfyNotifier) Name() string { return "ntfy" }

func (n *ntfyNotifier) Send(ctx context.Context, msg Message) error {
	// ntfy takes the message as the raw request body; metadata goes in headers.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, strings.NewReader(msg.Body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", sanitizeHeaderValue(msg.Title))
	req.Header.Set("Tags", "shield")
	if msg.EventType == "ban" || msg.EventType == "accepted" {
		req.Header.Set("Priority", "high")
	}
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		return httpError("ntfy", resp.StatusCode, body)
	}
	return nil
}

// sanitizeHeaderValue strips CR/LF so a value is always a legal single-line
// HTTP header (ntfy metadata travels in headers, not the body).
func sanitizeHeaderValue(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}
