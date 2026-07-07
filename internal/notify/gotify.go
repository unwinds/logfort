package notify

import (
	"context"
	"net/http"
	"strings"
	"time"
)

type gotifyNotifier struct {
	base   string // server base URL, e.g. https://gotify.example.com
	token  string // application token
	client *http.Client
}

// NewGotify returns a Notifier that posts to a Gotify server's /message API.
func NewGotify(baseURL, token string) Notifier {
	return &gotifyNotifier{
		base:   strings.TrimRight(baseURL, "/"),
		token:  token,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (g *gotifyNotifier) Name() string { return "gotify" }

func (g *gotifyNotifier) Send(ctx context.Context, msg Message) error {
	priority := 5
	if msg.EventType == "ban" || msg.EventType == "accepted" {
		priority = 8
	}
	payload := map[string]any{
		"title":    msg.Title,
		"message":  msg.Body,
		"priority": priority,
	}
	// The token goes in a header, not the URL, so it never lands in access logs.
	status, body, err := postJSONHdr(ctx, g.client, g.base+"/message", payload,
		map[string]string{"X-Gotify-Key": g.token})
	if err != nil {
		return err
	}
	if status >= 400 {
		return httpError("gotify", status, body)
	}
	return nil
}
