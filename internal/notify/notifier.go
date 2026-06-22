package notify

import "context"

// Notifier delivers alert messages to an external channel.
type Notifier interface {
	Send(ctx context.Context, msg Message) error
	Name() string
}

// Message is a notification payload.
type Message struct {
	Title     string
	Body      string
	IP        string
	EventType string
	Country   string
	TS        int64
}
