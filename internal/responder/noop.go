package responder

import "context"

// NoopResponder is used when the responder is disabled (default).
type NoopResponder struct{}

func (NoopResponder) Ban(_ context.Context, _ string) error    { return nil }
func (NoopResponder) Unban(_ context.Context, _ string) error  { return nil }
func (NoopResponder) List(_ context.Context) ([]string, error) { return []string{}, nil }
func (NoopResponder) Name() string                             { return "noop" }
