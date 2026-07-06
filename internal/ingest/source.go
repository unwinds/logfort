package ingest

import "context"

// Source is a provider of raw log lines.
// Start sends lines to out until ctx is cancelled or the source is exhausted.
type Source interface {
	Start(ctx context.Context, out chan<- string) error
	// Info describes the source for health reporting.
	Info() SourceInfo
}

// SourceInfo identifies a log source.
type SourceInfo struct {
	Kind   string `json:"kind"`   // "file" or "journald"
	Target string `json:"target"` // file path or systemd unit
}

// SourceStatus is the runtime health of one source, exposed via /api/health
// so a broken mount or unreadable log file is visible in the UI instead of
// failing silently.
type SourceStatus struct {
	SourceInfo
	State string `json:"state"` // "starting", "running", "error"
	Error string `json:"error,omitempty"`
}
