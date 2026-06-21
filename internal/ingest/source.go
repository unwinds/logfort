package ingest

import "context"

// Source is a provider of raw log lines.
// Start sends lines to out until ctx is cancelled or the source is exhausted.
type Source interface {
	Start(ctx context.Context, out chan<- string) error
}
