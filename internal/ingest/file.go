package ingest

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/nxadm/tail"
)

// fileSource tails a log file and forwards lines to a channel.
type fileSource struct {
	path string
}

// NewFileSource returns a Source that tails the file at path.
// The file need not exist at construction time.
func NewFileSource(path string) Source {
	return &fileSource{path: path}
}

// Start begins tailing the file. It blocks until ctx is cancelled.
func (f *fileSource) Start(ctx context.Context, out chan<- string) error {
	t, err := tail.TailFile(f.path, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Logger:    tail.DiscardingLogger,
	})
	if err != nil {
		return fmt.Errorf("tail %q: %w", f.path, err)
	}

	slog.Info("tailing log file", "path", f.path)

	defer func() {
		t.Stop()
		t.Cleanup()
	}()

	for {
		select {
		case line, ok := <-t.Lines:
			if !ok {
				return nil
			}
			if line.Err != nil {
				slog.Warn("tail error", "path", f.path, "err", line.Err)
				continue
			}
			select {
			case out <- line.Text:
			case <-ctx.Done():
				return ctx.Err()
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
