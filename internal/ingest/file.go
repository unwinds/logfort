package ingest

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/nxadm/tail"
)

// fileSource tails a log file and forwards lines to a channel.
type fileSource struct {
	path      string
	fromStart bool
}

// NewFileSource returns a Source that tails path starting from the current end.
// The file need not exist at construction time.
func NewFileSource(path string) Source {
	return &fileSource{path: path}
}

// NewFileSourceFromStart returns a Source that replays path from the beginning
// on every start, then follows for new lines. Use for state-bearing logs like
// fail2ban.log where full history is needed to reconstruct current state.
func NewFileSourceFromStart(path string) Source {
	return &fileSource{path: path, fromStart: true}
}

// Start begins tailing the file. It blocks until ctx is cancelled.
func (f *fileSource) Start(ctx context.Context, out chan<- string) error {
	loc := (*tail.SeekInfo)(nil) // default: start from end
	if f.fromStart {
		loc = &tail.SeekInfo{Offset: 0, Whence: io.SeekStart}
	}
	t, err := tail.TailFile(f.path, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Location:  loc,
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
