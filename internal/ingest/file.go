package ingest

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/nxadm/tail"
)

// fileSource tails a log file and forwards lines to a channel.
type fileSource struct {
	path      string
	fromStart bool
}

// NewFileSource returns a Source that tails path starting from the current end.
func NewFileSource(path string) Source {
	return &fileSource{path: path}
}

// NewFileSourceFromStart returns a Source that replays path from the beginning
// on every start, then follows for new lines. Use for state-bearing logs like
// fail2ban.log where full history is needed to reconstruct current state.
func NewFileSourceFromStart(path string) Source {
	return &fileSource{path: path, fromStart: true}
}

func (f *fileSource) Info() SourceInfo {
	return SourceInfo{Kind: "file", Target: f.path}
}

// Start begins tailing the file. It blocks until ctx is cancelled.
//
// A pre-flight open check turns the two most common deployment mistakes —
// a missing bind mount and a log file the container user cannot read — into
// a loud, retried error instead of a silent empty dashboard. The pipeline's
// retry loop re-invokes Start with backoff, so the source recovers as soon
// as the file appears or becomes readable.
func (f *fileSource) Start(ctx context.Context, out chan<- string) error {
	probe, err := os.Open(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("log file %q does not exist — check the volume mount / LOGFORT_LOG_PATHS", f.path)
		}
		if os.IsPermission(err) {
			return fmt.Errorf("log file %q is not readable by this process — add the log group to the container (group_add) or run it with a user that can read the file: %w", f.path, err)
		}
		return fmt.Errorf("open log file %q: %w", f.path, err)
	}
	probe.Close()

	loc := (*tail.SeekInfo)(nil) // default: start from end
	if f.fromStart {
		loc = &tail.SeekInfo{Offset: 0, Whence: io.SeekStart}
	}
	t, err := tail.TailFile(f.path, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Location:  loc,
		Logger:    newTailLogger(f.path),
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
				return fmt.Errorf("tail %q: line channel closed", f.path)
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

// newTailLogger routes the tail library's internal messages (waiting for the
// file, re-opening after rotation, read errors) into slog instead of
// discarding them — those messages are exactly what explains "no events".
func newTailLogger(path string) *log.Logger {
	return log.New(&tailLogWriter{path: path}, "", 0)
}

type tailLogWriter struct{ path string }

func (w *tailLogWriter) Write(p []byte) (int, error) {
	slog.Info("tail", "path", w.path, "msg", strings.TrimSpace(string(p)))
	return len(p), nil
}
