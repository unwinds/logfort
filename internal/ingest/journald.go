package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"time"
)

type journaldSource struct {
	unit string
}

// NewJournaldSource returns a Source that follows journald for the given systemd unit.
// Requires journalctl to be present in PATH.
func NewJournaldSource(unit string) Source {
	return &journaldSource{unit: unit}
}

func (j *journaldSource) Info() SourceInfo {
	return SourceInfo{Kind: "journald", Target: j.unit}
}

// journaldEntry holds the subset of journald JSON fields we need.
type journaldEntry struct {
	RealtimeTimestamp string          `json:"__REALTIME_TIMESTAMP"`
	Hostname          string          `json:"_HOSTNAME"`
	SyslogIdentifier  string          `json:"SYSLOG_IDENTIFIER"`
	PID               string          `json:"_PID"`
	Message           json.RawMessage `json:"MESSAGE"`
}

// Start launches `journalctl -o json --follow --lines=0 --unit=<unit>` and
// forwards reconstructed syslog lines to out until ctx is cancelled.
func (j *journaldSource) Start(ctx context.Context, out chan<- string) error {
	jctlPath, err := exec.LookPath("journalctl")
	if err != nil {
		return fmt.Errorf("journalctl not found in PATH: %w", err)
	}

	cmd := exec.CommandContext(ctx, jctlPath,
		"-o", "json",
		"--follow",
		"--lines=0",
		"--unit="+j.unit,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("pipe journalctl stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start journalctl: %w", err)
	}
	slog.Info("following journald", "unit", j.unit)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		raw := scanner.Text()
		if raw == "" {
			continue
		}
		var entry journaldEntry
		if err := json.Unmarshal([]byte(raw), &entry); err != nil {
			continue
		}
		line := journaldToSyslog(entry)
		if line == "" {
			continue
		}
		select {
		case out <- line:
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return ctx.Err()
		}
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("journalctl stdout: %w", err)
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if waitErr != nil {
		return fmt.Errorf("journalctl exited: %w", waitErr)
	}
	return fmt.Errorf("journalctl exited unexpectedly")
}

// journaldToSyslog converts a journald entry to an RFC3339 syslog line that
// parse.ParseLine can handle: "2024-01-15T10:30:00Z host proc[pid]: message"
func journaldToSyslog(e journaldEntry) string {
	if e.SyslogIdentifier == "" {
		return ""
	}
	msg := decodeJournaldMessage(e.Message)
	if msg == "" {
		return ""
	}

	var ts time.Time
	if e.RealtimeTimestamp != "" {
		if us, err := strconv.ParseInt(e.RealtimeTimestamp, 10, 64); err == nil {
			ts = time.UnixMicro(us).UTC()
		}
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	host := e.Hostname
	if host == "" {
		host = "localhost"
	}
	if e.PID != "" {
		return fmt.Sprintf("%s %s %s[%s]: %s",
			ts.Format(time.RFC3339), host, e.SyslogIdentifier, e.PID, msg)
	}
	return fmt.Sprintf("%s %s %s: %s",
		ts.Format(time.RFC3339), host, e.SyslogIdentifier, msg)
}

// decodeJournaldMessage extracts the MESSAGE string from journald JSON.
// journald encodes MESSAGE as a JSON string normally, but as a JSON array of
// byte values when the message contains non-UTF-8 bytes.
func decodeJournaldMessage(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var nums []int
	if json.Unmarshal(raw, &nums) == nil {
		b := make([]byte, len(nums))
		for i, v := range nums {
			if v < 0 || v > 255 {
				return ""
			}
			b[i] = byte(v)
		}
		return string(b)
	}
	return ""
}
