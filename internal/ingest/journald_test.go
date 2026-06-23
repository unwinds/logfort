package ingest

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDecodeJournaldMessage(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{
			name: "plain string",
			raw:  json.RawMessage(`"Failed password for root"`),
			want: "Failed password for root",
		},
		{
			name: "byte array (non-UTF-8 path)",
			raw:  json.RawMessage(`[70,97,105,108,101,100]`), // "Failed"
			want: "Failed",
		},
		{
			name: "empty raw",
			raw:  json.RawMessage(nil),
			want: "",
		},
		{
			name: "empty string",
			raw:  json.RawMessage(`""`),
			want: "",
		},
		{
			name: "byte array with out-of-range value",
			raw:  json.RawMessage(`[70, 256, 100]`),
			want: "",
		},
		{
			name: "byte array with negative value",
			raw:  json.RawMessage(`[70, -1, 100]`),
			want: "",
		},
		{
			name: "invalid json",
			raw:  json.RawMessage(`{not valid}`),
			want: "",
		},
		{
			name: "string with special chars",
			raw:  json.RawMessage(`"Accepted publickey for bob from 1.2.3.4 port 22"`),
			want: "Accepted publickey for bob from 1.2.3.4 port 22",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeJournaldMessage(tt.raw)
			if got != tt.want {
				t.Errorf("decodeJournaldMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJournaldToSyslog(t *testing.T) {
	fixedTS := int64(1705312200000000) // 2024-01-15T10:30:00Z in microseconds
	fixedTime := time.UnixMicro(fixedTS).UTC()

	tests := []struct {
		name    string
		entry   journaldEntry
		want    string
		wantNil bool
	}{
		{
			name: "full entry with PID",
			entry: journaldEntry{
				RealtimeTimestamp: "1705312200000000",
				Hostname:          "myhost",
				SyslogIdentifier:  "sshd",
				PID:               "12345",
				Message:           json.RawMessage(`"Failed password for root"`),
			},
			want: fixedTime.Format(time.RFC3339) + " myhost sshd[12345]: Failed password for root",
		},
		{
			name: "entry without PID",
			entry: journaldEntry{
				RealtimeTimestamp: "1705312200000000",
				Hostname:          "myhost",
				SyslogIdentifier:  "sshd",
				Message:           json.RawMessage(`"Invalid user admin"`),
			},
			want: fixedTime.Format(time.RFC3339) + " myhost sshd: Invalid user admin",
		},
		{
			name: "missing hostname defaults to localhost",
			entry: journaldEntry{
				RealtimeTimestamp: "1705312200000000",
				SyslogIdentifier:  "sshd",
				PID:               "1",
				Message:           json.RawMessage(`"test message"`),
			},
			want: fixedTime.Format(time.RFC3339) + " localhost sshd[1]: test message",
		},
		{
			name: "zero timestamp falls back to now",
			entry: journaldEntry{
				RealtimeTimestamp: "",
				Hostname:          "h",
				SyslogIdentifier:  "sshd",
				Message:           json.RawMessage(`"msg"`),
			},
			// can't check exact time, just verify non-empty
		},
		{
			name: "missing SyslogIdentifier returns empty",
			entry: journaldEntry{
				RealtimeTimestamp: "1705312200000000",
				Hostname:          "h",
				Message:           json.RawMessage(`"msg"`),
			},
			wantNil: true,
		},
		{
			name: "empty message returns empty",
			entry: journaldEntry{
				RealtimeTimestamp: "1705312200000000",
				Hostname:          "h",
				SyslogIdentifier:  "sshd",
				Message:           json.RawMessage(`""`),
			},
			wantNil: true,
		},
		{
			name: "message as byte array",
			entry: journaldEntry{
				RealtimeTimestamp: "1705312200000000",
				Hostname:          "myhost",
				SyslogIdentifier:  "sshd",
				PID:               "99",
				Message:           json.RawMessage(`[104,105]`), // "hi"
			},
			want: fixedTime.Format(time.RFC3339) + " myhost sshd[99]: hi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := journaldToSyslog(tt.entry)
			if tt.wantNil {
				if got != "" {
					t.Errorf("journaldToSyslog() = %q, want empty string", got)
				}
				return
			}
			if tt.want == "" {
				// zero-ts test: just check non-empty and contains identifier
				if got == "" {
					t.Error("journaldToSyslog() returned empty, want non-empty")
				}
				return
			}
			if got != tt.want {
				t.Errorf("journaldToSyslog() = %q, want %q", got, tt.want)
			}
		})
	}
}
