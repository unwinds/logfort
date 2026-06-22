package parse_test

import (
	"errors"
	"testing"

	"github.com/unwinds/sshwatch/internal/parse"
)

func TestParseSSHDLines(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantType  string
		wantIP    string
		wantUser  string
		wantPort  int
		wantValid *bool
		wantAuth  string
		wantErr   error
	}{
		{
			name:      "failed_password invalid user",
			line:      "Jun 21 14:32:01 myhost sshd[12345]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2",
			wantType:  "failed_password",
			wantIP:    "203.0.113.5",
			wantUser:  "admin",
			wantPort:  54321,
			wantValid: boolPtr(false),
		},
		{
			name:      "failed_password valid user",
			line:      "Jun 21 14:32:03 myhost sshd[12346]: Failed password for root from 198.51.100.7 port 41234 ssh2",
			wantType:  "failed_password",
			wantIP:    "198.51.100.7",
			wantUser:  "root",
			wantPort:  41234,
			wantValid: boolPtr(true),
		},
		{
			name:     "invalid_user",
			line:     "Jun 21 14:32:05 myhost sshd[12347]: Invalid user oracle from 203.0.113.9 port 40000",
			wantType: "invalid_user",
			wantIP:   "203.0.113.9",
			wantUser: "oracle",
			wantPort: 40000,
		},
		{
			name:      "accepted publickey",
			line:      "Jun 21 14:32:10 myhost sshd[12348]: Accepted publickey for bob from 192.0.2.11 port 22001 ssh2",
			wantType:  "accepted",
			wantIP:    "192.0.2.11",
			wantUser:  "bob",
			wantPort:  22001,
			wantValid: boolPtr(true),
			wantAuth:  "publickey",
		},
		{
			name:      "accepted password",
			line:      "Jun 21 14:32:15 myhost sshd[12349]: Accepted password for alice from 192.0.2.22 port 43210 ssh2",
			wantType:  "accepted",
			wantIP:    "192.0.2.22",
			wantUser:  "alice",
			wantPort:  43210,
			wantValid: boolPtr(true),
			wantAuth:  "password",
		},
		{
			name:     "max_auth",
			line:     "Jun 21 14:33:00 myhost sshd[12350]: error: maximum authentication attempts exceeded for root from 203.0.113.5 port 12345 ssh2 [preauth]",
			wantType: "max_auth",
			wantIP:   "203.0.113.5",
			wantUser: "root",
			wantPort: 12345,
		},
		{
			name:     "disconnect_preauth authenticating",
			line:     "Jun 21 14:33:05 myhost sshd[12351]: Connection closed by authenticating user root 203.0.113.5 port 12346 [preauth]",
			wantType: "disconnect_preauth",
			wantIP:   "203.0.113.5",
			wantUser: "root",
			wantPort: 12346,
		},
		{
			name:     "disconnect_preauth invalid",
			line:     "Jun 21 14:33:07 myhost sshd[12352]: Disconnected from invalid user oracle 198.51.100.9 port 55001 [preauth]",
			wantType: "disconnect_preauth",
			wantIP:   "198.51.100.9",
			wantUser: "oracle",
			wantPort: 55001,
		},
		{
			name:     "pam_failure",
			line:     "Jun 21 14:33:10 myhost sshd[12353]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.20  user=root",
			wantType: "pam_failure",
			wantIP:   "203.0.113.20",
			wantUser: "root",
		},
		// No-match cases.
		{
			name:    "cron line",
			line:    "Jun 21 14:33:30 myhost CRON[9999]: (root) CMD (some cron job)",
			wantErr: parse.ErrNoMatch,
		},
		{
			name:    "kernel line",
			line:    "Jun 21 14:33:31 myhost kernel: some kernel message",
			wantErr: parse.ErrNoMatch,
		},
		{
			name:    "sudo line",
			line:    "Jun 21 14:33:32 myhost sudo[1234]: alice : TTY=pts/0",
			wantErr: parse.ErrNoMatch,
		},
		{
			name:    "empty line",
			line:    "",
			wantErr: parse.ErrNoMatch,
		},
		{
			name:    "blank line",
			line:    "   ",
			wantErr: parse.ErrNoMatch,
		},
		// RHEL / single-digit day (space-padded).
		{
			name:     "invalid_user single digit day",
			line:     "Jun  5 09:00:05 rhel-host sshd[4323]: Invalid user deploy from 198.51.100.3 port 43212",
			wantType: "invalid_user",
			wantIP:   "198.51.100.3",
			wantUser: "deploy",
			wantPort: 43212,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := parse.ParseLine(tc.line)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error: got %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ev.EventType != tc.wantType {
				t.Errorf("EventType: got %q, want %q", ev.EventType, tc.wantType)
			}
			if ev.IP != tc.wantIP {
				t.Errorf("IP: got %q, want %q", ev.IP, tc.wantIP)
			}
			if ev.Username != tc.wantUser {
				t.Errorf("Username: got %q, want %q", ev.Username, tc.wantUser)
			}
			if tc.wantPort != 0 && ev.Port != tc.wantPort {
				t.Errorf("Port: got %d, want %d", ev.Port, tc.wantPort)
			}
			if tc.wantValid != nil {
				if ev.UserValid == nil {
					t.Errorf("UserValid: got nil, want %v", *tc.wantValid)
				} else if *ev.UserValid != *tc.wantValid {
					t.Errorf("UserValid: got %v, want %v", *ev.UserValid, *tc.wantValid)
				}
			}
			if tc.wantAuth != "" && ev.AuthMethod != tc.wantAuth {
				t.Errorf("AuthMethod: got %q, want %q", ev.AuthMethod, tc.wantAuth)
			}
			if ev.Source != "sshd" {
				t.Errorf("Source: got %q, want \"sshd\"", ev.Source)
			}
			if ev.TS.IsZero() {
				t.Error("TS is zero")
			}
		})
	}
}

func TestParseFail2BanLines(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantType string
		wantIP   string
		wantJail string
		wantErr  error
	}{
		{
			name:     "ban",
			line:     "2026-06-21 14:40:00,123 fail2ban.actions [12345]: NOTICE  [sshd] Ban 203.0.113.5",
			wantType: "ban",
			wantIP:   "203.0.113.5",
			wantJail: "sshd",
		},
		{
			name:     "unban",
			line:     "2026-06-21 14:55:00,789 fail2ban.actions [12345]: NOTICE  [sshd] Unban 203.0.113.5",
			wantType: "unban",
			wantIP:   "203.0.113.5",
			wantJail: "sshd",
		},
		{
			name:    "filter line (no-match)",
			line:    "2026-06-21 16:00:00,000 fail2ban.filter  [12345]: INFO    [sshd] Found 198.51.100.7",
			wantErr: parse.ErrNoMatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := parse.ParseLine(tc.line)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error: got %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ev.EventType != tc.wantType {
				t.Errorf("EventType: got %q, want %q", ev.EventType, tc.wantType)
			}
			if ev.IP != tc.wantIP {
				t.Errorf("IP: got %q, want %q", ev.IP, tc.wantIP)
			}
			if ev.Username != tc.wantJail {
				t.Errorf("Jail (Username): got %q, want %q", ev.Username, tc.wantJail)
			}
			if ev.Source != "fail2ban" {
				t.Errorf("Source: got %q, want \"fail2ban\"", ev.Source)
			}
		})
	}
}

func TestParseFixtureFile(t *testing.T) {
	type wantLine struct {
		evType string
		ip     string
	}
	// Each parseable line from testdata/auth_debian.log in order.
	want := []wantLine{
		{"failed_password", "203.0.113.5"},
		{"failed_password", "198.51.100.7"},
		{"invalid_user", "203.0.113.9"},
		{"accepted", "192.0.2.11"},
		{"accepted", "192.0.2.22"},
		{"max_auth", "203.0.113.5"},
		{"disconnect_preauth", "203.0.113.5"},
		{"disconnect_preauth", "198.51.100.9"},
		{"pam_failure", "203.0.113.20"},
		{"failed_password", "203.0.113.5"},
		{"failed_password", "203.0.113.5"},
		// CRON, kernel, sudo → ErrNoMatch (skipped)
	}

	lines := []string{
		"Jun 21 14:32:01 myhost sshd[12345]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2",
		"Jun 21 14:32:03 myhost sshd[12346]: Failed password for root from 198.51.100.7 port 41234 ssh2",
		"Jun 21 14:32:05 myhost sshd[12347]: Invalid user oracle from 203.0.113.9 port 40000",
		"Jun 21 14:32:10 myhost sshd[12348]: Accepted publickey for bob from 192.0.2.11 port 22001 ssh2",
		"Jun 21 14:32:15 myhost sshd[12349]: Accepted password for alice from 192.0.2.22 port 43210 ssh2",
		"Jun 21 14:33:00 myhost sshd[12350]: error: maximum authentication attempts exceeded for root from 203.0.113.5 port 12345 ssh2 [preauth]",
		"Jun 21 14:33:05 myhost sshd[12351]: Connection closed by authenticating user root 203.0.113.5 port 12346 [preauth]",
		"Jun 21 14:33:07 myhost sshd[12352]: Disconnected from invalid user oracle 198.51.100.9 port 55001 [preauth]",
		"Jun 21 14:33:10 myhost sshd[12353]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.20  user=root",
		"Jun 21 14:33:20 myhost sshd[12354]: Failed password for invalid user test from 203.0.113.5 port 54322 ssh2",
		"Jun 21 14:33:25 myhost sshd[12355]: Failed password for invalid user admin from 203.0.113.5 port 54323 ssh2",
		"Jun 21 14:33:30 myhost CRON[9999]: (root) CMD (some cron job)",
		"Jun 21 14:33:31 myhost kernel: some kernel message",
		"Jun 21 14:33:32 myhost sudo[1234]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt",
	}

	got := []wantLine{}
	for _, l := range lines {
		ev, err := parse.ParseLine(l)
		if errors.Is(err, parse.ErrNoMatch) {
			continue
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got = append(got, wantLine{ev.EventType, ev.IP})
	}

	if len(got) != len(want) {
		t.Fatalf("got %d events, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].evType != w.evType || got[i].ip != w.ip {
			t.Errorf("line %d: got {%q,%q}, want {%q,%q}", i, got[i].evType, got[i].ip, w.evType, w.ip)
		}
	}
}

func TestParseNginxLines(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantType string
		wantIP   string
		wantUser string
		wantErr  error
	}{
		// error.log auth failures
		{
			name:     "no user/password",
			line:     `2026/06/22 14:32:01 [error] 12345#12345: *1 no user/password was provided for basic authentication, client: 203.0.113.5, server: example.com, request: "GET /admin HTTP/1.1", host: "example.com"`,
			wantType: "http_auth_fail",
			wantIP:   "203.0.113.5",
		},
		{
			name:     "user not found",
			line:     `2026/06/22 14:32:02 [error] 12345#12345: *2 user "admin" was not found in "/etc/nginx/.htpasswd", client: 203.0.113.6, server: example.com, request: "GET /secret HTTP/1.1", host: "example.com"`,
			wantType: "http_auth_fail",
			wantIP:   "203.0.113.6",
			wantUser: "admin",
		},
		{
			name:     "password mismatch",
			line:     `2026/06/22 14:32:03 [error] 12345#12345: *3 user "root": password mismatch, client: 203.0.113.7, server: example.com, request: "POST /login HTTP/1.1", host: "example.com"`,
			wantType: "http_auth_fail",
			wantIP:   "203.0.113.7",
			wantUser: "root",
		},
		// error.log non-auth lines → ErrNoMatch
		{
			name:    "nginx notice line",
			line:    "2026/06/22 14:32:04 [notice] 12345#12345: signal process started",
			wantErr: parse.ErrNoMatch,
		},
		{
			name:    "nginx upstream timeout",
			line:    `2026/06/22 14:32:05 [warn] 12345#12345: *4 upstream timed out (110: Connection timed out), client: 203.0.113.8, server: example.com, request: "GET / HTTP/1.1", host: "example.com"`,
			wantErr: parse.ErrNoMatch,
		},
		// access.log 401 → auth failure
		{
			name:     "access.log 401 anonymous",
			line:     `203.0.113.5 - - [22/Jun/2026:14:32:01 +0000] "GET /admin HTTP/1.1" 401 0 "-" "curl/7.68.0"`,
			wantType: "http_auth_fail",
			wantIP:   "203.0.113.5",
			wantUser: "",
		},
		{
			name:     "access.log 401 with user",
			line:     `203.0.113.6 - admin [22/Jun/2026:14:32:02 +0000] "GET /wp-admin HTTP/1.1" 401 612 "-" "Mozilla/5.0"`,
			wantType: "http_auth_fail",
			wantIP:   "203.0.113.6",
			wantUser: "admin",
		},
		// access.log non-401 → ErrNoMatch
		{
			name:    "access.log 200",
			line:    `203.0.113.9 - - [22/Jun/2026:14:32:03 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`,
			wantErr: parse.ErrNoMatch,
		},
		{
			name:    "access.log 404",
			line:    `203.0.113.10 - - [22/Jun/2026:14:32:04 +0000] "GET /robots.txt HTTP/1.1" 404 153 "-" "Googlebot/2.1"`,
			wantErr: parse.ErrNoMatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := parse.ParseLine(tc.line)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error: got %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ev.EventType != tc.wantType {
				t.Errorf("EventType: got %q, want %q", ev.EventType, tc.wantType)
			}
			if ev.IP != tc.wantIP {
				t.Errorf("IP: got %q, want %q", ev.IP, tc.wantIP)
			}
			if ev.Username != tc.wantUser {
				t.Errorf("Username: got %q, want %q", ev.Username, tc.wantUser)
			}
			if ev.Source != "nginx" {
				t.Errorf("Source: got %q, want \"nginx\"", ev.Source)
			}
			if ev.TS.IsZero() {
				t.Error("TS is zero")
			}
		})
	}
}

func TestNginxDoesNotBreakSSHD(t *testing.T) {
	// Ensure sshd lines still parse correctly after nginx patterns were added.
	line := "Jun 21 14:32:01 myhost sshd[12345]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2"
	ev, err := parse.ParseLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Source != "sshd" || ev.EventType != "failed_password" {
		t.Errorf("got source=%q type=%q, want sshd/failed_password", ev.Source, ev.EventType)
	}
}

func boolPtr(b bool) *bool { return &b }
