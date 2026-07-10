package parse

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErrNoMatch is returned when a log line does not match any known pattern.
var ErrNoMatch = errors.New("no matching pattern")

// Syslog traditional format: "Jun 21 14:32:01 hostname sshd[12345]: message".
// The proc group also allows slashes for postfix's "postfix/smtpd" style names.
var reSyslogPrefix = regexp.MustCompile(`^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>\w+(?:[-/]\w+)*)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$`)

// RFC3339 prefix: "2024-06-21T14:32:01+00:00 hostname sshd[12345]: message"
var reRFC3339Prefix = regexp.MustCompile(`^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(?P<host>\S+)\s+(?P<proc>\w+(?:[-/]\w+)*)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$`)

type eventPattern struct {
	typ string
	re  *regexp.Regexp
}

// sshdPatterns are applied to the message portion of an sshd log line.
var sshdPatterns = []eventPattern{
	{
		typ: "accepted",
		re:  regexp.MustCompile(`^Accepted (?P<method>password|publickey|keyboard-interactive/pam|keyboard-interactive) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) ssh2`),
	},
	{
		// One line per wrong password. keyboard-interactive/pam is what sshd
		// logs when PAM handles the prompt (kbd-interactive auth enabled).
		typ: "failed_password",
		re:  regexp.MustCompile(`^Failed (?:password|keyboard-interactive/pam|keyboard-interactive) for (?P<invalid>invalid user )?(?P<user>.+?) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) ssh2`),
	},
	{
		typ: "invalid_user",
		re:  regexp.MustCompile(`^Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)`),
	},
	{
		typ: "max_auth",
		re:  regexp.MustCompile(`maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)`),
	},
	{
		typ: "disconnect_preauth",
		re:  regexp.MustCompile(`^(?:Connection closed|Disconnected) (?:by|from) (?:authenticating|invalid) user (?P<user>\S+) (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)`),
	},
	{
		typ: "pam_failure",
		re:  regexp.MustCompile(`pam_unix\(sshd:auth\): authentication failure;.*?rhost=(?P<ip>[0-9a-fA-F:.]+)(?:\s+user=(?P<user>\S+))?`),
	},
}

// dovecotPattern matches dovecot login-process auth failures:
//
//	imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=<admin>, method=PLAIN, rip=203.0.113.5, lip=...
//	pop3-login: Aborted login (auth failed, 3 attempts in 10 secs): user=<test>, method=PLAIN, rip=203.0.113.5, ...
//
// Lines without "(auth failed" (e.g. "no auth attempts" scanner probes) are
// deliberately not matched — nobody typed a wrong password.
var dovecotPattern = regexp.MustCompile(`^(?:imap|pop3|submission|managesieve)-login: .*\(auth failed, \d+ attempts[^)]*\): user=<(?P<user>[^>]*)>.*rip=(?P<ip>[0-9a-fA-F:.]+)`)

// postfixPattern matches postfix/smtpd SASL authentication failures:
//
//	warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: authentication failure
//	warning: host.example.com[203.0.113.5]: SASL PLAIN authentication failed: ..., sasl_username=admin@example.com
var postfixPattern = regexp.MustCompile(`^warning: \S*\[(?P<ip>[0-9a-fA-F:.]+)\]: SASL \S+ authentication failed(?::.*?)?(?:, sasl_username=(?P<user>\S+))?$`)

// --- sudo / user-management (local privilege audit) ---
//
// These events describe local root escalation and account changes, not remote
// attacks. They carry no source IP, so they never count toward auto-ban or the
// attack statistics — they exist for the audit feed and privilege alerts.

// sudoSuccessPattern matches a successful sudo command:
//
//	alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update
var sudoSuccessPattern = regexp.MustCompile(`^(?P<user>\S+) : TTY=\S+ ; PWD=\S+ ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.+)$`)

// sudoFailPattern matches a failed sudo attempt (wrong password, not in
// sudoers, command not allowed). Tried only after sudoSuccessPattern, so a
// success line (which has no reason segment before TTY=) never reaches it:
//
//	bob : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/su
//	bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash
var sudoFailPattern = regexp.MustCompile(`^(?P<user>\S+) : (?P<reason>.+?) ; TTY=\S+ ; PWD=\S+ ; USER=\S+ ; COMMAND=(?P<cmd>.+)$`)

// userAddPattern matches a new account (useradd). A UID of 0 is a red flag —
// a second root-equivalent user.
var userAddPattern = regexp.MustCompile(`new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+), GID=\d+, home=[^,]+, shell=(?P<shell>[^,\s]+)`)

// userDelPattern matches account deletion (userdel).
var userDelPattern = regexp.MustCompile(`^delete user '(?P<name>[^']+)'`)

// fail2banPattern matches fail2ban log lines.
var fail2banPattern = regexp.MustCompile(`\[(?P<jail>[^\]]+)\]\s+(?P<action>Ban|Unban)\s+(?P<ip>[0-9a-fA-F:.]+)`)

// fail2banPrefix matches the timestamp portion of a fail2ban log line.
var fail2banPrefix = regexp.MustCompile(`^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+fail2ban`)

// fail2banTS extracts the leading "YYYY-MM-DD HH:MM:SS" timestamp. Compiled
// once at init — parseFail2BanLine runs for every fail2ban.log line (replayed
// from the beginning on each start), so a per-call MustCompile is wasteful.
var fail2banTS = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`)

// Nginx error.log: "2026/06/22 14:32:01 [error] 12345#12345: *N message"
var reNginxError = regexp.MustCompile(`^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[\w+\] \d+#\d+: \*\d+ (?P<msg>.+)$`)

// nginxAuthPatterns are applied to the message portion of nginx error.log lines.
var nginxAuthPatterns = []eventPattern{
	{
		typ: "http_auth_fail",
		re:  regexp.MustCompile(`no user/password was provided for basic authentication, client: (?P<ip>[0-9a-fA-F:.]+)`),
	},
	{
		typ: "http_auth_fail",
		re:  regexp.MustCompile(`user "(?P<user>[^"]*)" was not found in "[^"]+", client: (?P<ip>[0-9a-fA-F:.]+)`),
	},
	{
		typ: "http_auth_fail",
		re:  regexp.MustCompile(`user "(?P<user>[^"]*)": password mismatch, client: (?P<ip>[0-9a-fA-F:.]+)`),
	},
}

// Nginx access.log combined format: "IP - user [ts] "req" status bytes ..."
// Only 401 responses are treated as auth failures.
var reNginxAccess = regexp.MustCompile(`^(?P<ip>[0-9a-fA-F:.]+) - (?P<user>\S+) \[(?P<ts>[^\]]+)\] "[^"]*" (?P<status>\d{3}) `)

func namedGroups(re *regexp.Regexp, s string) map[string]string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(re.SubexpNames()))
	for i, name := range re.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = m[i]
		}
	}
	return result
}

// parseTraditionalTS parses a zone-less syslog timestamp. The timestamp is
// interpreted in the process's local timezone — syslog writes local time, and
// treating it as UTC skews every event by the host's UTC offset. On hosts west
// of UTC that skew made live events look like the past, which silently
// suppressed all notifications (the dispatcher drops pre-startup events).
// Deployments mount /etc/localtime into the container so time.Local matches
// the host that produced the log.
func parseTraditionalTS(ts string) (time.Time, error) {
	now := time.Now()
	// Normalise multiple spaces (e.g. "Jun  1" → "Jun 1")
	ts = strings.Join(strings.Fields(ts), " ")
	t, err := time.Parse("Jan 2 15:04:05", ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("unrecognised syslog timestamp: %q", ts)
	}
	// Attach current year; roll back if the result is in the future (Dec→Jan boundary).
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t.UTC(), nil
}

func parseTimestamp(ts string) (time.Time, error) {
	// RFC3339 variants
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, ts); err == nil {
			return t.UTC(), nil
		}
	}
	return parseTraditionalTS(ts)
}

// ParseLine parses a raw log line (sshd, fail2ban, or nginx) into an Event.
// Returns ErrNoMatch if the line is not a recognised auth event.
func ParseLine(line string) (*Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, ErrNoMatch
	}

	// fail2ban: "2026-06-21 14:40:00,123 fail2ban..."
	if fail2banPrefix.MatchString(line) {
		return parseFail2BanLine(line)
	}

	// nginx error.log: "2026/06/22 14:32:01 [error] ..."
	if reNginxError.MatchString(line) {
		return parseNginxErrorLine(line)
	}

	// nginx access.log: "203.0.113.5 - user [ts] ..."
	if reNginxAccess.MatchString(line) {
		return parseNginxAccessLine(line)
	}

	return parseSyslogLine(line)
}

// parseSyslogLine handles syslog/RFC3339-prefixed lines and dispatches on the
// logging process: sshd, dovecot login processes, or postfix smtpd.
func parseSyslogLine(line string) (*Event, error) {
	var ts time.Time
	var msg, proc string

	if m := namedGroups(reRFC3339Prefix, line); m != nil {
		var err error
		ts, err = parseTimestamp(m["ts"])
		if err != nil {
			return nil, ErrNoMatch
		}
		msg, proc = m["msg"], m["proc"]
	} else if m := namedGroups(reSyslogPrefix, line); m != nil {
		var err error
		ts, err = parseTimestamp(m["ts"])
		if err != nil {
			return nil, ErrNoMatch
		}
		msg, proc = m["msg"], m["proc"]
	} else {
		return nil, ErrNoMatch
	}

	switch {
	case proc == "sshd" || proc == "sshd-session":
		return parseSSHDMessage(ts, msg, line)
	case proc == "dovecot":
		return parseMailMessage(ts, msg, line, dovecotPattern, "dovecot")
	case strings.HasPrefix(proc, "postfix") && strings.HasSuffix(proc, "smtpd"):
		// "postfix/smtpd" and multi-instance "postfix/submission/smtpd".
		return parseMailMessage(ts, msg, line, postfixPattern, "postfix")
	case proc == "sudo":
		return parseSudoMessage(ts, msg, line)
	case proc == "useradd" || proc == "userdel":
		return parseUserMessage(ts, msg, line, proc)
	}
	return nil, ErrNoMatch
}

// parseSudoMessage recognises successful and failed sudo invocations.
func parseSudoMessage(ts time.Time, msg, line string) (*Event, error) {
	if m := namedGroups(sudoSuccessPattern, msg); m != nil {
		return &Event{
			TS:        ts,
			EventType: "sudo_session",
			Username:  m["user"],
			Source:    "sudo",
			Detail:    "as " + m["target"] + ": " + m["cmd"],
			Raw:       line,
		}, nil
	}
	if m := namedGroups(sudoFailPattern, msg); m != nil {
		detail := m["reason"]
		if cmd := m["cmd"]; cmd != "" {
			detail += ": " + cmd
		}
		return &Event{
			TS:        ts,
			EventType: "sudo_fail",
			Username:  m["user"],
			Source:    "sudo",
			Detail:    detail,
			Raw:       line,
		}, nil
	}
	return nil, ErrNoMatch
}

// parseUserMessage recognises account creation and deletion.
func parseUserMessage(ts time.Time, msg, line, proc string) (*Event, error) {
	if proc == "useradd" {
		if m := namedGroups(userAddPattern, msg); m != nil {
			return &Event{
				TS:        ts,
				EventType: "user_add",
				Username:  m["name"],
				Source:    "useradd",
				Detail:    "uid=" + m["uid"] + " shell=" + m["shell"],
				Raw:       line,
			}, nil
		}
		return nil, ErrNoMatch
	}
	if m := namedGroups(userDelPattern, msg); m != nil {
		return &Event{
			TS:        ts,
			EventType: "user_del",
			Username:  m["name"],
			Source:    "userdel",
			Raw:       line,
		}, nil
	}
	return nil, ErrNoMatch
}

// parseMailMessage matches a dovecot/postfix auth-failure pattern. Mail auth
// failures are primary attempt events (counted by auto-ban and thresholds),
// exactly like failed_password for sshd.
func parseMailMessage(ts time.Time, msg, line string, re *regexp.Regexp, source string) (*Event, error) {
	m := namedGroups(re, msg)
	if m == nil {
		return nil, ErrNoMatch
	}
	return &Event{
		TS:        ts,
		IP:        m["ip"],
		EventType: "mail_auth_fail",
		Username:  m["user"],
		Source:    source,
		Raw:       line,
	}, nil
}

func parseSSHDMessage(ts time.Time, msg, line string) (*Event, error) {
	for _, p := range sshdPatterns {
		m := namedGroups(p.re, msg)
		if m == nil {
			continue
		}

		ev := &Event{
			TS:        ts,
			EventType: p.typ,
			Source:    "sshd",
			IP:        m["ip"],
			Username:  strings.TrimSpace(m["user"]),
			Raw:       line,
		}

		if portStr := m["port"]; portStr != "" {
			ev.Port, _ = strconv.Atoi(portStr)
		}
		if method := m["method"]; method != "" {
			ev.AuthMethod = method
		}

		switch p.typ {
		case "failed_password":
			isInvalid := m["invalid"] != ""
			v := !isInvalid
			ev.UserValid = &v
		case "accepted":
			v := true
			ev.UserValid = &v
		}

		return ev, nil
	}

	return nil, ErrNoMatch
}

func parseNginxErrorLine(line string) (*Event, error) {
	m := namedGroups(reNginxError, line)
	if m == nil {
		return nil, ErrNoMatch
	}
	// nginx error.log timestamps carry no zone — interpret as local time.
	ts, err := time.ParseInLocation("2006/01/02 15:04:05", m["ts"], time.Local)
	if err != nil {
		return nil, ErrNoMatch
	}
	ts = ts.UTC()
	for _, p := range nginxAuthPatterns {
		pm := namedGroups(p.re, m["msg"])
		if pm == nil {
			continue
		}
		return &Event{
			TS:        ts,
			IP:        pm["ip"],
			EventType: p.typ,
			Username:  pm["user"],
			Source:    "nginx",
			Raw:       line,
		}, nil
	}
	return nil, ErrNoMatch
}

func parseNginxAccessLine(line string) (*Event, error) {
	m := namedGroups(reNginxAccess, line)
	if m == nil {
		return nil, ErrNoMatch
	}
	if m["status"] != "401" {
		return nil, ErrNoMatch
	}
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m["ts"])
	if err != nil {
		return nil, ErrNoMatch
	}
	user := m["user"]
	if user == "-" {
		user = ""
	}
	return &Event{
		TS:        ts.UTC(),
		IP:        m["ip"],
		EventType: "http_auth_fail",
		Username:  user,
		Source:    "nginx",
		Raw:       line,
	}, nil
}

func parseFail2BanLine(line string) (*Event, error) {
	// Extract timestamp from fail2ban prefix: "2026-06-21 14:40:00,123 ..."
	tsMatch := fail2banTS.FindString(line)
	if tsMatch == "" {
		return nil, ErrNoMatch
	}
	// fail2ban logs local time without a zone — interpret as local time.
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", tsMatch, time.Local)
	if err != nil {
		return nil, ErrNoMatch
	}
	ts = ts.UTC()

	m := namedGroups(fail2banPattern, line)
	if m == nil {
		return nil, ErrNoMatch
	}

	evType := "ban"
	if m["action"] == "Unban" {
		evType = "unban"
	}

	return &Event{
		TS:        ts,
		IP:        m["ip"],
		EventType: evType,
		Source:    "fail2ban",
		Username:  m["jail"],
		Raw:       line,
	}, nil
}
