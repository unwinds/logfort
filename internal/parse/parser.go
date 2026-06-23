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

// Syslog traditional format: "Jun 21 14:32:01 hostname sshd[12345]: message"
var reSyslogPrefix = regexp.MustCompile(`^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>\w+(?:-\w+)*)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$`)

// RFC3339 prefix: "2024-06-21T14:32:01+00:00 hostname sshd[12345]: message"
var reRFC3339Prefix = regexp.MustCompile(`^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(?P<host>\S+)\s+(?P<proc>\w+(?:-\w+)*)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$`)

type eventPattern struct {
	typ string
	re  *regexp.Regexp
}

// sshdPatterns are applied to the message portion of an sshd log line.
var sshdPatterns = []eventPattern{
	{
		typ: "accepted",
		re:  regexp.MustCompile(`^Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) ssh2`),
	},
	{
		typ: "failed_password",
		re:  regexp.MustCompile(`^Failed password for (?P<invalid>invalid user )?(?P<user>.+?) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) ssh2`),
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

// fail2banPattern matches fail2ban log lines.
var fail2banPattern = regexp.MustCompile(`\[(?P<jail>[^\]]+)\]\s+(?P<action>Ban|Unban)\s+(?P<ip>[0-9a-fA-F:.]+)`)

// fail2banPrefix matches the timestamp portion of a fail2ban log line.
var fail2banPrefix = regexp.MustCompile(`^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+fail2ban`)

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

func parseTraditionalTS(ts string) (time.Time, error) {
	now := time.Now()
	// Normalise multiple spaces (e.g. "Jun  1" → "Jun  1")
	ts = strings.Join(strings.Fields(ts), " ")
	t, err := time.Parse("Jan 2 15:04:05", ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("unrecognised syslog timestamp: %q", ts)
	}
	// Attach current year; roll back if the result is in the future (Dec→Jan boundary).
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, nil
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

	return parseSSHDLine(line)
}

func parseSSHDLine(line string) (*Event, error) {
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

	if proc != "sshd" && proc != "sshd-session" {
		return nil, ErrNoMatch
	}

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
	ts, err := time.ParseInLocation("2006/01/02 15:04:05", m["ts"], time.UTC)
	if err != nil {
		return nil, ErrNoMatch
	}
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
	tsMatch := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`).FindString(line)
	if tsMatch == "" {
		return nil, ErrNoMatch
	}
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", tsMatch, time.UTC)
	if err != nil {
		return nil, ErrNoMatch
	}

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
