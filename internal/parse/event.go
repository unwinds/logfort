package parse

import "time"

// GeoInfo holds geolocation data for an IP address.
// Fields are zero/empty when GeoIP lookup is unavailable.
type GeoInfo struct {
	Country string
	City    string
	Lat     float64
	Lon     float64
	ASN     string
}

// Event represents a single parsed authentication log entry.
type Event struct {
	TS         time.Time // UTC
	IP         string
	EventType  string // failed_password|invalid_user|accepted|max_auth|disconnect_preauth|pam_failure|http_auth_fail|mail_auth_fail|ban|unban|sudo_session|sudo_fail|user_add|user_del
	Username   string
	UserValid  *bool  // nil if unknown
	AuthMethod string // password|publickey|""
	Port       int
	Source     string // sshd|fail2ban|nginx|dovecot|postfix|sudo|useradd|userdel
	// Detail carries extra context for local audit events that has no dedicated
	// column: the target user + command for sudo, uid/shell for a new account.
	Detail string
	// Threat is set by the ingest pipeline (not the parser) to the name of the
	// blocklist an IP was found in, or "" when the IP is not listed / no
	// blocklist is configured.
	Threat string
	Geo    GeoInfo
	Raw    string
}
