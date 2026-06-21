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
	EventType  string // failed_password|invalid_user|accepted|max_auth|disconnect_preauth|pam_failure|ban|unban
	Username   string
	UserValid  *bool  // nil if unknown
	AuthMethod string // password|publickey|""
	Port       int
	Source     string // sshd|fail2ban|nginx
	Geo        GeoInfo
	Raw        string
}
