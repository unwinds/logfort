package store

import (
	"context"
	"errors"
	"time"

	"github.com/unwinds/logfort/internal/parse"
)

// ErrDuplicate is returned by InsertEvent when the event already exists in the
// database (matched by the dedup unique index). Callers should skip downstream
// side-effects (SSE publish, notifications) for duplicate events.
var ErrDuplicate = errors.New("duplicate event")

// Store persists and queries authentication events.
type Store interface {
	InsertEvent(ctx context.Context, e *parse.Event) error
	ListEvents(ctx context.Context, q EventQuery) ([]EventRow, int64, error)
	GetStats(ctx context.Context, window string) (*Stats, error)
	ListBans(ctx context.Context, activeOnly bool) ([]BanRow, error)
	GetMapPoints(ctx context.Context, window string) ([]MapPoint, error)
	DeleteOldEvents(ctx context.Context, retentionDays int) (int64, error)
	// BanIP records a manual ban in the bans table.
	BanIP(ctx context.Context, ip, source, reason string) error
	// UnbanIP marks all active bans for an IP as inactive.
	UnbanIP(ctx context.Context, ip string) error
	// CountIPEvents returns the number of non-ban/unban events from ip since the given time.
	CountIPEvents(ctx context.Context, ip string, since time.Time) (int64, error)
	// GetSetting returns the value for key. found is false when the key does not exist.
	GetSetting(ctx context.Context, key string) (value string, found bool, err error)
	// SetSetting upserts a key-value pair in the settings table.
	SetSetting(ctx context.Context, key, value string) error
	// SetSettings atomically persists multiple key-value pairs in a single transaction.
	SetSettings(ctx context.Context, pairs map[string]string) error
	// GetAllSettings returns all key-value pairs from the settings table.
	GetAllSettings(ctx context.Context) (map[string]string, error)
	Close() error
}

// MapPoint is a geo-aggregated attack point for the map view.
type MapPoint struct {
	IP       string  `json:"ip"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	Country  string  `json:"country,omitempty"`
	Count    int64   `json:"count"`
	LastSeen int64   `json:"last_seen"`
}

// EventQuery holds parameters for listing events.
type EventQuery struct {
	Limit     int
	Offset    int
	EventType string
	IP        string
	Country   string
	Since     *time.Time
	Until     *time.Time
}

// EventRow is the JSON-serialisable form of an event returned by the API.
type EventRow struct {
	ID         int64    `json:"id"`
	TS         int64    `json:"ts"`
	IP         string   `json:"ip"`
	EventType  string   `json:"event_type"`
	Username   string   `json:"username,omitempty"`
	UserValid  *bool    `json:"user_valid,omitempty"`
	AuthMethod string   `json:"auth_method,omitempty"`
	Port       int      `json:"port,omitempty"`
	Source     string   `json:"source"`
	Country    string   `json:"country,omitempty"`
	City       string   `json:"city,omitempty"`
	Lat        *float64 `json:"lat,omitempty"`
	Lon        *float64 `json:"lon,omitempty"`
}

// BanRow is the JSON-serialisable form of a ban record.
type BanRow struct {
	ID         int64  `json:"id"`
	IP         string `json:"ip"`
	Jail       string `json:"jail,omitempty"`
	BannedAt   int64  `json:"banned_at"`
	UnbannedAt *int64 `json:"unbanned_at,omitempty"`
	Active     bool   `json:"active"`
	Source     string `json:"source"`
	Reason     string `json:"reason,omitempty"`
}

// Stats holds aggregate statistics for a time window.
type Stats struct {
	Window          string         `json:"window"`
	TotalAttempts   int64          `json:"total_attempts"`
	UniqueIPs       int64          `json:"unique_ips"`
	Failed          int64          `json:"failed"`
	Accepted        int64          `json:"accepted"`
	CurrentlyBanned int64          `json:"currently_banned"`
	TopIPs          []TopIP        `json:"top_ips"`
	TopCountries    []TopCountry   `json:"top_countries"`
	TopUsernames    []TopUsername  `json:"top_usernames"`
	Timeline        []TimeBucket   `json:"timeline"`
}

// TopIP holds an IP address and its attempt count.
type TopIP struct {
	IP      string `json:"ip"`
	Count   int64  `json:"count"`
	Country string `json:"country,omitempty"`
}

// TopCountry holds a country code and its attempt count.
type TopCountry struct {
	Country string `json:"country"`
	Count   int64  `json:"count"`
}

// TopUsername holds a username and its attempt count.
type TopUsername struct {
	Username string `json:"username"`
	Count    int64  `json:"count"`
}

// TimeBucket holds a time bucket and its event count.
type TimeBucket struct {
	BucketTS int64 `json:"bucket_ts"`
	Count    int64 `json:"count"`
}
