package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

const (
	DefaultRetentionDays    = 90
	DefaultAutoBanThreshold = 50
	DefaultAutoBanWindow    = "1h"
	// DefaultAutoBanBanTime is how long auto-bans last (seconds). Attacker IPs
	// are mostly dynamic, so permanent auto-bans slowly poison the blocklist
	// with addresses that long since moved on to legitimate owners.
	DefaultAutoBanBanTime = int64(24 * 3600)
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	Listen              string
	Backend             string // "file" or "journald"
	LogPaths            []string
	JournaldUnit        string
	Fail2BanLog         string
	DBPath              string
	GeoIPDB             string
	ASNDB               string
	RetentionDays       int
	HomeLat             *float64
	HomeLon             *float64
	AuthEnabled         bool
	AuthUser            string
	AuthPass            string
	ResponderEnabled    bool
	ResponderBackend    string
	NftTable            string
	NftSet              string
	Fail2BanJail        string
	Fail2BanSocket      string
	IgnoreIPs           []string
	NotifyWebhookURL    string
	NotifyTelegramToken string
	NotifyTelegramChat  string
	NotifyDiscordURL    string
	NotifySlackURL      string
	NotifyNtfyURL       string
	NotifyNtfyToken     string
	NotifyGotifyURL     string
	NotifyGotifyToken   string
	NotifySMTPHost      string // "host:port"
	NotifySMTPUser      string
	NotifySMTPPass      string
	NotifySMTPFrom      string
	NotifySMTPTo        string // comma-separated recipients
	NotifyRules         []string
	LogLevel            slog.Level

	// DemoMode replaces all log sources with a synthetic traffic generator —
	// for evaluating the dashboard without a real server. Never enable in
	// production: real logs are not read while it is on.
	DemoMode bool

	// ExtraIgnoreIPs holds allowlist entries added from the settings UI
	// (persisted in the DB, key "security.ignore_ips"). They are unioned with
	// IgnoreIPs at runtime — env/default entries can never be removed via UI.
	ExtraIgnoreIPs []string

	// UI-configurable settings (persisted in DB; no env vars)
	AutoBanEnabled   bool
	AutoBanThreshold int
	AutoBanWindow    string
	AutoBanBanTime   int64 // seconds an auto-ban lasts; 0 = permanent

	// fail2ban jail tuning managed from the UI (persisted in DB; 0 = not
	// managed). Applied to the running fail2ban via its command socket.
	F2BMaxRetry int64
	F2BBanTime  int64 // seconds
	F2BFindTime int64 // seconds
}

// Load reads configuration from environment variables with sane defaults.
func Load() (*Config, error) {
	cfg := &Config{
		Listen:              getEnv("LOGFORT_LISTEN", "127.0.0.1:8080"),
		Backend:             getEnv("LOGFORT_BACKEND", "file"),
		JournaldUnit:        getEnv("LOGFORT_JOURNALD_UNIT", "ssh.service"),
		Fail2BanLog:         getEnv("LOGFORT_FAIL2BAN_LOG", ""),
		DBPath:              getEnv("LOGFORT_DB_PATH", "/data/logfort.db"),
		GeoIPDB:             getEnv("LOGFORT_GEOIP_DB", "/data/geo.mmdb"),
		ASNDB:               getEnv("LOGFORT_ASN_DB", "/data/asn.mmdb"),
		NftTable:            getEnv("LOGFORT_NFT_TABLE", "inet filter"),
		NftSet:              getEnv("LOGFORT_NFT_SET", "logfort_block"),
		Fail2BanJail:        getEnv("LOGFORT_FAIL2BAN_JAIL", "sshd"),
		Fail2BanSocket:      getEnv("LOGFORT_FAIL2BAN_SOCKET", "/var/run/fail2ban/fail2ban.sock"),
		NotifyWebhookURL:    getEnv("LOGFORT_NOTIFY_WEBHOOK_URL", ""),
		NotifyTelegramToken: getEnv("LOGFORT_NOTIFY_TELEGRAM_TOKEN", ""),
		NotifyTelegramChat:  getEnv("LOGFORT_NOTIFY_TELEGRAM_CHAT_ID", ""),
		NotifyDiscordURL:    getEnv("LOGFORT_NOTIFY_DISCORD_URL", ""),
		NotifySlackURL:      getEnv("LOGFORT_NOTIFY_SLACK_URL", ""),
		NotifyNtfyURL:       getEnv("LOGFORT_NOTIFY_NTFY_URL", ""),
		NotifyNtfyToken:     getEnv("LOGFORT_NOTIFY_NTFY_TOKEN", ""),
		NotifyGotifyURL:     getEnv("LOGFORT_NOTIFY_GOTIFY_URL", ""),
		NotifyGotifyToken:   getEnv("LOGFORT_NOTIFY_GOTIFY_TOKEN", ""),
		NotifySMTPHost:      getEnv("LOGFORT_NOTIFY_SMTP_HOST", ""),
		NotifySMTPUser:      getEnv("LOGFORT_NOTIFY_SMTP_USER", ""),
		NotifySMTPPass:      getEnv("LOGFORT_NOTIFY_SMTP_PASS", ""),
		NotifySMTPFrom:      getEnv("LOGFORT_NOTIFY_SMTP_FROM", ""),
		NotifySMTPTo:        getEnv("LOGFORT_NOTIFY_SMTP_TO", ""),
		// UI-only settings get sane defaults here so a failed DB overlay
		// (e.g. transient read error at startup) never leaves zero values.
		AutoBanThreshold: DefaultAutoBanThreshold,
		AutoBanWindow:    DefaultAutoBanWindow,
		AutoBanBanTime:   DefaultAutoBanBanTime,
	}

	// Log paths (comma-separated)
	if raw := getEnv("LOGFORT_LOG_PATHS", "/host/auth.log"); raw != "" {
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				cfg.LogPaths = append(cfg.LogPaths, p)
			}
		}
	}

	// Retention days
	var err error
	cfg.RetentionDays, err = strconv.Atoi(getEnv("LOGFORT_RETENTION_DAYS", "90"))
	if err != nil || cfg.RetentionDays < 1 {
		return nil, fmt.Errorf("LOGFORT_RETENTION_DAYS must be a positive integer")
	}

	// Home location (optional)
	if raw := getEnv("LOGFORT_HOME_LAT", ""); raw != "" {
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, fmt.Errorf("LOGFORT_HOME_LAT: %w", err)
		}
		cfg.HomeLat = &v
	}
	if raw := getEnv("LOGFORT_HOME_LON", ""); raw != "" {
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, fmt.Errorf("LOGFORT_HOME_LON: %w", err)
		}
		cfg.HomeLon = &v
	}

	// Auth
	cfg.AuthEnabled = getEnvBool("LOGFORT_AUTH_ENABLED", false)
	cfg.AuthUser = getEnv("LOGFORT_AUTH_USER", "")
	cfg.AuthPass = getEnv("LOGFORT_AUTH_PASS", "")
	if cfg.AuthEnabled && (cfg.AuthUser == "" || cfg.AuthPass == "") {
		return nil, fmt.Errorf("LOGFORT_AUTH_ENABLED=true requires both LOGFORT_AUTH_USER and LOGFORT_AUTH_PASS to be set")
	}

	cfg.DemoMode = getEnvBool("LOGFORT_DEMO", false)

	// Responder
	cfg.ResponderEnabled = getEnvBool("LOGFORT_RESPONDER_ENABLED", false)
	cfg.ResponderBackend = getEnv("LOGFORT_RESPONDER_BACKEND", "nftables")

	// Ignore IPs
	defaultIgnore := "127.0.0.1/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
	if raw := getEnv("LOGFORT_IGNORE_IPS", defaultIgnore); raw != "" {
		for _, ip := range strings.Split(raw, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				cfg.IgnoreIPs = append(cfg.IgnoreIPs, ip)
			}
		}
	}

	// Notify rules
	if raw := getEnv("LOGFORT_NOTIFY_RULES", ""); raw != "" {
		for _, r := range strings.Split(raw, ",") {
			if r = strings.TrimSpace(r); r != "" {
				cfg.NotifyRules = append(cfg.NotifyRules, r)
			}
		}
	}

	// Log level
	switch strings.ToLower(getEnv("LOGFORT_LOG_LEVEL", "info")) {
	case "debug":
		cfg.LogLevel = slog.LevelDebug
	case "warn":
		cfg.LogLevel = slog.LevelWarn
	case "error":
		cfg.LogLevel = slog.LevelError
	default:
		cfg.LogLevel = slog.LevelInfo
	}

	return cfg, nil
}

// NotifySettingKeys maps DB settings keys to the corresponding Config string
// field for every UI-configurable notification channel. Used by
// OverlaySettings and by the settings API so the two can never disagree on
// which keys exist.
func (c *Config) NotifySettingKeys() map[string]*string {
	return map[string]*string{
		"notify.telegram.token":   &c.NotifyTelegramToken,
		"notify.telegram.chat_id": &c.NotifyTelegramChat,
		"notify.discord.url":      &c.NotifyDiscordURL,
		"notify.webhook.url":      &c.NotifyWebhookURL,
		"notify.slack.url":        &c.NotifySlackURL,
		"notify.ntfy.url":         &c.NotifyNtfyURL,
		"notify.ntfy.token":       &c.NotifyNtfyToken,
		"notify.gotify.url":       &c.NotifyGotifyURL,
		"notify.gotify.token":     &c.NotifyGotifyToken,
		"notify.smtp.host":        &c.NotifySMTPHost,
		"notify.smtp.user":        &c.NotifySMTPUser,
		"notify.smtp.pass":        &c.NotifySMTPPass,
		"notify.smtp.from":        &c.NotifySMTPFrom,
		"notify.smtp.to":          &c.NotifySMTPTo,
	}
}

// SplitList splits a comma-separated string into trimmed, non-empty entries.
func SplitList(raw string) []string {
	var out []string
	for _, e := range strings.Split(raw, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// OverlaySettings fills in empty notify fields from a key-value map (e.g. from
// the DB settings table). Env-var-set values (already non-empty) take priority.
// UI-only settings (autoban, retention, extra allowlist) are always overlaid
// from the DB.
func (c *Config) OverlaySettings(s map[string]string) {
	for key, field := range c.NotifySettingKeys() {
		if *field == "" {
			*field = s[key]
		}
	}
	if len(c.NotifyRules) == 0 {
		c.NotifyRules = SplitList(s["notify.rules"])
	}

	// Extra allowlist entries — purely UI-controlled, always overlay from DB.
	c.ExtraIgnoreIPs = SplitList(s["security.ignore_ips"])

	// Retention days — DB wins if set (UI override of env default).
	if v := s["general.retention_days"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.RetentionDays = n
		}
	}

	// Auto-ban — purely UI-controlled, always overlay from DB.
	if v := s["autoban.enabled"]; v != "" {
		c.AutoBanEnabled = v == "true"
	}
	if v := s["autoban.threshold"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.AutoBanThreshold = n
		}
	}
	if c.AutoBanThreshold == 0 {
		c.AutoBanThreshold = DefaultAutoBanThreshold
	}
	if v := s["autoban.window"]; v != "" {
		c.AutoBanWindow = v
	}
	if c.AutoBanWindow == "" {
		c.AutoBanWindow = DefaultAutoBanWindow
	}
	// "0" is a valid stored value here — it means permanent auto-bans.
	if v := s["autoban.bantime"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			c.AutoBanBanTime = n
		}
	}

	// fail2ban jail tuning — purely UI-controlled, always overlay from DB.
	if v := s["f2b.maxretry"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			c.F2BMaxRetry = n
		}
	}
	if v := s["f2b.bantime"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			c.F2BBanTime = n
		}
	}
	if v := s["f2b.findtime"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			c.F2BFindTime = n
		}
	}
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// getEnvBool parses a boolean env var, accepting the usual spellings
// (true/1/T/TRUE …). Unset or unparsable values return def.
func getEnvBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return b
}
