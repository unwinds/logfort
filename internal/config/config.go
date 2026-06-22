package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	Listen        string
	Backend       string // "file" or "journald"
	LogPaths      []string
	JournaldUnit  string
	Fail2BanLog   string
	DBPath        string
	GeoIPDB       string
	RetentionDays int
	HomeLat       *float64
	HomeLon       *float64
	AuthEnabled   bool
	AuthUser      string
	AuthPass      string
	ResponderEnabled bool
	ResponderBackend string
	NftTable      string
	NftSet        string
	Fail2BanJail  string
	IgnoreIPs     []string
	NotifyWebhookURL    string
	NotifyTelegramToken string
	NotifyTelegramChat  string
	NotifyDiscordURL    string
	NotifyRules   []string
	LogLevel      slog.Level
}

// Load reads configuration from environment variables with sane defaults.
func Load() (*Config, error) {
	cfg := &Config{
		Listen:           getEnv("LOGFORT_LISTEN", "127.0.0.1:8080"),
		Backend:          getEnv("LOGFORT_BACKEND", "file"),
		JournaldUnit:     getEnv("LOGFORT_JOURNALD_UNIT", "ssh.service"),
		Fail2BanLog:      getEnv("LOGFORT_FAIL2BAN_LOG", ""),
		DBPath:           getEnv("LOGFORT_DB_PATH", "/data/logfort.db"),
		GeoIPDB:          getEnv("LOGFORT_GEOIP_DB", "/data/geo.mmdb"),
		NftTable:         getEnv("LOGFORT_NFT_TABLE", "inet filter"),
		NftSet:           getEnv("LOGFORT_NFT_SET", "logfort_block"),
		Fail2BanJail:     getEnv("LOGFORT_FAIL2BAN_JAIL", "sshd"),
		NotifyWebhookURL: getEnv("LOGFORT_NOTIFY_WEBHOOK_URL", ""),
		NotifyTelegramToken: getEnv("LOGFORT_NOTIFY_TELEGRAM_TOKEN", ""),
		NotifyTelegramChat:  getEnv("LOGFORT_NOTIFY_TELEGRAM_CHAT_ID", ""),
		NotifyDiscordURL:    getEnv("LOGFORT_NOTIFY_DISCORD_URL", ""),
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
	cfg.AuthEnabled = getEnv("LOGFORT_AUTH_ENABLED", "false") == "true"
	cfg.AuthUser = getEnv("LOGFORT_AUTH_USER", "")
	cfg.AuthPass = getEnv("LOGFORT_AUTH_PASS", "")
	if cfg.AuthEnabled && (cfg.AuthUser == "" || cfg.AuthPass == "") {
		return nil, fmt.Errorf("LOGFORT_AUTH_ENABLED=true requires both LOGFORT_AUTH_USER and LOGFORT_AUTH_PASS to be set")
	}

	// Responder
	cfg.ResponderEnabled = getEnv("LOGFORT_RESPONDER_ENABLED", "false") == "true"
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

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
