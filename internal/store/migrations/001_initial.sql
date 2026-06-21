CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    ip          TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    username    TEXT,
    user_valid  INTEGER,
    auth_method TEXT,
    port        INTEGER,
    source      TEXT    NOT NULL DEFAULT 'sshd',
    country     TEXT,
    city        TEXT,
    lat         REAL,
    lon         REAL,
    asn         TEXT,
    raw         TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip      ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_type    ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_country ON events(country);

CREATE TABLE IF NOT EXISTS bans (
    id          INTEGER PRIMARY KEY,
    ip          TEXT    NOT NULL,
    jail        TEXT,
    banned_at   INTEGER NOT NULL,
    unbanned_at INTEGER,
    active      INTEGER NOT NULL DEFAULT 1,
    source      TEXT    NOT NULL,
    reason      TEXT
);
CREATE INDEX IF NOT EXISTS idx_bans_ip     ON bans(ip);
CREATE INDEX IF NOT EXISTS idx_bans_active ON bans(active);

CREATE TABLE IF NOT EXISTS ip_intel (
    ip         TEXT PRIMARY KEY,
    rdns       TEXT,
    asn        TEXT,
    updated_at INTEGER
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);
