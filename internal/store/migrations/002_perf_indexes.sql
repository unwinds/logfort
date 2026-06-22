-- Composite index for the dominant stats query pattern (ts range + type filter).
CREATE INDEX IF NOT EXISTS idx_events_ts_type ON events(ts, event_type);
-- Per-IP time range queries (CountIPEvents, notify threshold).
CREATE INDEX IF NOT EXISTS idx_events_ip_ts   ON events(ip, ts);
