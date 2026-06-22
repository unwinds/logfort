-- Recreate dedup index using COALESCE(port, -1) so that NULL ports (unknown)
-- map to -1 rather than 0, keeping port=0 and port=unknown distinguishable
-- should port=0 ever be stored explicitly in the future.
DROP INDEX IF EXISTS idx_events_dedup;
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedup
    ON events(ts, ip, COALESCE(port, -1), event_type);
