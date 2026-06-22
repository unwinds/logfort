-- Remove exact duplicates before creating the unique constraint (safe upgrade path).
DELETE FROM events WHERE id NOT IN (
    SELECT MIN(id) FROM events GROUP BY ts, ip, IFNULL(port, 0), event_type
);

-- Unique index prevents duplicate rows on log re-reads after restart.
-- IFNULL(port, 0) makes NULL ports comparable so the expression is unique-safe.
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedup
    ON events(ts, ip, IFNULL(port, 0), event_type);
