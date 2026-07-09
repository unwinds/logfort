-- Widen the dedup key so IP-less local-audit events (sudo, useradd, userdel)
-- are not collapsed. Their ip is empty and port is NULL, so the previous key
-- (ts, ip, port, event_type) dropped every distinct audit line that shared a
-- one-second bucket with another (two users failing sudo in the same second,
-- a batch useradd, and so on). Adding username and detail restores per-event
-- uniqueness while identical re-read lines still deduplicate. The new key is a
-- superset of the old columns, so existing rows stay unique and the rebuild
-- cannot fail on current data.
-- NOTE: comments in migration files must not contain semicolons or quotes --
-- the runner splits on the semicolon with no SQL-aware parser.
DROP INDEX IF EXISTS idx_events_dedup;
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedup ON events(ts, ip, COALESCE(port, -1), event_type, COALESCE(username, ''), COALESCE(detail, ''));
