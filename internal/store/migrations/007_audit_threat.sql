-- detail: free-text context for local audit events (sudo command, new-user
-- uid/shell) that has no dedicated column.
-- threat: name of the blocklist an IP matched at ingest time, or NULL.
-- NOTE: comments in migration files must not contain semicolons -- the runner
-- splits on that character with no SQL-aware parser.
ALTER TABLE events ADD COLUMN detail TEXT;
ALTER TABLE events ADD COLUMN threat TEXT;
CREATE INDEX IF NOT EXISTS idx_events_threat ON events(threat);
