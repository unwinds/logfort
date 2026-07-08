-- Ban expiry: NULL expires_at = permanent ban. Otherwise the expiry sweeper
-- unbans and deactivates the row once expires_at has passed.
-- NOTE: comments in migration files must not contain semicolons because the
-- migration runner splits files on that character without a SQL-aware parser.
ALTER TABLE bans ADD COLUMN expires_at INTEGER;
CREATE INDEX IF NOT EXISTS idx_bans_active_expires ON bans(active, expires_at);

-- ip_intel was reserved for rDNS enrichment that never shipped. ASN now comes
-- from the optional local ASN mmdb instead, so the table has no callers.
DROP TABLE IF EXISTS ip_intel;
