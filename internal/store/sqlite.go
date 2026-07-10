package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/unwinds/logfort/internal/parse"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// SQLiteStore implements Store using a local SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// New opens (or creates) the SQLite database at dsn and applies migrations.
func New(dsn string) (*SQLiteStore, error) {
	// Ensure the parent directory exists for plain file paths; a missing
	// directory otherwise surfaces as an opaque "unable to open database file"
	// error on the first query.
	if dsn != ":memory:" && !strings.HasPrefix(dsn, "file:") {
		if dir := filepath.Dir(dsn); dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0o750)
		}
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", dsn, err)
	}
	// SQLite is not safe with concurrent writers; use a single connection.
	db.SetMaxOpenConns(1)

	s := &SQLiteStore{db: db}
	if err := s.applyPragmas(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *SQLiteStore) applyPragmas() error {
	for _, stmt := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
		"PRAGMA cache_size=-65536", // 64 MB page cache
		"PRAGMA temp_store=MEMORY", // sorts/groups in RAM
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("pragma %q: %w", stmt, err)
		}
	}
	return nil
}

func (s *SQLiteStore) migrate() error {
	// Ensure migrations table exists.
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	// Load applied versions.
	rows, err := s.db.Query("SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("query migrations: %w", err)
	}
	applied := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()

	// Collect migration files sorted by version number.
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		// Extract numeric version from filename prefix (e.g. "001_initial.sql" → 1).
		numStr := strings.SplitN(entry.Name(), "_", 2)[0]
		version, err := strconv.Atoi(numStr)
		if err != nil {
			return fmt.Errorf("parse migration version from %q: %w", entry.Name(), err)
		}
		if applied[version] {
			continue
		}

		data, err := migrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("begin tx: %w", err)
		}
		for _, stmt := range splitSQL(string(data)) {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("exec migration %s: %w", entry.Name(), err)
			}
		}
		if _, err := tx.Exec("INSERT INTO schema_migrations(version, applied_at) VALUES(?,?)", version, time.Now().Unix()); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", entry.Name(), err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// InsertEvent persists a parsed event to the database.
func (s *SQLiteStore) InsertEvent(ctx context.Context, e *parse.Event) error {
	var userValid *int
	if e.UserValid != nil {
		v := 0
		if *e.UserValid {
			v = 1
		}
		userValid = &v
	}
	var lat, lon *float64
	if e.Geo.Lat != 0 || e.Geo.Lon != 0 {
		lat, lon = &e.Geo.Lat, &e.Geo.Lon
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO events(ts, ip, event_type, username, user_valid, auth_method, port, source, country, city, lat, lon, asn, detail, threat, raw)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.TS.Unix(), e.IP, e.EventType, nullStr(e.Username), userValid,
		nullStr(e.AuthMethod), nullInt(e.Port), e.Source,
		nullStr(e.Geo.Country), nullStr(e.Geo.City), lat, lon, nullStr(e.Geo.ASN),
		nullStr(e.Detail), nullStr(e.Threat), nullStr(e.Raw),
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("insert event rows affected: %w", err)
	}
	if n == 0 {
		return ErrDuplicate
	}

	// Mirror ban/unban events into the bans table.
	// Use WHERE NOT EXISTS to skip insertion when an active ban for this IP
	// already exists — prevents duplicate rows on log re-reads at restart.
	if e.EventType == "ban" {
		_, err = s.db.ExecContext(ctx, `
			INSERT INTO bans(ip, jail, banned_at, active, source, reason)
			SELECT ?,?,?,1,'fail2ban',?
			WHERE NOT EXISTS (SELECT 1 FROM bans WHERE ip=? AND active=1)`,
			e.IP, nullStr(e.Username), e.TS.Unix(), nullStr(""), e.IP,
		)
	} else if e.EventType == "unban" {
		_, err = s.db.ExecContext(ctx, `
			UPDATE bans SET active=0, unbanned_at=? WHERE ip=? AND active=1 AND source='fail2ban'`,
			e.TS.Unix(), e.IP,
		)
	}
	return err
}

// ListEvents returns a filtered, paginated list of events and the total count.
func (s *SQLiteStore) ListEvents(ctx context.Context, q EventQuery) ([]EventRow, int64, error) {
	where, args := buildEventWhere(q)

	var total int64
	row := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events"+where, args...)
	if err := row.Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count events: %w", err)
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}

	args = append(args, limit, q.Offset)
	rows, err := s.db.QueryContext(ctx,
		"SELECT id,ts,ip,event_type,username,user_valid,auth_method,port,source,country,city,lat,lon,asn,detail,threat FROM events"+
			where+" ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?", args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	events := []EventRow{}
	for rows.Next() {
		var e EventRow
		var userValid sql.NullInt64
		var country, city, authMethod, username, asn, detail, threat sql.NullString
		var lat, lon sql.NullFloat64
		var port sql.NullInt64
		if err := rows.Scan(&e.ID, &e.TS, &e.IP, &e.EventType,
			&username, &userValid, &authMethod, &port,
			&e.Source, &country, &city, &lat, &lon, &asn, &detail, &threat); err != nil {
			return nil, 0, fmt.Errorf("scan event: %w", err)
		}
		e.Username = username.String
		e.AuthMethod = authMethod.String
		e.Country = country.String
		e.City = city.String
		e.ASN = asn.String
		e.Detail = detail.String
		e.Threat = threat.String
		if port.Valid {
			e.Port = int(port.Int64)
		}
		if userValid.Valid {
			v := userValid.Int64 == 1
			e.UserValid = &v
		}
		if lat.Valid {
			e.Lat = &lat.Float64
		}
		if lon.Valid {
			e.Lon = &lon.Float64
		}
		events = append(events, e)
	}
	return events, total, rows.Err()
}

// GetStats returns aggregate statistics for the given window.
func (s *SQLiteStore) GetStats(ctx context.Context, window string) (*Stats, error) {
	since, bucketSecs, err := windowToSince(window)
	if err != nil {
		return nil, err
	}

	args := []any{}
	whereTS := ""
	if since > 0 {
		whereTS = " WHERE ts >= ?"
		args = append(args, since)
	}

	st := &Stats{
		Window:       window,
		BucketSecs:   bucketSecs,
		TopIPs:       []TopIP{},
		TopCountries: []TopCountry{},
		TopUsernames: []TopUsername{},
		Timeline:     []TimeBucket{},
	}

	// Attack stats exclude ban/unban bookkeeping and local audit events (sudo,
	// account changes) — the latter have no source IP and are not remote attacks,
	// so counting them would skew every figure and add an empty-IP row to the tops.
	baseWhere := whereTS
	if baseWhere == "" {
		baseWhere = " WHERE event_type NOT IN (" + nonAttemptTypes + ")"
	} else {
		baseWhere += " AND event_type NOT IN (" + nonAttemptTypes + ")"
	}

	scanInt := func(query string, a ...any) (int64, error) {
		var v int64
		return v, s.db.QueryRowContext(ctx, query, a...).Scan(&v)
	}

	if st.TotalAttempts, err = scanInt("SELECT COUNT(*) FROM events"+baseWhere, args...); err != nil {
		return nil, err
	}
	if st.UniqueIPs, err = scanInt("SELECT COUNT(DISTINCT ip) FROM events"+baseWhere, args...); err != nil {
		return nil, err
	}

	// Failed = all non-accepted, non-ban/unban
	failWhere := baseWhere + " AND event_type != 'accepted'"
	if st.Failed, err = scanInt("SELECT COUNT(*) FROM events"+failWhere, args...); err != nil {
		return nil, err
	}

	acceptWhere := baseWhere + " AND event_type = 'accepted'"
	if st.Accepted, err = scanInt("SELECT COUNT(*) FROM events"+acceptWhere, args...); err != nil {
		return nil, err
	}

	if st.CurrentlyBanned, err = scanInt("SELECT COUNT(*) FROM bans WHERE active=1"); err != nil {
		return nil, err
	}

	// Top IPs
	topIPRows, err := s.db.QueryContext(ctx,
		"SELECT ip, COUNT(*) as c, MAX(country) FROM events"+baseWhere+
			" GROUP BY ip ORDER BY c DESC LIMIT 10", args...)
	if err != nil {
		return nil, err
	}
	defer topIPRows.Close()
	for topIPRows.Next() {
		var t TopIP
		var country sql.NullString
		if err := topIPRows.Scan(&t.IP, &t.Count, &country); err != nil {
			return nil, err
		}
		t.Country = country.String
		st.TopIPs = append(st.TopIPs, t)
	}
	topIPRows.Close()

	// Top countries
	tcRows, err := s.db.QueryContext(ctx,
		"SELECT country, COUNT(*) as c FROM events"+baseWhere+
			" AND country IS NOT NULL AND country != '' GROUP BY country ORDER BY c DESC LIMIT 10", args...)
	if err != nil {
		return nil, err
	}
	defer tcRows.Close()
	for tcRows.Next() {
		var t TopCountry
		if err := tcRows.Scan(&t.Country, &t.Count); err != nil {
			return nil, err
		}
		st.TopCountries = append(st.TopCountries, t)
	}
	tcRows.Close()

	// Top usernames
	tuRows, err := s.db.QueryContext(ctx,
		"SELECT username, COUNT(*) as c FROM events"+baseWhere+
			" AND username IS NOT NULL AND username != '' GROUP BY username ORDER BY c DESC LIMIT 10", args...)
	if err != nil {
		return nil, err
	}
	defer tuRows.Close()
	for tuRows.Next() {
		var t TopUsername
		if err := tuRows.Scan(&t.Username, &t.Count); err != nil {
			return nil, err
		}
		st.TopUsernames = append(st.TopUsernames, t)
	}
	tuRows.Close()

	// Timeline buckets
	tlRows, err := s.db.QueryContext(ctx,
		fmt.Sprintf("SELECT (ts / %d) * %d AS bucket, COUNT(*) FROM events%s GROUP BY bucket ORDER BY bucket", bucketSecs, bucketSecs, baseWhere),
		args...)
	if err != nil {
		return nil, err
	}
	defer tlRows.Close()
	for tlRows.Next() {
		var b TimeBucket
		if err := tlRows.Scan(&b.BucketTS, &b.Count); err != nil {
			return nil, err
		}
		st.Timeline = append(st.Timeline, b)
	}
	tlRows.Close()

	return st, nil
}

const banColumns = "id,ip,jail,banned_at,unbanned_at,expires_at,active,source,reason"

// scanBans reads BanRow records from a query over banColumns.
func scanBans(rows *sql.Rows) ([]BanRow, error) {
	bans := []BanRow{}
	for rows.Next() {
		var b BanRow
		var jail, reason sql.NullString
		var unbannedAt, expiresAt sql.NullInt64
		var active int64
		if err := rows.Scan(&b.ID, &b.IP, &jail, &b.BannedAt, &unbannedAt, &expiresAt, &active, &b.Source, &reason); err != nil {
			return nil, err
		}
		b.Jail = jail.String
		b.Reason = reason.String
		b.Active = active == 1
		if unbannedAt.Valid {
			b.UnbannedAt = &unbannedAt.Int64
		}
		if expiresAt.Valid {
			b.ExpiresAt = &expiresAt.Int64
		}
		bans = append(bans, b)
	}
	return bans, rows.Err()
}

// ListBans returns ban records, optionally filtered to active ones.
func (s *SQLiteStore) ListBans(ctx context.Context, activeOnly bool) ([]BanRow, error) {
	query := "SELECT " + banColumns + " FROM bans"
	if activeOnly {
		query += " WHERE active=1"
	}
	query += " ORDER BY banned_at DESC"

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBans(rows)
}

// ListExpiredBans returns active bans whose expiry has passed. Permanent bans
// (NULL expires_at) are never returned.
func (s *SQLiteStore) ListExpiredBans(ctx context.Context, now time.Time) ([]BanRow, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+banColumns+" FROM bans WHERE active=1 AND expires_at IS NOT NULL AND expires_at <= ? ORDER BY expires_at",
		now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBans(rows)
}

// GetMapPoints returns geo-aggregated attack points for the map view.
// Only events with known lat/lon are included.
func (s *SQLiteStore) GetMapPoints(ctx context.Context, window string) ([]MapPoint, error) {
	since, _, err := windowToSince(window)
	if err != nil {
		return nil, err
	}

	args := []any{}
	where := " WHERE lat IS NOT NULL AND lon IS NOT NULL AND event_type NOT IN (" + nonAttemptTypes + ")"
	if since > 0 {
		where += " AND ts >= ?"
		args = append(args, since)
	}

	rows, err := s.db.QueryContext(ctx,
		"SELECT ip, AVG(lat), AVG(lon), MAX(country), COUNT(*), MAX(ts) FROM events"+
			where+" GROUP BY ip ORDER BY COUNT(*) DESC LIMIT 500", args...)
	if err != nil {
		return nil, fmt.Errorf("map points: %w", err)
	}
	defer rows.Close()

	points := []MapPoint{}
	for rows.Next() {
		var p MapPoint
		var country sql.NullString
		if err := rows.Scan(&p.IP, &p.Lat, &p.Lon, &country, &p.Count, &p.LastSeen); err != nil {
			return nil, err
		}
		p.Country = country.String
		points = append(points, p)
	}
	return points, rows.Err()
}

// DeleteOldEvents removes events older than retentionDays. Inactive ban
// history rows older than the same cutoff are pruned in the same pass so the
// bans table does not grow without bound. Active bans are never touched.
func (s *SQLiteStore) DeleteOldEvents(ctx context.Context, retentionDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Unix()
	res, err := s.db.ExecContext(ctx, "DELETE FROM events WHERE ts < ?", cutoff)
	if err != nil {
		return 0, err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM bans WHERE active=0 AND banned_at < ?", cutoff); err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// BanIP inserts a new ban record, skipping if an active ban for this IP exists.
// expiresAt is a Unix timestamp after which the expiry sweeper lifts the ban;
// 0 stores NULL (permanent).
func (s *SQLiteStore) BanIP(ctx context.Context, ip, source, reason string, expiresAt int64) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO bans(ip, banned_at, active, source, reason, expires_at)
		SELECT ?, ?, 1, ?, ?, ?
		WHERE NOT EXISTS (SELECT 1 FROM bans WHERE ip=? AND active=1)`,
		ip, time.Now().Unix(), source, nullStr(reason), nullInt64(expiresAt), ip,
	)
	return err
}

// UnbanIP marks all active bans for an IP as inactive.
func (s *SQLiteStore) UnbanIP(ctx context.Context, ip string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE bans SET active=0, unbanned_at=? WHERE ip=? AND active=1`,
		time.Now().Unix(), ip,
	)
	return err
}

// nonAttemptTypes is the SQL IN-list of event types excluded from attack
// statistics: ban/unban bookkeeping and local privilege-audit events, which
// carry no source IP and are not remote attacks.
const nonAttemptTypes = "'ban','unban','sudo_session','sudo_fail','user_add','user_del'"

// GetIPInfo returns an aggregate profile for a single IP address.
func (s *SQLiteStore) GetIPInfo(ctx context.Context, ip string) (*IPInfo, error) {
	info := &IPInfo{IP: ip, TypeCounts: map[string]int64{}}

	var first, last sql.NullInt64
	var country, city, asn, threat sql.NullString
	var lat, lon sql.NullFloat64
	err := s.db.QueryRowContext(ctx, `
		SELECT MIN(ts), MAX(ts), COUNT(*),
		       MAX(country), MAX(city), MAX(lat), MAX(lon), MAX(asn), MAX(threat)
		FROM events WHERE ip = ?`, ip).
		Scan(&first, &last, &info.Total, &country, &city, &lat, &lon, &asn, &threat)
	if err != nil {
		return nil, fmt.Errorf("ip info: %w", err)
	}
	if first.Valid {
		info.FirstSeen = first.Int64
	}
	if last.Valid {
		info.LastSeen = last.Int64
	}
	info.Country = country.String
	info.City = city.String
	info.ASN = asn.String
	info.Threat = threat.String
	if lat.Valid {
		info.Lat = &lat.Float64
	}
	if lon.Valid {
		info.Lon = &lon.Float64
	}

	rows, err := s.db.QueryContext(ctx,
		"SELECT event_type, COUNT(*) FROM events WHERE ip = ? GROUP BY event_type", ip)
	if err != nil {
		return nil, fmt.Errorf("ip info types: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		var c int64
		if err := rows.Scan(&t, &c); err != nil {
			return nil, err
		}
		info.TypeCounts[t] = c
	}
	return info, rows.Err()
}

// CountIPEvents returns the number of actual failed authentication attempts
// from ip since the given time. Only primary attempt events are counted:
// sshd logs several lines per wrong password for an unknown user
// ("Invalid user", pam_unix failure, preauth disconnect) and counting those
// auxiliary lines would double- or triple-count a single attempt, making
// auto-ban and threshold alerts fire far earlier than configured. Accepted
// logins never count.
func (s *SQLiteStore) CountIPEvents(ctx context.Context, ip string, since time.Time) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM events WHERE ip=? AND ts>=? AND event_type IN ('failed_password','http_auth_fail','mail_auth_fail','max_auth')",
		ip, since.Unix(),
	).Scan(&count)
	return count, err
}

// GetSetting returns the stored value for key. found is false when absent.
func (s *SQLiteStore) GetSetting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return v, err == nil, err
}

// SetSetting upserts a key-value pair.
func (s *SQLiteStore) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
		key, value)
	return err
}

// SetSettings atomically persists multiple key-value pairs in a single transaction.
func (s *SQLiteStore) SetSettings(ctx context.Context, pairs map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin settings tx: %w", err)
	}
	for k, v := range pairs {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
			k, v); err != nil {
			tx.Rollback()
			return fmt.Errorf("set setting %q: %w", k, err)
		}
	}
	return tx.Commit()
}

// GetAllSettings returns all key-value pairs.
func (s *SQLiteStore) GetAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, rows.Err()
}

// Ping verifies the database answers queries — a cheap end-to-end probe for
// the health endpoint (sql.DB.Ping alone may not touch SQLite at all).
func (s *SQLiteStore) Ping(ctx context.Context) error {
	var one int
	return s.db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}

// Backup writes a consistent snapshot of the database to dstPath using
// VACUUM INTO. The snapshot is taken at a single point in time and is safe
// to run while the pipeline keeps writing; the destination must not exist.
func (s *SQLiteStore) Backup(ctx context.Context, dstPath string) error {
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", dstPath); err != nil {
		return fmt.Errorf("vacuum into %q: %w", dstPath, err)
	}
	return nil
}

// Close updates query-planner statistics and closes the database.
func (s *SQLiteStore) Close() error {
	_, _ = s.db.Exec("PRAGMA optimize")
	return s.db.Close()
}

// --- helpers ---

func buildEventWhere(q EventQuery) (string, []any) {
	var conds []string
	var args []any

	if q.EventType != "" {
		conds = append(conds, "event_type = ?")
		args = append(args, q.EventType)
	}
	if q.IP != "" {
		conds = append(conds, "ip = ?")
		args = append(args, q.IP)
	}
	if q.Country != "" {
		conds = append(conds, "country = ?")
		args = append(args, q.Country)
	}
	if q.Username != "" {
		conds = append(conds, "username = ?")
		args = append(args, q.Username)
	}
	if q.Since != nil {
		conds = append(conds, "ts >= ?")
		args = append(args, q.Since.Unix())
	}
	if q.Until != nil {
		conds = append(conds, "ts <= ?")
		args = append(args, q.Until.Unix())
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// IsValidWindow reports whether window is an accepted stats/map window value.
// Handlers use it to distinguish a client error (bad window → 400) from an
// internal store failure (→ 500).
func IsValidWindow(window string) bool {
	switch window {
	case "1h", "6h", "24h", "", "7d", "30d", "all":
		return true
	}
	return false
}

// windowToSince converts a window string to a Unix timestamp (0 = no filter)
// and the bucket size in seconds for timeline grouping. Bucket sizes are
// chosen so every window renders a meaningful number of bars (~12–30).
func windowToSince(window string) (since int64, bucketSecs int64, err error) {
	now := time.Now()
	switch window {
	case "1h":
		return now.Add(-time.Hour).Unix(), 300, nil
	case "6h":
		return now.Add(-6 * time.Hour).Unix(), 1800, nil
	case "24h", "":
		return now.Add(-24 * time.Hour).Unix(), 3600, nil
	case "7d":
		return now.AddDate(0, 0, -7).Unix(), 86400, nil
	case "30d":
		return now.AddDate(0, 0, -30).Unix(), 86400, nil
	case "all":
		return 0, 86400, nil
	default:
		return 0, 0, fmt.Errorf("invalid window %q; use 1h|6h|24h|7d|30d|all", window)
	}
}

// splitSQL splits a migration file into individual statements on ";" so that
// multi-statement files are executed one statement at a time. This is necessary
// because database/sql does not guarantee that drivers execute all statements in
// a multi-statement Exec call.
func splitSQL(s string) []string {
	var stmts []string
	for _, stmt := range strings.Split(s, ";") {
		if stmt = strings.TrimSpace(stmt); stmt != "" {
			stmts = append(stmts, stmt)
		}
	}
	return stmts
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
