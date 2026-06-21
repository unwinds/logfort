package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/unwinds/sshwatch/internal/parse"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// SQLiteStore implements Store using a local SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// New opens (or creates) the SQLite database at dsn and applies migrations.
func New(dsn string) (*SQLiteStore, error) {
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
		if _, err := tx.Exec(string(data)); err != nil {
			tx.Rollback()
			return fmt.Errorf("exec migration %s: %w", entry.Name(), err)
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

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO events(ts, ip, event_type, username, user_valid, auth_method, port, source, country, city, lat, lon, asn, raw)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.TS.Unix(), e.IP, e.EventType, nullStr(e.Username), userValid,
		nullStr(e.AuthMethod), nullInt(e.Port), e.Source,
		nullStr(e.Geo.Country), nullStr(e.Geo.City), lat, lon, nullStr(e.Geo.ASN),
		nullStr(e.Raw),
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}

	// Mirror ban/unban events into the bans table.
	if e.EventType == "ban" {
		_, err = s.db.ExecContext(ctx, `
			INSERT INTO bans(ip, jail, banned_at, active, source, reason)
			VALUES(?,?,?,1,'fail2ban',?)
			ON CONFLICT DO NOTHING`,
			e.IP, nullStr(e.Username), e.TS.Unix(), nullStr(""),
		)
	} else if e.EventType == "unban" {
		_, err = s.db.ExecContext(ctx, `
			UPDATE bans SET active=0, unbanned_at=? WHERE ip=? AND active=1`,
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

	countArgs := len(args)
	args = append(args, limit, q.Offset)
	rows, err := s.db.QueryContext(ctx,
		"SELECT id,ts,ip,event_type,username,user_valid,auth_method,port,source,country,city,lat,lon FROM events"+
			where+" ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?", args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()
	_ = countArgs

	var events []EventRow
	for rows.Next() {
		var e EventRow
		var userValid sql.NullInt64
		var country, city, authMethod, username sql.NullString
		var lat, lon sql.NullFloat64
		var port sql.NullInt64
		if err := rows.Scan(&e.ID, &e.TS, &e.IP, &e.EventType,
			&username, &userValid, &authMethod, &port,
			&e.Source, &country, &city, &lat, &lon); err != nil {
			return nil, 0, fmt.Errorf("scan event: %w", err)
		}
		e.Username = username.String
		e.AuthMethod = authMethod.String
		e.Country = country.String
		e.City = city.String
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

	st := &Stats{Window: window}

	// Total attempts (non-ban/unban events)
	baseWhere := whereTS
	if baseWhere == "" {
		baseWhere = " WHERE event_type NOT IN ('ban','unban')"
	} else {
		baseWhere += " AND event_type NOT IN ('ban','unban')"
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

// ListBans returns ban records, optionally filtered to active ones.
func (s *SQLiteStore) ListBans(ctx context.Context, activeOnly bool) ([]BanRow, error) {
	query := "SELECT id,ip,jail,banned_at,unbanned_at,active,source,reason FROM bans"
	if activeOnly {
		query += " WHERE active=1"
	}
	query += " ORDER BY banned_at DESC"

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bans []BanRow
	for rows.Next() {
		var b BanRow
		var jail, reason sql.NullString
		var unbannedAt sql.NullInt64
		var active int64
		if err := rows.Scan(&b.ID, &b.IP, &jail, &b.BannedAt, &unbannedAt, &active, &b.Source, &reason); err != nil {
			return nil, err
		}
		b.Jail = jail.String
		b.Reason = reason.String
		b.Active = active == 1
		if unbannedAt.Valid {
			b.UnbannedAt = &unbannedAt.Int64
		}
		bans = append(bans, b)
	}
	return bans, rows.Err()
}

// GetMapPoints returns geo-aggregated attack points for the map view.
// Only events with known lat/lon are included.
func (s *SQLiteStore) GetMapPoints(ctx context.Context, window string) ([]MapPoint, error) {
	since, _, err := windowToSince(window)
	if err != nil {
		return nil, err
	}

	args := []any{}
	where := " WHERE lat IS NOT NULL AND lon IS NOT NULL AND event_type NOT IN ('ban','unban')"
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

	var points []MapPoint
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

// DeleteOldEvents removes events older than retentionDays.
func (s *SQLiteStore) DeleteOldEvents(ctx context.Context, retentionDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Unix()
	res, err := s.db.ExecContext(ctx, "DELETE FROM events WHERE ts < ?", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error { return s.db.Close() }

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

// windowToSince converts a window string to a Unix timestamp (0 = no filter)
// and the bucket size in seconds for timeline grouping.
func windowToSince(window string) (since int64, bucketSecs int64, err error) {
	now := time.Now()
	switch window {
	case "1h":
		return now.Add(-time.Hour).Unix(), 3600, nil
	case "6h":
		return now.Add(-6 * time.Hour).Unix(), 3600, nil
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
