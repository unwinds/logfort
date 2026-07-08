package ingest

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

// demoSource emits synthetic auth-log lines so the dashboard can be evaluated
// without pointing LogFort at a real server. It backfills ~24 h of history at
// startup (pre-startup timestamps, so the notify replay guard keeps notifiers
// quiet), then drips live events. Lines go through the normal parse pipeline —
// demo mode exercises exactly the same code paths as production.
type demoSource struct{}

// NewDemoSource returns a Source that generates synthetic traffic.
func NewDemoSource() Source { return &demoSource{} }

func (d *demoSource) Info() SourceInfo {
	return SourceInfo{Kind: "demo", Target: "synthetic traffic generator"}
}

const demoBackfillLines = 1500

// First octets of commonly allocated public ranges. Random addresses inside
// them mostly resolve in GeoIP/ASN databases, which keeps the demo map alive.
var demoOctets = []int{
	5, 23, 31, 37, 45, 46, 59, 61, 77, 80, 89, 91, 94, 101, 103, 109,
	111, 113, 121, 125, 134, 139, 141, 152, 159, 163, 171, 176, 178,
	185, 190, 193, 195, 200, 202, 210, 212, 217, 218, 220, 222,
}

var demoUsers = []string{
	"root", "admin", "ubuntu", "test", "oracle", "postgres", "git",
	"deploy", "user", "ftpuser", "pi", "minecraft", "www", "backup",
}

func demoIP(rng *rand.Rand) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		demoOctets[rng.Intn(len(demoOctets))],
		rng.Intn(254)+1, rng.Intn(254)+1, rng.Intn(254)+1)
}

func (d *demoSource) Start(ctx context.Context, out chan<- string) error {
	rng := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // demo data, not crypto

	// A handful of "hot" attackers dominate the top lists, like real traffic.
	hot := make([]string, 8)
	for i := range hot {
		hot[i] = demoIP(rng)
	}
	pickIP := func() string {
		if rng.Intn(100) < 60 {
			return hot[rng.Intn(len(hot))]
		}
		return demoIP(rng)
	}

	send := func(line string) bool {
		select {
		case out <- line:
			return true
		case <-ctx.Done():
			return false
		}
	}

	// Backfill the last 24 h so charts and top lists are populated on first load.
	now := time.Now()
	for i := 0; i < demoBackfillLines; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ts := now.Add(-time.Duration(rng.Int63n(int64(24 * time.Hour))))
		if !send(demoLine(rng, ts, pickIP)) {
			return ctx.Err()
		}
	}

	// Live drip: bursts of 1–3 lines every 0.5–4 s.
	for {
		delay := time.Duration(500+rng.Intn(3500)) * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		for n := rng.Intn(3) + 1; n > 0; n-- {
			if !send(demoLine(rng, time.Now(), pickIP)) {
				return ctx.Err()
			}
		}
	}
}

// demoLine renders one synthetic log line in a randomly chosen source format.
func demoLine(rng *rand.Rand, ts time.Time, pickIP func() string) string {
	local := ts.Local()
	sysTS := local.Format("Jan _2 15:04:05")
	ip := pickIP()
	user := demoUsers[rng.Intn(len(demoUsers))]
	port := rng.Intn(60000) + 1025
	pid := rng.Intn(30000) + 1000

	switch v := rng.Intn(100); {
	case v < 50: // sshd failed password
		return fmt.Sprintf("%s demo sshd[%d]: Failed password for invalid user %s from %s port %d ssh2",
			sysTS, pid, user, ip, port)
	case v < 60: // sshd invalid user
		return fmt.Sprintf("%s demo sshd[%d]: Invalid user %s from %s port %d",
			sysTS, pid, user, ip, port)
	case v < 68: // sshd preauth disconnect
		return fmt.Sprintf("%s demo sshd[%d]: Connection closed by invalid user %s %s port %d [preauth]",
			sysTS, pid, user, ip, port)
	case v < 75: // nginx access.log 401
		return fmt.Sprintf(`%s - %s [%s] "GET /admin HTTP/1.1" 401 188 "-" "Mozilla/5.0"`,
			ip, user, local.Format("02/Jan/2006:15:04:05 -0700"))
	case v < 82: // postfix SASL failure
		return fmt.Sprintf("%s demo postfix/smtpd[%d]: warning: unknown[%s]: SASL LOGIN authentication failed: authentication failure",
			sysTS, pid, ip)
	case v < 89: // dovecot imap failure
		return fmt.Sprintf("%s demo dovecot: imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=<%s>, method=PLAIN, rip=%s, lip=10.0.0.5",
			sysTS, user, ip)
	case v < 93: // sshd max_auth
		return fmt.Sprintf("%s demo sshd[%d]: error: maximum authentication attempts exceeded for %s from %s port %d ssh2 [preauth]",
			sysTS, pid, user, ip, port)
	case v < 96: // accepted login from a stable "friendly" address
		return fmt.Sprintf("%s demo sshd[%d]: Accepted publickey for deploy from 91.198.174.192 port %d ssh2",
			sysTS, pid, port)
	case v < 98: // fail2ban ban
		return fmt.Sprintf("%s,%03d fail2ban.actions [sshd] Ban %s",
			local.Format("2006-01-02 15:04:05"), rng.Intn(999), ip)
	default: // fail2ban unban
		return fmt.Sprintf("%s,%03d fail2ban.actions [sshd] Unban %s",
			local.Format("2006-01-02 15:04:05"), rng.Intn(999), ip)
	}
}
