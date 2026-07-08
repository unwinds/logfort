package notify

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// digestSchedule describes a recurring summary notification. Digests are not
// event rules: they fire on a wall-clock schedule and summarise a stats
// window, independent of live traffic.
type digestSchedule struct {
	label  string // "daily" | "weekly"
	window string // stats window the digest summarises: "24h" | "7d"
}

// digestHour is the local hour of day at which digests fire. 9:00 keeps the
// summary out of night-time notification silence windows on phones.
const digestHour = 9

// next returns the next wall-clock firing time strictly after now.
func (ds digestSchedule) next(now time.Time) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), digestHour, 0, 0, 0, now.Location())
	if ds.label == "weekly" {
		// Next Monday at digestHour.
		daysAhead := (int(time.Monday) - int(next.Weekday()) + 7) % 7
		next = next.AddDate(0, 0, daysAhead)
	}
	for !next.After(now) {
		if ds.label == "weekly" {
			next = next.AddDate(0, 0, 7)
		} else {
			next = next.AddDate(0, 0, 1)
		}
	}
	return next
}

// parseDigest converts "digest:daily" / "digest:weekly" into a schedule.
func parseDigest(s string) (digestSchedule, error) {
	switch strings.TrimPrefix(s, "digest:") {
	case "daily":
		return digestSchedule{label: "daily", window: "24h"}, nil
	case "weekly":
		return digestSchedule{label: "weekly", window: "7d"}, nil
	}
	return digestSchedule{}, fmt.Errorf("unknown digest %q; valid: digest:daily, digest:weekly", s)
}

// runDigest sleeps until each scheduled firing time and sends the summary.
// Exits when the dispatcher is stopped.
func (d *Dispatcher) runDigest(ds digestSchedule) {
	for {
		next := ds.next(time.Now())
		timer := time.NewTimer(time.Until(next))
		select {
		case <-d.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			d.sendDigest(ds)
		}
	}
}

// sendDigest builds and delivers one digest message to every notifier.
func (d *Dispatcher) sendDigest(ds digestSchedule) {
	if d.st == nil {
		return
	}
	ctx, cancel := context.WithTimeout(d.ctx, time.Minute)
	defer cancel()

	stats, err := d.st.GetStats(ctx, ds.window)
	if err != nil || stats == nil {
		slog.Warn("digest: stats query failed", "window", ds.window, "err", err)
		return
	}

	title := "LogFort: Daily Digest"
	period := "24 hours"
	if ds.label == "weekly" {
		title = "LogFort: Weekly Digest"
		period = "7 days"
	}

	var b strings.Builder
	if stats.TotalAttempts == 0 {
		fmt.Fprintf(&b, "All quiet: no authentication events in the last %s.", period)
	} else {
		fmt.Fprintf(&b, "Last %s: %d failed attempts from %d IPs, %d accepted logins.",
			period, stats.Failed, stats.UniqueIPs, stats.Accepted)
	}
	fmt.Fprintf(&b, "\nCurrently banned: %d", stats.CurrentlyBanned)

	if len(stats.TopIPs) > 0 {
		b.WriteString("\nTop attackers:")
		for i, t := range stats.TopIPs {
			if i == 3 {
				break
			}
			fmt.Fprintf(&b, " %s (%d", t.IP, t.Count)
			if t.Country != "" {
				b.WriteString(", " + t.Country)
			}
			b.WriteString(")")
		}
	}
	if len(stats.TopUsernames) > 0 {
		b.WriteString("\nTop usernames:")
		for i, t := range stats.TopUsernames {
			if i == 3 {
				break
			}
			fmt.Fprintf(&b, " %s (%d)", t.Username, t.Count)
		}
	}
	if len(stats.TopCountries) > 0 {
		b.WriteString("\nTop countries:")
		for i, t := range stats.TopCountries {
			if i == 3 {
				break
			}
			fmt.Fprintf(&b, " %s (%d)", t.Country, t.Count)
		}
	}

	msg := Message{
		Title:     title,
		Body:      b.String(),
		EventType: "digest",
		TS:        time.Now().Unix(),
	}
	for _, n := range d.notifiers {
		if err := n.Send(ctx, msg); err != nil {
			slog.Warn("digest send failed", "notifier", n.Name(), "err", err)
		}
	}
}
