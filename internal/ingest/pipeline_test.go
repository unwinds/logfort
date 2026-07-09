package ingest_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/unwinds/logfort/internal/geo"
	"github.com/unwinds/logfort/internal/ingest"
	"github.com/unwinds/logfort/internal/parse"
	"github.com/unwinds/logfort/internal/store"
)

// fakeSource sends a fixed set of lines then exits (no blocking).
type fakeSource struct{ lines []string }

func (f *fakeSource) Info() ingest.SourceInfo {
	return ingest.SourceInfo{Kind: "fake", Target: "test"}
}

func (f *fakeSource) Start(ctx context.Context, out chan<- string) error {
	for _, l := range f.lines {
		select {
		case out <- l:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// stubStore records InsertEvent calls; optionally returns ErrDuplicate.
type stubStore struct {
	mu       sync.Mutex
	inserted []*parse.Event
	dupErr   bool
}

func (s *stubStore) InsertEvent(_ context.Context, e *parse.Event) error {
	if s.dupErr {
		return store.ErrDuplicate
	}
	s.mu.Lock()
	s.inserted = append(s.inserted, e)
	s.mu.Unlock()
	return nil
}

func (s *stubStore) events() []*parse.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]*parse.Event, len(s.inserted))
	copy(cp, s.inserted)
	return cp
}

func (s *stubStore) ListEvents(_ context.Context, _ store.EventQuery) ([]store.EventRow, int64, error) {
	return []store.EventRow{}, 0, nil
}
func (s *stubStore) GetStats(_ context.Context, _ string) (*store.Stats, error) {
	return &store.Stats{
		TopIPs: []store.TopIP{}, TopCountries: []store.TopCountry{},
		TopUsernames: []store.TopUsername{}, Timeline: []store.TimeBucket{},
	}, nil
}
func (s *stubStore) ListBans(_ context.Context, _ bool) ([]store.BanRow, error) {
	return []store.BanRow{}, nil
}
func (s *stubStore) GetMapPoints(_ context.Context, _ string) ([]store.MapPoint, error) {
	return []store.MapPoint{}, nil
}
func (s *stubStore) DeleteOldEvents(_ context.Context, _ int) (int64, error) { return 0, nil }
func (s *stubStore) BanIP(_ context.Context, _, _, _ string, _ int64) error  { return nil }
func (s *stubStore) UnbanIP(_ context.Context, _ string) error               { return nil }
func (s *stubStore) ListExpiredBans(_ context.Context, _ time.Time) ([]store.BanRow, error) {
	return []store.BanRow{}, nil
}
func (s *stubStore) CountIPEvents(_ context.Context, _ string, _ time.Time) (int64, error) {
	return 0, nil
}
func (s *stubStore) GetIPInfo(_ context.Context, ip string) (*store.IPInfo, error) {
	return &store.IPInfo{IP: ip, TypeCounts: map[string]int64{}}, nil
}
func (s *stubStore) GetSetting(_ context.Context, _ string) (string, bool, error) {
	return "", false, nil
}
func (s *stubStore) SetSetting(_ context.Context, _, _ string) error             { return nil }
func (s *stubStore) SetSettings(_ context.Context, _ map[string]string) error    { return nil }
func (s *stubStore) GetAllSettings(_ context.Context) (map[string]string, error) { return nil, nil }
func (s *stubStore) Ping(_ context.Context) error                                { return nil }
func (s *stubStore) Backup(_ context.Context, _ string) error                    { return nil }
func (s *stubStore) Close() error                                                { return nil }

const sshFail = "Jun 21 14:32:01 myhost sshd[12345]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2"
const sshAccept = "Jun 21 14:32:10 myhost sshd[12348]: Accepted publickey for bob from 192.0.2.11 port 22001 ssh2"
const noMatch = "Jun 21 14:33:32 myhost sudo[1234]: alice : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/apt"

func TestPipeline_ParsedCounters(t *testing.T) {
	src := &fakeSource{lines: []string{sshFail, sshAccept, noMatch}}
	st := &stubStore{}

	p := ingest.NewPipeline([]ingest.Source{src}, parse.ParseLine, st)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := p.Run(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}

	parsed, unparsed := p.Counters()
	if parsed != 2 {
		t.Errorf("parsed = %d, want 2", parsed)
	}
	if unparsed != 1 {
		t.Errorf("unparsed = %d, want 1", unparsed)
	}
	if len(st.events()) != 2 {
		t.Errorf("inserted events = %d, want 2", len(st.events()))
	}
}

func TestPipeline_ErrDuplicateSkipsPublish(t *testing.T) {
	src := &fakeSource{lines: []string{sshFail}}
	st := &stubStore{dupErr: true}

	published := 0
	p := ingest.NewPipeline([]ingest.Source{src}, parse.ParseLine, st)
	p.SetPublishHook(func(_ *parse.Event) { published++ })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := p.Run(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}

	if published != 0 {
		t.Errorf("publish hook called %d times on ErrDuplicate, want 0", published)
	}
	// parsed counter is still incremented even if insert returns ErrDuplicate
	parsed, _ := p.Counters()
	if parsed != 1 {
		t.Errorf("parsed = %d, want 1", parsed)
	}
}

func TestPipeline_PublishHookCalledOnSuccess(t *testing.T) {
	src := &fakeSource{lines: []string{sshFail, sshAccept}}
	st := &stubStore{}

	var published []*parse.Event
	var mu sync.Mutex
	p := ingest.NewPipeline([]ingest.Source{src}, parse.ParseLine, st)
	p.SetPublishHook(func(ev *parse.Event) {
		mu.Lock()
		published = append(published, ev)
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := p.Run(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}

	mu.Lock()
	n := len(published)
	mu.Unlock()
	if n != 2 {
		t.Errorf("publish hook called %d times, want 2", n)
	}
}

func TestPipeline_GeoLookup(t *testing.T) {
	src := &fakeSource{lines: []string{sshFail}}
	st := &stubStore{}

	// fakeGeo returns a fixed country for any IP.
	type fakeGeo struct{ geo.Looker }
	_ = fakeGeo{}

	p := ingest.NewPipeline([]ingest.Source{src}, parse.ParseLine, st)
	p.SetGeo(fixedGeo{country: "US", city: "TestCity"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := p.Run(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}

	evs := st.events()
	if len(evs) != 1 {
		t.Fatalf("inserted = %d, want 1", len(evs))
	}
	if evs[0].Geo.Country != "US" {
		t.Errorf("Geo.Country = %q, want %q", evs[0].Geo.Country, "US")
	}
	if evs[0].Geo.City != "TestCity" {
		t.Errorf("Geo.City = %q, want %q", evs[0].Geo.City, "TestCity")
	}
}

func TestPipeline_MultipleSources(t *testing.T) {
	src1 := &fakeSource{lines: []string{sshFail}}
	src2 := &fakeSource{lines: []string{sshAccept}}
	st := &stubStore{}

	p := ingest.NewPipeline([]ingest.Source{src1, src2}, parse.ParseLine, st)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := p.Run(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}

	if len(st.events()) != 2 {
		t.Errorf("inserted = %d, want 2", len(st.events()))
	}
}

// fixedGeo is a geo.Looker that returns fixed Info for any IP.
type fixedGeo struct {
	country string
	city    string
}

func (f fixedGeo) Lookup(_ string) geo.Info {
	return geo.Info{Country: f.country, City: f.city}
}
