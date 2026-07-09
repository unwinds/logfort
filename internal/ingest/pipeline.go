package ingest

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/unwinds/logfort/internal/geo"
	"github.com/unwinds/logfort/internal/parse"
	"github.com/unwinds/logfort/internal/store"
	"github.com/unwinds/logfort/internal/threat"
)

// Pipeline connects one or more Sources to the store via a parse worker pool.
type Pipeline struct {
	sources   []Source
	parseFunc func(string) (*parse.Event, error)
	store     store.Store
	geo       geo.Looker
	blocklist *threat.List
	workers   int
	publish   func(*parse.Event) // optional SSE hook (nil = no-op)

	parsed   atomic.Int64
	unparsed atomic.Int64

	statusMu sync.Mutex
	statuses []SourceStatus // index-aligned with sources
}

// NewPipeline creates a Pipeline with the given sources and dependencies.
func NewPipeline(sources []Source, parseFunc func(string) (*parse.Event, error), st store.Store) *Pipeline {
	statuses := make([]SourceStatus, len(sources))
	for i, s := range sources {
		statuses[i] = SourceStatus{SourceInfo: s.Info(), State: "starting"}
	}
	return &Pipeline{
		sources:   sources,
		parseFunc: parseFunc,
		store:     st,
		workers:   4,
		statuses:  statuses,
	}
}

// SetGeo wires a GeoIP looker into the pipeline.
// If not set, geo fields are left empty.
func (p *Pipeline) SetGeo(g geo.Looker) { p.geo = g }

// SetBlocklist wires a threat blocklist into the pipeline. When set, each
// event's source IP is checked and Event.Threat is filled with the list name on
// a match. Nil-safe: a nil list is a no-op.
func (p *Pipeline) SetBlocklist(l *threat.List) { p.blocklist = l }

// SetPublishHook sets a function called for every successfully parsed event.
// Used by the SSE hub (v0.3+).
func (p *Pipeline) SetPublishHook(fn func(*parse.Event)) { p.publish = fn }

// Counters returns the total parsed and unparsed (no-match) line counts.
func (p *Pipeline) Counters() (parsed, unparsed int64) {
	return p.parsed.Load(), p.unparsed.Load()
}

// SourceStatuses returns a snapshot of every source's health for /api/health.
func (p *Pipeline) SourceStatuses() []SourceStatus {
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	out := make([]SourceStatus, len(p.statuses))
	copy(out, p.statuses)
	return out
}

func (p *Pipeline) setStatus(i int, state, errMsg string) {
	p.statusMu.Lock()
	p.statuses[i].State = state
	p.statuses[i].Error = errMsg
	p.statusMu.Unlock()
}

// Run starts all sources and the worker pool. It blocks until ctx is done.
func (p *Pipeline) Run(ctx context.Context) error {
	lines := make(chan string, 1000)

	// Start all sources concurrently; close lines when all are done.
	var srcWg sync.WaitGroup
	for i, src := range p.sources {
		srcWg.Add(1)
		i, s := i, src
		go func() {
			defer srcWg.Done()
			backoff := time.Second
			for {
				p.setStatus(i, "running", "")
				err := s.Start(ctx, lines)
				if err == nil || errors.Is(err, context.Canceled) || ctx.Err() != nil {
					return
				}
				p.setStatus(i, "error", err.Error())
				slog.Error("source error, retrying", "err", err, "backoff", backoff)
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
			}
		}()
	}
	go func() {
		srcWg.Wait()
		close(lines)
	}()

	// Worker pool: parse → store → publish.
	var workerWg sync.WaitGroup
	for range p.workers {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for line := range lines {
				ev, err := p.parseFunc(line)
				if errors.Is(err, parse.ErrNoMatch) {
					p.unparsed.Add(1)
					continue
				}
				if err != nil {
					slog.Warn("parse error", "err", err, "line", line)
					p.unparsed.Add(1)
					continue
				}
				p.parsed.Add(1)
				if p.geo != nil && ev.IP != "" {
					info := p.geo.Lookup(ev.IP)
					ev.Geo.Country = info.Country
					ev.Geo.City = info.City
					ev.Geo.Lat = info.Lat
					ev.Geo.Lon = info.Lon
					ev.Geo.ASN = info.ASN
				}
				if p.blocklist != nil && ev.IP != "" {
					ev.Threat = p.blocklist.Lookup(ev.IP)
				}
				if err := p.store.InsertEvent(ctx, ev); err != nil {
					if errors.Is(err, store.ErrDuplicate) {
						continue
					}
					if !errors.Is(err, context.Canceled) {
						slog.Error("store event", "err", err)
					}
				}
				if p.publish != nil {
					p.publish(ev)
				}
			}
		}()
	}

	workerWg.Wait()
	return nil
}
