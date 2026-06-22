package ingest

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/unwinds/logfort/internal/geo"
	"github.com/unwinds/logfort/internal/parse"
	"github.com/unwinds/logfort/internal/store"
)

// Pipeline connects one or more Sources to the store via a parse worker pool.
type Pipeline struct {
	sources   []Source
	parseFunc func(string) (*parse.Event, error)
	store     store.Store
	geo       geo.Looker
	workers   int
	publish   func(*parse.Event) // optional SSE hook (nil = no-op)

	parsed   atomic.Int64
	unparsed atomic.Int64
}

// NewPipeline creates a Pipeline with the given sources and dependencies.
func NewPipeline(sources []Source, parseFunc func(string) (*parse.Event, error), st store.Store) *Pipeline {
	return &Pipeline{
		sources:   sources,
		parseFunc: parseFunc,
		store:     st,
		workers:   4,
	}
}

// SetGeo wires a GeoIP looker into the pipeline.
// If not set, geo fields are left empty.
func (p *Pipeline) SetGeo(g geo.Looker) { p.geo = g }

// SetPublishHook sets a function called for every successfully parsed event.
// Used by the SSE hub (v0.3+).
func (p *Pipeline) SetPublishHook(fn func(*parse.Event)) { p.publish = fn }

// Counters returns the total parsed and unparsed (no-match) line counts.
func (p *Pipeline) Counters() (parsed, unparsed int64) {
	return p.parsed.Load(), p.unparsed.Load()
}

// Run starts all sources and the worker pool. It blocks until ctx is done.
func (p *Pipeline) Run(ctx context.Context) error {
	lines := make(chan string, 1000)

	// Start all sources concurrently; close lines when all are done.
	var srcWg sync.WaitGroup
	for _, src := range p.sources {
		srcWg.Add(1)
		s := src
		go func() {
			defer srcWg.Done()
			if err := s.Start(ctx, lines); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("source error", "err", err)
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
