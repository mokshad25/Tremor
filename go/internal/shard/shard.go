// Package shard runs the per-shard processing goroutines.
//
// Each shard owns the state for the services routed to it (Drain trees and
// baselines from Phase 3), so that state needs no locks. Events reach a shard
// in WAL sequence order, which is what makes a single number per shard a
// valid checkpoint.
package shard

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mokshad/tremor/internal/event"
	"github.com/mokshad/tremor/internal/router"
)

// Processor is the work a shard does per event. It is called from one
// goroutine only. Flush must make the effects of every Process call so far
// durable; it is called (from another goroutine) before a checkpoint is
// saved.
type Processor interface {
	Process(ev *event.Event)
	Flush() error
	Close() error
}

// Ticker is implemented by processors that need time to pass even when no
// events arrive (e.g. to notice that a service went silent). Advance is
// called from the shard goroutine, so it needs no locking either.
type Ticker interface {
	Advance(nowNs int64)
}

// Chain runs several processors in order for every event.
type Chain []Processor

func (c Chain) Process(ev *event.Event) {
	for _, p := range c {
		p.Process(ev)
	}
}

func (c Chain) Advance(nowNs int64) {
	for _, p := range c {
		if t, ok := p.(Ticker); ok {
			t.Advance(nowNs)
		}
	}
}

func (c Chain) Flush() error {
	for _, p := range c {
		if err := p.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func (c Chain) Close() error {
	var first error
	for _, p := range c {
		if err := p.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Message is one dispatch to one shard: the events routed to it, plus the
// watermark. After a shard handles a message, every event with seq <=
// Watermark that was routed to it has been processed, so its checkpoint can
// advance to Watermark even if Events is empty. Without watermarks an idle
// shard's checkpoint would never move, and it would pin every WAL segment
// forever.
type Message struct {
	Events    []event.Event
	Watermark uint64
}

type Shard struct {
	id       int
	in       chan Message
	restored uint64 // checkpoint loaded at startup: events <= this are skipped
	cp       atomic.Uint64
	proc     Processor

	processed atomic.Int64
	skipped   atomic.Int64
}

func (s *Shard) run(tickEvery time.Duration, now func() int64) {
	var tick <-chan time.Time
	ticker, isTicker := s.proc.(Ticker)
	if isTicker && tickEvery > 0 {
		t := time.NewTicker(tickEvery)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case m, ok := <-s.in:
			if !ok {
				return
			}
			s.handle(m)
		case <-tick:
			ticker.Advance(now())
		}
	}
}

func (s *Shard) handle(m Message) {
	for i := range m.Events {
		ev := &m.Events[i]
		if ev.Seq <= s.restored {
			// Already processed before the last checkpoint: this is the
			// replay overlap, dropped by sequence number.
			s.skipped.Add(1)
			continue
		}
		s.proc.Process(ev)
		s.processed.Add(1)
	}
	if m.Watermark > s.cp.Load() {
		s.cp.Store(m.Watermark)
	}
}

// Set is the group of shards plus the router that feeds them.
type Set struct {
	r      router.Router
	shards []*Shard
	wg     sync.WaitGroup

	// TickEvery is how often Ticker processors are advanced with the wall
	// clock (Now). Zero disables it. Set before Start.
	TickEvery time.Duration
	Now       func() int64
}

// NewSet creates len(restored) shards; restored[i] is shard i's checkpoint.
// queueCap bounds the messages waiting for each shard: when a shard falls
// behind, Dispatch blocks, which stalls the WAL committer, which fills the
// ingest queue, which turns into 429s at the gateway. Backpressure flows all
// the way back to the producer; nothing grows without bound.
func NewSet(r router.Router, restored []uint64, queueCap int, newProc func(id int) Processor) *Set {
	s := &Set{r: r}
	for i, cp := range restored {
		sh := &Shard{id: i, in: make(chan Message, queueCap), restored: cp, proc: newProc(i)}
		sh.cp.Store(cp)
		s.shards = append(s.shards, sh)
	}
	return s
}

func (s *Set) Start() {
	now := s.Now
	if now == nil {
		now = func() int64 { return time.Now().UnixNano() }
	}
	for _, sh := range s.shards {
		s.wg.Go(func() { sh.run(s.TickEvery, now) })
	}
}

// Dispatch routes events (already durable in the WAL, in seq order) to
// their shards and advances every shard's watermark. It must not be called
// concurrently with itself.
func (s *Set) Dispatch(groups [][]event.Event, watermark uint64) {
	buckets := make([][]event.Event, len(s.shards))
	for _, g := range groups {
		for i := range g {
			k := s.r.Shard(g[i].Service)
			buckets[k] = append(buckets[k], g[i])
		}
	}
	for i, sh := range s.shards {
		sh.in <- Message{Events: buckets[i], Watermark: watermark}
	}
}

// Close stops accepting dispatches and waits for every shard to drain. The
// processors stay open so a final Snapshot can flush them; release them with
// CloseProcessors afterwards.
func (s *Set) Close() {
	for _, sh := range s.shards {
		close(sh.in)
	}
	s.wg.Wait()
}

// CloseProcessors closes every processor. Call it after Close and after the
// final checkpoint has been saved.
func (s *Set) CloseProcessors() error {
	var first error
	for _, sh := range s.shards {
		if err := sh.proc.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// MinRestored is where replay must start from (minus one).
func (s *Set) MinRestored() uint64 {
	low := s.shards[0].restored
	for _, sh := range s.shards[1:] {
		low = min(low, sh.restored)
	}
	return low
}

// Snapshot returns checkpoints that are safe to persist. The order matters:
// read every shard's checkpoint FIRST, then flush the processors. Everything
// covered by a checkpoint value was processed before that value was stored,
// so the flush that follows makes it durable. Flushing first would leave a
// window where a checkpoint covers effects that were never flushed.
func (s *Set) Snapshot() ([]uint64, error) {
	cps := make([]uint64, len(s.shards))
	for i, sh := range s.shards {
		cps[i] = sh.cp.Load()
	}
	for _, sh := range s.shards {
		if err := sh.proc.Flush(); err != nil {
			return nil, err
		}
	}
	return cps, nil
}

// Stats returns totals for metrics.
func (s *Set) Stats() map[string]int64 {
	var processed, skipped, depth int64
	cps := make([]uint64, len(s.shards))
	for i, sh := range s.shards {
		processed += sh.processed.Load()
		skipped += sh.skipped.Load()
		depth += int64(len(sh.in))
		cps[i] = sh.cp.Load()
	}
	return map[string]int64{
		"shards":                       int64(len(s.shards)),
		"shard_events_processed_total": processed,
		"shard_events_skipped_total":   skipped,
		"shard_queue_depth_total":      depth,
		"shard_checkpoint_min":         int64(slices.Min(cps)),
		"shard_checkpoint_max":         int64(slices.Max(cps)),
	}
}

// Nop is a Processor that does nothing (Phase 2 has no detection yet).
type Nop struct{}

func (Nop) Process(*event.Event) {}
func (Nop) Flush() error         { return nil }
func (Nop) Close() error         { return nil }

// ShardStat is one shard's state for metrics.
type ShardStat struct {
	Depth      int
	Processed  int64
	Checkpoint uint64
}

// PerShard returns each shard's queue depth, processed count and checkpoint.
func (s *Set) PerShard() []ShardStat {
	out := make([]ShardStat, len(s.shards))
	for i, sh := range s.shards {
		out[i] = ShardStat{Depth: len(sh.in), Processed: sh.processed.Load(), Checkpoint: sh.cp.Load()}
	}
	return out
}
