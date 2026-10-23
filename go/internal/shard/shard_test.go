package shard

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mokshad/tremor/internal/event"
	"github.com/mokshad/tremor/internal/router"
)

// recordingProc remembers the seqs it processed, per shard.
type recordingProc struct {
	mu      sync.Mutex
	seqs    []uint64
	svc     map[string]bool
	flushes int
}

func (r *recordingProc) Process(ev *event.Event) {
	r.mu.Lock()
	r.seqs = append(r.seqs, ev.Seq)
	r.svc[ev.Service] = true
	r.mu.Unlock()
}
func (r *recordingProc) Flush() error { r.mu.Lock(); r.flushes++; r.mu.Unlock(); return nil }
func (r *recordingProc) Close() error { return nil }

func seqEvents(from, to uint64, services int) []event.Event {
	var out []event.Event
	for s := from; s <= to; s++ {
		out = append(out, event.Event{Seq: s, Service: fmt.Sprintf("svc-%d", s%uint64(services))})
	}
	return out
}

func newSet(restored []uint64) (*Set, []*recordingProc) {
	procs := make([]*recordingProc, len(restored))
	s := NewSet(router.NewModulo(len(restored)), restored, 4, func(id int) Processor {
		procs[id] = &recordingProc{svc: map[string]bool{}}
		return procs[id]
	})
	s.Start()
	return s, procs
}

func TestDispatchRoutesInOrderAndAdvancesWatermarks(t *testing.T) {
	s, procs := newSet([]uint64{0, 0, 0, 0})
	s.Dispatch([][]event.Event{seqEvents(1, 50, 10), seqEvents(51, 100, 10)}, 100)
	// One shard may receive no events at all; its checkpoint must still move.
	s.Dispatch(nil, 120)
	s.Close()

	total := 0
	owner := map[string]int{}
	for id, p := range procs {
		total += len(p.seqs)
		for i := 1; i < len(p.seqs); i++ {
			if p.seqs[i] <= p.seqs[i-1] {
				t.Fatalf("shard %d out of order: %v", id, p.seqs)
			}
		}
		for svc := range p.svc {
			if prev, ok := owner[svc]; ok && prev != id {
				t.Fatalf("service %s on shards %d and %d", svc, prev, id)
			}
			owner[svc] = id
		}
	}
	if total != 100 {
		t.Fatalf("processed %d, want 100", total)
	}
	cps, _ := s.Snapshot()
	for i, cp := range cps {
		if cp != 120 {
			t.Fatalf("shard %d checkpoint %d, want 120 (watermark)", i, cp)
		}
	}
}

func TestReplayOverlapIsSkippedPerShard(t *testing.T) {
	r := router.NewModulo(2)
	evs := seqEvents(1, 40, 7)
	// Shard 0 had checkpointed 30, shard 1 only 10.
	s, procs := newSet([]uint64{30, 10})
	if s.MinRestored() != 10 {
		t.Fatalf("min restored %d", s.MinRestored())
	}
	s.Dispatch([][]event.Event{seqEvents(11, 40, 7)}, 40) // replay from min+1
	s.Close()
	for _, ev := range evs {
		sh := r.Shard(ev.Service)
		restored := []uint64{30, 10}[sh]
		got := false
		for _, q := range procs[sh].seqs {
			if q == ev.Seq {
				got = true
			}
		}
		if want := ev.Seq > restored; got != want {
			t.Fatalf("seq %d on shard %d (restored %d): processed=%v want %v", ev.Seq, sh, restored, got, want)
		}
	}
	if st := s.Stats(); st["shard_events_skipped_total"] == 0 {
		t.Fatal("skips not counted")
	}
}

func TestSnapshotFlushesAfterReadingCheckpoints(t *testing.T) {
	s, procs := newSet([]uint64{0, 0})
	s.Dispatch([][]event.Event{seqEvents(1, 10, 3)}, 10)
	s.Close()
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	for _, p := range procs {
		if p.flushes != 1 {
			t.Fatalf("flushes = %d", p.flushes)
		}
	}
}

func TestProcessedLogRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenProcessedLog(dir, "run1", 0)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := OpenProcessedLog(dir, "run2", 0)
	for _, ev := range seqEvents(1, 5, 1) {
		a.Process(&ev)
	}
	ev := event.Event{Seq: 3}
	b.Process(&ev) // a replayed duplicate in a later run
	a.Close()
	b.Close()
	if _, err := OpenProcessedLog(dir, "run1", 0); err == nil {
		t.Fatal("existing processed log overwritten")
	}
	seen, err := ReadProcessedLogs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 5 || seen[3] != 2 || seen[1] != 1 {
		t.Fatalf("seen %v", seen)
	}
}

// tickingProc counts events and Advance calls without any locking: both
// must happen on the shard goroutine, which -race verifies.
type tickingProc struct {
	events, ticks int
	lastNow       int64
}

func (p *tickingProc) Process(*event.Event) { p.events++ }
func (p *tickingProc) Advance(now int64)    { p.ticks++; p.lastNow = now }
func (p *tickingProc) Flush() error         { return nil }
func (p *tickingProc) Close() error         { return nil }

func TestTickerRunsOnShardGoroutine(t *testing.T) {
	p := &tickingProc{}
	s := NewSet(router.NewModulo(1), []uint64{0}, 4, func(int) Processor { return Chain{p, Nop{}} })
	s.TickEvery = time.Millisecond
	s.Now = func() int64 { return 42 }
	s.Start()
	for i := range 20 {
		s.Dispatch([][]event.Event{seqEvents(uint64(i*5+1), uint64(i*5+5), 2)}, uint64(i*5+5))
		time.Sleep(time.Millisecond)
	}
	s.Close()
	if p.events != 100 || p.ticks == 0 || p.lastNow != 42 {
		t.Fatalf("events %d ticks %d now %d", p.events, p.ticks, p.lastNow)
	}
}
