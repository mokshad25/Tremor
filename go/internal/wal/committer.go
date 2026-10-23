package wal

import (
	"log/slog"
	"time"

	"github.com/mokshad/tremor/internal/event"
	"github.com/mokshad/tremor/internal/metrics"
	"github.com/mokshad/tremor/internal/pipeline"
)

// SyncPolicy is the group-commit trigger: a group is closed once
// EveryRecords records are pending, or Interval after its first record,
// whichever comes first. Larger values mean fewer fsyncs (more throughput)
// and a longer wait before producers are acked (more latency). Neither
// setting can lose an acknowledged event: acks are only sent after the fsync.
type SyncPolicy struct {
	EveryRecords int
	Interval     time.Duration
}

// Dispatcher receives durable events, in sequence order. groups holds one
// slice per batch; watermark is the highest seq in this dispatch, and every
// event up to it is included. Dispatch may block (shard backpressure).
type Dispatcher interface {
	Dispatch(groups [][]event.Event, watermark uint64)
}

// maxGroupsInFlight bounds closed groups waiting for (or in) fsync. Beyond
// it the committer blocks, the ingest queue fills, and the gateway sheds load.
const maxGroupsInFlight = 4

// Committer owns the Log while serving. It is a two-stage pipeline:
//
//	committer goroutine: append batches -> close a group -> flush to the OS
//	syncer goroutine:    fsync the group -> ack its producers -> dispatch
//
// While one group is being fsynced, the next one keeps filling, so a slow
// fsync (F_FULLFSYNC tail latency reaches tens of milliseconds) produces a
// bigger next group instead of stalling intake. Groups are synced, acked and
// dispatched strictly in order by the single syncer.
type Committer struct {
	Log      *Log
	Policy   SyncPolicy
	Dispatch Dispatcher
	Metrics  *metrics.WAL
	Hist     *metrics.Histograms // optional: write/fsync latency for Prometheus
	Logger   *slog.Logger
}

type group struct {
	batches []*pipeline.Batch
	target  SyncTarget
	err     error // Flush failed: reject without syncing
}

// Run consumes in until it is closed, then syncs the final group, waits
// for the syncer to finish, and returns.
func (c *Committer) Run(in <-chan *pipeline.Batch) {
	groups := make(chan group, maxGroupsInFlight)
	syncerDone := make(chan struct{})
	go func() { c.syncer(groups); close(syncerDone) }()

	var (
		pending []*pipeline.Batch
		records int
		timer   = time.NewTimer(time.Hour)
		armed   bool
	)
	timer.Stop()

	closeGroup := func() {
		if armed {
			timer.Stop()
			armed = false
		}
		if len(pending) == 0 {
			return
		}
		t0 := time.Now()
		target, err := c.Log.Flush()
		c.Hist.ObserveWALWrite(time.Since(t0).Seconds())
		groups <- group{batches: pending, target: target, err: err}
		pending, records = nil, 0 // the syncer owns the old slice now
	}

	for {
		var tick <-chan time.Time
		if armed {
			tick = timer.C
		}
		select {
		case b, ok := <-in:
			if !ok {
				closeGroup()
				close(groups)
				<-syncerDone
				return
			}
			first, last, n, err := c.Log.Append(b.Events)
			if err != nil {
				b.Ack(err)
				continue
			}
			c.Metrics.RecordsAppended.Add(int64(len(b.Events)))
			c.Metrics.BytesAppended.Add(int64(n))
			b.FirstSeq, b.LastSeq = first, last
			pending = append(pending, b)
			records += len(b.Events)
			if records >= c.Policy.EveryRecords {
				closeGroup()
			} else if !armed {
				timer.Reset(c.Policy.Interval)
				armed = true
			}
		case <-tick:
			armed = false
			closeGroup()
		}
	}
}

// syncer makes each group durable, then acks and dispatches it.
func (c *Committer) syncer(groups <-chan group) {
	for g := range groups {
		err := g.err
		if err == nil {
			start := time.Now()
			err = c.Log.FsyncFile(g.target)
			took := time.Since(start).Nanoseconds()
			c.Metrics.Syncs.Add(1)
			c.Metrics.SyncNanos.Add(took)
			metrics.ObserveMax(&c.Metrics.SyncMaxNanos, took)
			c.Hist.ObserveWALFsync(float64(took) / 1e9)
		}
		if err != nil {
			// The records may or may not be on disk. Tell producers they were
			// not accepted (they will retry); anything that did reach disk is
			// replayed after restart, so the worst case is a duplicate.
			c.Metrics.SyncErrors.Add(1)
			c.Logger.Error("wal: sync failed; rejecting batches", "batches", len(g.batches), "err", err)
			for _, b := range g.batches {
				b.Ack(err)
			}
			continue
		}
		events := make([][]event.Event, len(g.batches))
		for i, b := range g.batches {
			b.Ack(nil) // durable: the producer may now forget this batch
			events[i] = b.Events
		}
		c.Dispatch.Dispatch(events, g.batches[len(g.batches)-1].LastSeq)
	}
}
