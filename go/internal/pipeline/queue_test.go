package pipeline

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mokshad/tremor/internal/event"
)

func batchOf(n int) *Batch { return NewBatch(make([]event.Event, n), n) }

func TestAcquireRejectsWhenFull(t *testing.T) {
	q := NewQueue(2)
	for i := range 2 {
		if err := q.Acquire(); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	if err := q.Acquire(); !errors.Is(err, ErrFull) {
		t.Fatalf("third acquire = %v, want ErrFull", err)
	}
	q.Release()
	if err := q.Acquire(); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
}

func TestAckReleasesSlotExactlyOnce(t *testing.T) {
	q := NewQueue(1)
	if err := q.Acquire(); err != nil {
		t.Fatal(err)
	}
	b := batchOf(1)
	if err := q.Submit(b); err != nil {
		t.Fatal(err)
	}
	got := <-q.Batches()
	got.Ack(nil)
	got.Ack(errors.New("ignored")) // second ack must not release again or block
	if err := <-b.Done(); err != nil {
		t.Fatalf("done = %v", err)
	}
	if q.InFlight() != 0 {
		t.Fatalf("in flight = %d after ack", q.InFlight())
	}
}

func TestSubmitAfterCloseFailsWithoutPanic(t *testing.T) {
	q := NewQueue(4)
	if err := q.Acquire(); err != nil {
		t.Fatal(err)
	}
	q.Close()
	q.Close() // idempotent
	if err := q.Submit(batchOf(1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("submit after close = %v", err)
	}
	if err := q.Acquire(); !errors.Is(err, ErrClosed) {
		t.Fatalf("acquire after close = %v", err)
	}
}

func TestRunDrainsEverythingOnClose(t *testing.T) {
	const n = 64
	q := NewQueue(n)
	var processed atomic.Int64
	gate := make(chan struct{})
	wait := Run(q, 4, func(b *Batch) error {
		<-gate // hold workers so batches pile up in the queue
		processed.Add(int64(len(b.Events)))
		return nil
	})
	batches := make([]*Batch, n)
	for i := range batches {
		if err := q.Acquire(); err != nil {
			t.Fatal(err)
		}
		batches[i] = batchOf(1)
		if err := q.Submit(batches[i]); err != nil {
			t.Fatal(err)
		}
	}
	q.Close() // close while work is still queued
	close(gate)
	wait()
	if processed.Load() != n {
		t.Fatalf("processed %d of %d", processed.Load(), n)
	}
	for i, b := range batches {
		select {
		case err := <-b.Done():
			if err != nil {
				t.Fatalf("batch %d err %v", i, err)
			}
		default:
			t.Fatalf("batch %d never acked", i)
		}
	}
}

// TestConcurrentProducersNeverExceedCapacity hammers Acquire/Submit from many
// goroutines while Close races with them. Run with -race.
func TestConcurrentProducersNeverExceedCapacity(t *testing.T) {
	const capacity = 8
	q := NewQueue(capacity)
	var maxSeen atomic.Int64
	wait := Run(q, 2, func(*Batch) error {
		if v := int64(q.InFlight()); v > maxSeen.Load() {
			maxSeen.Store(v)
		}
		time.Sleep(50 * time.Microsecond)
		return nil
	})

	var accepted, rejected, acked atomic.Int64
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 200 {
				if err := q.Acquire(); err != nil {
					rejected.Add(1)
					continue
				}
				b := batchOf(1)
				if err := q.Submit(b); err != nil {
					q.Release()
					rejected.Add(1)
					continue
				}
				accepted.Add(1)
				if <-b.Done() == nil {
					acked.Add(1)
				}
			}
		})
	}
	time.AfterFunc(5*time.Millisecond, q.Close)
	wg.Wait()
	q.Close()
	wait()

	if maxSeen.Load() > capacity {
		t.Fatalf("in-flight reached %d > capacity %d", maxSeen.Load(), capacity)
	}
	if accepted.Load() != acked.Load() {
		t.Fatalf("accepted %d but acked %d", accepted.Load(), acked.Load())
	}
	if accepted.Load()+rejected.Load() != 32*200 {
		t.Fatalf("lost requests: %d + %d", accepted.Load(), rejected.Load())
	}
	if q.InFlight() != 0 {
		t.Fatalf("leaked %d slots", q.InFlight())
	}
}
