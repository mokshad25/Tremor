// Package pipeline holds the bounded hand-off between the gateway and the
// processing stages.
//
// Backpressure model: a Queue has a fixed number of admission slots. A
// producer must Acquire a slot before it reads a request body; the slot is
// held while the batch is decoded, queued and processed, and released only
// when the batch is acked. Because the channel capacity equals the slot count,
// Submit can never block, and the number of batches in memory anywhere
// between "body read" and "acked" is bounded by the slot count.
package pipeline

import (
	"errors"
	"sync"

	"github.com/mokshad/tremor/internal/event"
)

var (
	// ErrFull means every admission slot is taken. Callers should shed load
	// (HTTP 429) rather than wait.
	ErrFull = errors.New("pipeline: queue full")
	// ErrClosed means the queue is shutting down and accepts no new work.
	ErrClosed = errors.New("pipeline: closed")
)

// Batch is a group of events submitted together by one producer request.
// Its producer is acknowledged exactly once, via Ack.
type Batch struct {
	Events []event.Event
	Bytes  int // size of the request body the batch was decoded from

	// FirstSeq and LastSeq are the WAL sequence numbers assigned to
	// Events[0] and Events[len-1]. Set by the WAL before Ack; 0 before that.
	FirstSeq, LastSeq uint64

	done chan error
	once sync.Once
	q    *Queue
}

// NewBatch wraps events for submission.
func NewBatch(events []event.Event, bytes int) *Batch {
	return &Batch{Events: events, Bytes: bytes, done: make(chan error, 1)}
}

// Done returns a channel that receives the batch's outcome exactly once.
func (b *Batch) Done() <-chan error { return b.done }

// Ack records the batch outcome (nil = success) and frees its admission slot.
// It never blocks, even if the producer stopped waiting, and extra calls are
// no-ops.
func (b *Batch) Ack(err error) {
	b.once.Do(func() {
		b.done <- err // buffered, cap 1: never blocks
		if b.q != nil {
			b.q.Release()
		}
	})
}

// Queue is a bounded, non-blocking batch queue with admission control.
type Queue struct {
	slots chan struct{}
	ch    chan *Batch

	mu     sync.RWMutex // guards closed and the send on ch against Close
	closed bool
}

// NewQueue returns a queue that admits at most capacity batches at once.
func NewQueue(capacity int) *Queue {
	if capacity < 1 {
		capacity = 1
	}
	return &Queue{
		slots: make(chan struct{}, capacity),
		ch:    make(chan *Batch, capacity),
	}
}

// Acquire reserves an admission slot without blocking. On success the caller
// must either Submit a batch (whose Ack releases the slot) or call Release.
func (q *Queue) Acquire() error {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		return ErrClosed
	}
	select {
	case q.slots <- struct{}{}:
		return nil
	default:
		return ErrFull
	}
}

// Release frees a slot obtained with Acquire that will not be submitted.
func (q *Queue) Release() { <-q.slots }

// Submit enqueues b using a slot already obtained with Acquire. It never
// blocks. On error the caller still owns the slot and must Release it.
func (q *Queue) Submit(b *Batch) error {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		return ErrClosed
	}
	b.q = q
	select {
	case q.ch <- b:
		return nil
	default:
		// Unreachable while every caller holds a slot: len(ch) <= slots in use.
		b.q = nil
		return ErrFull
	}
}

// Close stops admission and closes the batch channel so consumers drain what
// is already queued and then exit. It is safe to call more than once.
func (q *Queue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		close(q.ch)
	}
}

// Batches is the consumer side. It is closed after Close once drained.
func (q *Queue) Batches() <-chan *Batch { return q.ch }

// Depth is the number of batches waiting for a consumer.
func (q *Queue) Depth() int { return len(q.ch) }

// InFlight is the number of admission slots in use (decoding, queued or
// being processed).
func (q *Queue) InFlight() int { return len(q.slots) }

// Capacity is the maximum number of admitted batches.
func (q *Queue) Capacity() int { return cap(q.slots) }
