// Package ingest implements TREMOR's producer-facing receivers: HTTP JSON
// (POST /ingest), OTLP/HTTP (POST /v1/logs, protobuf or JSON) and
// OTLP/gRPC (LogsService/Export). All three share one path:
//
//	admit (non-blocking slot) -> decode -> redact PII -> submit to the WAL
//	queue -> wait for the fsync ack
//
// so backpressure, redaction-before-disk and the ack semantics are the same
// whichever protocol a producer uses.
package ingest

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/mokshad/tremor/internal/event"
	"github.com/mokshad/tremor/internal/metrics"
	"github.com/mokshad/tremor/internal/pipeline"
)

// Options are the gateway limits (from config.Ingest).
type Options struct {
	MaxBodyBytes      int64
	MaxEventsPerBatch int
	RetryAfter        time.Duration
	AckTimeout        time.Duration
}

// Redactor removes PII from a batch in place before it is queued for the
// WAL (internal/redact implements it). nil disables redaction, which is
// only for measuring its cost.
type Redactor interface {
	Events([]event.Event)
}

// Gateway is the shared core of every receiver.
type Gateway struct {
	q        *pipeline.Queue
	m        *metrics.Gateway
	opt      Options
	red      Redactor
	log      *slog.Logger
	now      func() time.Time
	draining atomic.Bool

	retryAfter     string // Retry-After header value (whole seconds)
	retryAfterSecs int
}

// NewGateway returns a gateway that feeds q.
func NewGateway(q *pipeline.Queue, m *metrics.Gateway, opt Options, red Redactor, log *slog.Logger) *Gateway {
	secs := max(int(math.Ceil(opt.RetryAfter.Seconds())), 1)
	return &Gateway{q: q, m: m, opt: opt, red: red, log: log, now: time.Now,
		retryAfter: strconv.Itoa(secs), retryAfterSecs: secs}
}

// SetDraining makes every receiver refuse new batches (503 / UNAVAILABLE)
// and report not-ready, so producers move away before shutdown.
func (g *Gateway) SetDraining() { g.draining.Store(true) }

// Rejection is why a batch was not accepted. Overload rejections (queue
// full) are the normal backpressure signal; the others mean "not now".
// Both are retryable: the producer keeps the batch and tries again.
type Rejection struct {
	Reason   string // machine-readable, e.g. "queue_full"
	Overload bool   // true: HTTP 429; false: HTTP 503
}

func (r *Rejection) Error() string { return r.Reason }

var (
	errQueueFull    = &Rejection{Reason: "queue_full", Overload: true}
	errDraining     = &Rejection{Reason: "draining"}
	errShuttingDown = &Rejection{Reason: "shutting_down"}
	errAckTimeout   = &Rejection{Reason: "ack_timeout"}
	errWAL          = &Rejection{Reason: "wal_unavailable"}
)

// admit reserves an admission slot without blocking, before the request
// body is read or decoded. On success the caller must call commit (which
// always consumes the slot) or release.
func (g *Gateway) admit() *Rejection {
	g.m.Requests.Add(1)
	if g.draining.Load() {
		g.m.Rejected503.Add(1)
		return errDraining
	}
	switch err := g.q.Acquire(); {
	case errors.Is(err, pipeline.ErrFull):
		g.m.Rejected429.Add(1)
		return errQueueFull
	case err != nil:
		g.m.Rejected503.Add(1)
		return errShuttingDown
	}
	return nil
}

// release frees an admitted slot that will not be committed (bad input).
func (g *Gateway) release() {
	g.q.Release()
	g.m.RejectedBad.Add(1)
}

// commit redacts events, queues them for the WAL and waits until they are
// fsynced. It consumes the admitted slot in every case. A nil error means
// the batch is durable.
func (g *Gateway) commit(ctx context.Context, events []event.Event, bytes int) (*pipeline.Batch, error) {
	// PII is removed here, before the batch can reach the WAL: nothing
	// downstream (disk, metrics, logs, the LLM) ever sees raw values.
	if g.red != nil {
		g.red.Events(events)
	}
	batch := pipeline.NewBatch(events, bytes)
	if err := g.q.Submit(batch); err != nil {
		g.q.Release()
		g.m.Rejected503.Add(1)
		return nil, errShuttingDown
	}
	timer := time.NewTimer(g.opt.AckTimeout)
	defer timer.Stop()
	select {
	case err := <-batch.Done():
		if err != nil {
			g.log.Error("batch not made durable", "events", len(events), "err", err)
			g.m.Rejected503.Add(1)
			return nil, errWAL
		}
		g.m.RequestsAccepted.Add(1)
		g.m.EventsAccepted.Add(int64(len(events)))
		return batch, nil
	case <-timer.C:
		// Not acked in time. The batch may still be processed later, so a
		// retry can create a duplicate: that is the at-least-once contract.
		// The slot stays held until the batch is acked, keeping memory bounded.
		g.m.Rejected503.Add(1)
		return nil, errAckTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
