package ingest

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mokshad/tremor/internal/event"
	"github.com/mokshad/tremor/internal/metrics"
	"github.com/mokshad/tremor/internal/pipeline"
)

var testOpts = Options{MaxBodyBytes: 4096, MaxEventsPerBatch: 10, RetryAfter: 2 * time.Second, AckTimeout: time.Second}

type fixture struct {
	h       *Gateway
	q       *pipeline.Queue
	m       *metrics.Gateway
	handler http.Handler
}

// newFixture builds a gateway. If consume is true a worker acks every batch
// and records its events in got.
func newFixture(t *testing.T, capacity int, opt Options, consume bool) (*fixture, *[]event.Event) {
	t.Helper()
	q := pipeline.NewQueue(capacity)
	m := &metrics.Gateway{}
	h := NewGateway(q, m, opt, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.now = func() time.Time { return time.Unix(1000, 0) }
	got := &[]event.Event{}
	if consume {
		var next uint64 = 1
		wait := pipeline.Run(q, 1, func(b *pipeline.Batch) error {
			*got = append(*got, b.Events...)
			b.FirstSeq, b.LastSeq = next, next+uint64(len(b.Events))-1 // stand-in for the WAL
			next = b.LastSeq + 1
			return nil
		})
		t.Cleanup(func() { q.Close(); wait() })
	}
	return &fixture{h: h, q: q, m: m, handler: h.Routes()}, got
}

func post(handler http.Handler, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ingest", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response not JSON: %q", rec.Body.String())
	}
	return m
}

const goodBatch = `{"events":[
 {"service":"auth-service","timestamp":"2026-01-05T14:00:00Z","level":"warn","message":"Login failed","attributes":{"attempts":3}},
 {"service":"ledger","message":"Balance check"}]}`

func TestIngestAcceptsAndAcksAfterConsume(t *testing.T) {
	f, got := newFixture(t, 4, testOpts, true)
	rec := post(f.handler, strings.NewReader(goodBatch))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if body := decode(t, rec); body["accepted"] != float64(2) || body["first_seq"] != float64(1) || body["last_seq"] != float64(2) {
		t.Fatalf("body %s", rec.Body)
	}
	// The 200 is only written after the consumer acked, so the events are
	// already visible here without any synchronisation tricks.
	if len(*got) != 2 || (*got)[0].Level != event.LevelWarning || (*got)[0].Attrs["attempts"] != "3" {
		t.Fatalf("consumed %+v", *got)
	}
	if (*got)[1].Timestamp != time.Unix(1000, 0).UnixNano() {
		t.Fatal("missing timestamp should default to receive time")
	}
	if f.m.EventsAccepted.Load() != 2 || f.m.RequestsAccepted.Load() != 1 || f.q.InFlight() != 0 {
		t.Fatalf("metrics %v inflight %d", f.m.Snapshot(), f.q.InFlight())
	}
}

// countingReader records whether the handler touched the body.
type countingReader struct {
	r     io.Reader
	reads atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) { c.reads.Add(1); return c.r.Read(p) }

func TestQueueFullReturns429WithoutReadingBody(t *testing.T) {
	f, _ := newFixture(t, 1, testOpts, false)
	if err := f.q.Acquire(); err != nil { // occupy the only slot
		t.Fatal(err)
	}
	body := &countingReader{r: strings.NewReader(goodBatch)}
	rec := post(f.handler, body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	if decode(t, rec)["error"] != "queue_full" {
		t.Fatalf("body %s", rec.Body)
	}
	if body.reads.Load() != 0 {
		t.Fatal("body was read for a rejected request")
	}
	if f.m.Rejected429.Load() != 1 {
		t.Fatal("429 not counted")
	}
}

func TestBadRequestsReleaseSlot(t *testing.T) {
	f, _ := newFixture(t, 1, testOpts, false)
	cases := []struct {
		name, body string
		status     int
		errCode    string
	}{
		{"invalid json", `{"events":[`, 400, "invalid_json"},
		{"empty batch", `{"events":[]}`, 400, "empty_batch"},
		{"invalid event", `{"events":[{"service":"a"},{"message":"no service"}]}`, 400, "invalid_event"},
		{"too many events", `{"events":[` + strings.Repeat(`{"service":"a"},`, 10) + `{"service":"a"}]}`, 413, "too_many_events"},
		{"body too large", `{"events":[{"service":"a","message":"` + strings.Repeat("x", 5000) + `"}]}`, 413, "body_too_large"},
	}
	for _, c := range cases {
		rec := post(f.handler, strings.NewReader(c.body))
		if rec.Code != c.status {
			t.Errorf("%s: status %d, want %d (%s)", c.name, rec.Code, c.status, rec.Body)
			continue
		}
		body := decode(t, rec)
		if body["error"] != c.errCode {
			t.Errorf("%s: error %v, want %s", c.name, body["error"], c.errCode)
		}
		if c.errCode == "invalid_event" && body["index"] != float64(1) {
			t.Errorf("invalid_event index = %v, want 1", body["index"])
		}
		// With capacity 1, a leaked slot would turn the next case into a 429.
		if f.q.InFlight() != 0 {
			t.Fatalf("%s: leaked admission slot", c.name)
		}
	}
	if f.m.RejectedBad.Load() != int64(len(cases)) {
		t.Fatalf("bad count = %d", f.m.RejectedBad.Load())
	}
}

func TestWrongContentType(t *testing.T) {
	f, _ := newFixture(t, 1, testOpts, false)
	req := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(goodBatch))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestAckTimeoutReturns503AndKeepsSlot(t *testing.T) {
	opt := testOpts
	opt.AckTimeout = 20 * time.Millisecond
	f, _ := newFixture(t, 2, opt, false) // no consumer: nothing ever acks
	rec := post(f.handler, strings.NewReader(goodBatch))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status %d headers %v", rec.Code, rec.Header())
	}
	if decode(t, rec)["error"] != "ack_timeout" {
		t.Fatalf("body %s", rec.Body)
	}
	// The batch is still queued and may yet be processed, so its slot must
	// stay reserved until it is acked: that is what keeps memory bounded.
	if f.q.InFlight() != 1 || f.q.Depth() != 1 {
		t.Fatalf("inflight %d depth %d", f.q.InFlight(), f.q.Depth())
	}
}

func TestDrainingRejectsWith503(t *testing.T) {
	f, _ := newFixture(t, 4, testOpts, true)
	f.h.SetDraining()
	rec := post(f.handler, strings.NewReader(goodBatch))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("status %d", rec.Code)
	}
	ready := httptest.NewRecorder()
	f.handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz %d while draining", ready.Code)
	}
	health := httptest.NewRecorder()
	f.handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("healthz %d", health.Code)
	}
}

func TestClosedQueueReturns503(t *testing.T) {
	f, _ := newFixture(t, 4, testOpts, false)
	f.q.Close()
	if rec := post(f.handler, strings.NewReader(goodBatch)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	f, _ := newFixture(t, 1, testOpts, false)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ingest", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestFailedAckReturns503(t *testing.T) {
	q := pipeline.NewQueue(2)
	m := &metrics.Gateway{}
	h := NewGateway(q, m, testOpts, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	wait := pipeline.Run(q, 1, func(*pipeline.Batch) error { return errors.New("disk on fire") })
	defer func() { q.Close(); wait() }()
	rec := post(h.Routes(), strings.NewReader(goodBatch))
	if rec.Code != http.StatusServiceUnavailable || decode(t, rec)["error"] != "wal_unavailable" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if m.EventsAccepted.Load() != 0 {
		t.Fatal("failed batch counted as accepted")
	}
}
