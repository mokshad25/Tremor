package ingest

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/mokshad/tremor/internal/event"
)

// Routes returns the HTTP handler for the native API: POST /ingest,
// GET /healthz and GET /readyz.
func (g *Gateway) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest", g.ingest)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if g.draining.Load() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "draining"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	return mux
}

// acceptedBody is the 200 response. first_seq..last_seq is the contiguous
// WAL range the batch was written to; it is durable when this is sent.
type acceptedBody struct {
	Accepted int    `json:"accepted"`
	FirstSeq uint64 `json:"first_seq"`
	LastSeq  uint64 `json:"last_seq"`
}

type errorBody struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
	Index  *int   `json:"index,omitempty"` // offending event, for invalid_event
}

func (g *Gateway) ingest(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/json" {
			g.m.Requests.Add(1)
			g.m.RejectedBad.Add(1)
			writeJSON(w, http.StatusUnsupportedMediaType, errorBody{Error: "unsupported_media_type", Detail: "use application/json"})
			return
		}
	}
	// Admission control happens BEFORE the body is read: an overloaded
	// gateway sheds load for the cost of parsing headers, not bodies.
	if rej := g.admit(); rej != nil {
		g.reject(w, rej)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.opt.MaxBodyBytes))
	if err != nil {
		g.release()
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: "body_too_large", Detail: "limit " + strconv.FormatInt(g.opt.MaxBodyBytes, 10) + " bytes"})
			return
		}
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "read_failed", Detail: err.Error()})
		return
	}
	var wb event.WireBatch
	if err := json.Unmarshal(body, &wb); err != nil {
		g.release()
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_json", Detail: err.Error()})
		return
	}
	switch n := len(wb.Events); {
	case n == 0:
		g.release()
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "empty_batch"})
		return
	case n > g.opt.MaxEventsPerBatch:
		g.release()
		writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: "too_many_events", Detail: "limit " + strconv.Itoa(g.opt.MaxEventsPerBatch)})
		return
	}
	// All-or-nothing: one invalid event rejects the batch, so a producer's
	// retry never has to work out which half was already accepted.
	received := g.now().UnixNano()
	events := make([]event.Event, len(wb.Events))
	for i := range wb.Events {
		ev, err := event.FromWire(&wb.Events[i], received)
		if err != nil {
			g.release()
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_event", Detail: err.Error(), Index: &i})
			return
		}
		events[i] = ev
	}
	batch, err := g.commit(r.Context(), events, len(body))
	if err != nil {
		var rej *Rejection
		if errors.As(err, &rej) {
			g.reject(w, rej)
		}
		return // context cancelled: the producer is gone
	}
	writeJSON(w, http.StatusOK, acceptedBody{Accepted: len(events), FirstSeq: batch.FirstSeq, LastSeq: batch.LastSeq})
}

// reject writes 429 (overload) or 503 with Retry-After.
func (g *Gateway) reject(w http.ResponseWriter, rej *Rejection) {
	w.Header().Set("Retry-After", g.retryAfter)
	status := http.StatusServiceUnavailable
	if rej.Overload {
		status = http.StatusTooManyRequests
	}
	writeJSON(w, status, errorBody{Error: rej.Reason})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
