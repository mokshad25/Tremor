// Package event defines TREMOR's internal log event and the conversion from
// the HTTP wire format into it.
//
// Normalisation rules deliberately match the Python TREMOR parser
// (app/ingest/parser.py) so detection results stay comparable across the two
// implementations.
package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits applied to every event. They bound per-event memory so that the
// gateway's byte budget (queue capacity x max body size) actually holds.
const (
	MaxServiceLen  = 128
	MaxMessageLen  = 2048 // bytes; longer messages are truncated + "..."
	MaxAttrs       = 64
	MaxAttrKeyLen  = 128
	MaxAttrValLen  = 2048
	truncateSuffix = "..."
)

// Level is a normalised severity. The zero value is LevelInfo so that an
// event with no level behaves like the Python parser's default.
type Level uint8

const (
	LevelInfo Level = iota
	LevelDebug
	LevelWarning
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelWarning:
		return "WARNING"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// ParseLevel maps free-form level strings onto the four TREMOR levels.
// WARN->WARNING, FATAL/CRITICAL->ERROR, TRACE->DEBUG, anything unknown->INFO.
func ParseLevel(s string) Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG", "TRACE":
		return LevelDebug
	case "WARN", "WARNING":
		return LevelWarning
	case "ERROR", "ERR", "FATAL", "CRITICAL", "CRIT", "PANIC":
		return LevelError
	default:
		return LevelInfo
	}
}

// Event is the unit that flows through every pipeline stage.
type Event struct {
	Seq        uint64 // assigned by the WAL (Phase 2); 0 before that
	Service    string // shard key
	Timestamp  int64  // producer event time, unix nanoseconds
	ReceivedAt int64  // gateway receive time, unix nanoseconds
	Level      Level
	Message    string
	Attrs      map[string]string // nil when the producer sent none
}

// Wire is one event as producers send it to POST /ingest.
type Wire struct {
	Service    string                     `json:"service"`
	Timestamp  json.RawMessage            `json:"timestamp,omitempty"`
	Level      string                     `json:"level,omitempty"`
	Message    string                     `json:"message"`
	Attributes map[string]json.RawMessage `json:"attributes,omitempty"`
}

// WireBatch is the POST /ingest request body.
type WireBatch struct {
	Events []Wire `json:"events"`
}

// FromWire validates w and converts it into an Event. receivedAt (unix nanos)
// is used as the timestamp when the producer did not send one.
func FromWire(w *Wire, receivedAt int64) (Event, error) {
	if w.Service == "" {
		return Event{}, errors.New("service is required")
	}
	if len(w.Service) > MaxServiceLen {
		return Event{}, fmt.Errorf("service longer than %d bytes", MaxServiceLen)
	}
	ts, err := ParseTimestamp(w.Timestamp, receivedAt)
	if err != nil {
		return Event{}, err
	}
	if len(w.Attributes) > MaxAttrs {
		return Event{}, fmt.Errorf("more than %d attributes", MaxAttrs)
	}
	var attrs map[string]string
	if len(w.Attributes) > 0 {
		attrs = make(map[string]string, len(w.Attributes))
		for k, raw := range w.Attributes {
			if k == "" || len(k) > MaxAttrKeyLen {
				return Event{}, fmt.Errorf("attribute key must be 1-%d bytes", MaxAttrKeyLen)
			}
			attrs[k] = truncate(attrValue(raw), MaxAttrValLen)
		}
	}
	return Event{
		Service:    w.Service,
		Timestamp:  ts,
		ReceivedAt: receivedAt,
		Level:      ParseLevel(w.Level),
		Message:    truncate(w.Message, MaxMessageLen),
		Attrs:      attrs,
	}, nil
}

// attrValue flattens a JSON attribute value to a string: strings are
// unquoted, everything else (numbers, bools, objects) keeps its JSON text.
// Producers send numbers and bools all the time and rejecting them would be
// hostile; the detection stages only ever compare strings.
func attrValue(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
	}
	if bytes.Equal(raw, []byte("null")) {
		return ""
	}
	return string(raw)
}

// ParseTimestamp accepts an RFC 3339 string or a unix number. Numbers are
// interpreted by magnitude: >=1e17 nanoseconds, >=1e14 microseconds, >2e9
// milliseconds (the Python parser's rule), otherwise seconds. A missing or
// null timestamp falls back to the gateway receive time.
func ParseTimestamp(raw json.RawMessage, fallback int64) (int64, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return fallback, nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, fmt.Errorf("timestamp: %w", err)
		}
		if s == "" {
			return fallback, nil
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return 0, fmt.Errorf("timestamp %q is not RFC 3339", s)
		}
		return t.UnixNano(), nil
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, fmt.Errorf("timestamp must be an RFC 3339 string or a unix number")
	}
	if f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("timestamp %v out of range", f)
	}
	switch {
	case f >= 1e17:
		return int64(f), nil
	case f >= 1e14:
		return int64(f * 1e3), nil
	case f > 2e9:
		return int64(f * 1e6), nil
	default:
		return int64(f * 1e9), nil
	}
}

// truncate cuts s to at most max bytes (plus the suffix) without splitting a
// UTF-8 sequence.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncateSuffix
}

// Clamp applies the same size limits as FromWire to an event built by
// another receiver (OTLP): service, message and attribute values are
// truncated, and attributes beyond MaxAttrs are dropped (in key order, so
// the result is deterministic). It returns how many attributes it dropped.
func Clamp(e *Event) (dropped int) {
	e.Service = truncate(e.Service, MaxServiceLen)
	e.Message = truncate(e.Message, MaxMessageLen)
	if len(e.Attrs) > MaxAttrs {
		keys := make([]string, 0, len(e.Attrs))
		for k := range e.Attrs {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys[MaxAttrs:] {
			delete(e.Attrs, k)
			dropped++
		}
	}
	for k, v := range e.Attrs {
		if len(k) > MaxAttrKeyLen {
			delete(e.Attrs, k)
			dropped++
			continue
		}
		e.Attrs[k] = truncate(v, MaxAttrValLen)
	}
	return dropped
}
