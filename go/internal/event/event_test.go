package event

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"info": LevelInfo, "INFO": LevelInfo, "": LevelInfo, "notice": LevelInfo,
		"warn": LevelWarning, "Warning": LevelWarning,
		"error": LevelError, "FATAL": LevelError, "critical": LevelError,
		"trace": LevelDebug, "debug": LevelDebug, " debug ": LevelDebug,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseTimestamp(t *testing.T) {
	const fallback = int64(42)
	want := time.Date(2026, 1, 5, 14, 0, 0, 0, time.UTC).UnixNano()
	cases := []struct {
		raw     string
		want    int64
		wantErr bool
	}{
		{"", fallback, false},
		{"null", fallback, false},
		{`""`, fallback, false},
		{`"2026-01-05T14:00:00Z"`, want, false},
		{`"2026-01-05T14:00:00.000+00:00"`, want, false},
		{"1767621600", want, false},          // seconds
		{"1767621600000", want, false},       // milliseconds
		{"1767621600000000", want, false},    // microseconds
		{"1767621600000000000", want, false}, // nanoseconds
		{`"yesterday"`, 0, true},
		{"-1", 0, true},
		{"true", 0, true},
	}
	for _, c := range cases {
		got, err := ParseTimestamp(json.RawMessage(c.raw), fallback)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseTimestamp(%s) err = %v, wantErr %v", c.raw, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("ParseTimestamp(%s) = %d, want %d", c.raw, got, c.want)
		}
	}
}

func TestFromWire(t *testing.T) {
	w := Wire{
		Service: "auth-service",
		Level:   "warn",
		Message: "Login failed",
		Attributes: map[string]json.RawMessage{
			"user": json.RawMessage(`"alice"`), "attempts": json.RawMessage(`3`),
			"ok": json.RawMessage(`false`), "none": json.RawMessage(`null`),
		},
	}
	ev, err := FromWire(&w, 99)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Service != "auth-service" || ev.Level != LevelWarning || ev.Timestamp != 99 || ev.ReceivedAt != 99 {
		t.Fatalf("unexpected event %+v", ev)
	}
	wantAttrs := map[string]string{"user": "alice", "attempts": "3", "ok": "false", "none": ""}
	for k, v := range wantAttrs {
		if ev.Attrs[k] != v {
			t.Errorf("attr %s = %q, want %q", k, ev.Attrs[k], v)
		}
	}
}

func TestFromWireRejects(t *testing.T) {
	tooMany := map[string]json.RawMessage{}
	for i := 0; i <= MaxAttrs; i++ {
		tooMany[strings.Repeat("k", i+1)] = json.RawMessage(`1`)
	}
	cases := map[string]Wire{
		"no service":     {Message: "x"},
		"long service":   {Service: strings.Repeat("s", MaxServiceLen+1)},
		"bad timestamp":  {Service: "s", Timestamp: json.RawMessage(`"nope"`)},
		"too many attrs": {Service: "s", Attributes: tooMany},
		"empty attr key": {Service: "s", Attributes: map[string]json.RawMessage{"": json.RawMessage(`1`)}},
	}
	for name, w := range cases {
		if _, err := FromWire(&w, 0); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestTruncateKeepsUTF8Valid(t *testing.T) {
	// 'é' is two bytes; place one across the cut point.
	s := strings.Repeat("a", MaxMessageLen-1) + "é" + "tail"
	ev, err := FromWire(&Wire{Service: "s", Message: s}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(ev.Message) {
		t.Fatal("truncated message is not valid UTF-8")
	}
	if !strings.HasSuffix(ev.Message, "...") || len(ev.Message) > MaxMessageLen+3 {
		t.Fatalf("bad truncation: len=%d", len(ev.Message))
	}
	short, _ := FromWire(&Wire{Service: "s", Message: "short"}, 0)
	if short.Message != "short" {
		t.Fatalf("short message changed: %q", short.Message)
	}
}
