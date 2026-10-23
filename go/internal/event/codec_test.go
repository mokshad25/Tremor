package event

import (
	"bytes"
	"reflect"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	cases := []Event{
		{},
		{Service: "auth-service", Timestamp: 1767621600000000000, ReceivedAt: 1767621600123456789,
			Level: LevelError, Message: "Login failed user=<EMAIL> ünïcode",
			Attrs: map[string]string{"host": "a-1", "attempts": "3", "": ""}},
		{Service: "s", Timestamp: -5, Message: "negative time is still representable"},
	}
	for _, in := range cases {
		buf := AppendBinary(nil, &in)
		var out Event
		if err := DecodeBinary(buf, &out); err != nil {
			t.Fatalf("decode %+v: %v", in, err)
		}
		if len(in.Attrs) == 0 {
			in.Attrs = nil
		}
		if !reflect.DeepEqual(in, out) {
			t.Fatalf("round trip\n in  %+v\n out %+v", in, out)
		}
	}
}

func TestCodecDeterministic(t *testing.T) {
	e := Event{Service: "s", Attrs: map[string]string{"b": "2", "a": "1", "c": "3", "d": "4"}}
	first := AppendBinary(nil, &e)
	for range 50 { // map iteration order is random; output must not be
		if !bytes.Equal(first, AppendBinary(nil, &e)) {
			t.Fatal("encoding depends on map order")
		}
	}
}

func TestDecodeRejectsTruncatedAndTrailing(t *testing.T) {
	e := Event{Service: "svc", Message: "hello", Attrs: map[string]string{"k": "v"}}
	buf := AppendBinary(nil, &e)
	for i := range len(buf) {
		var out Event
		if err := DecodeBinary(buf[:i], &out); err == nil {
			t.Fatalf("truncated at %d decoded without error", i)
		}
	}
	var out Event
	if err := DecodeBinary(append(buf, 0), &out); err == nil {
		t.Fatal("trailing byte accepted")
	}
}

func FuzzDecodeBinary(f *testing.F) {
	e := Event{Service: "svc", Message: "m", Attrs: map[string]string{"k": "v"}}
	f.Add(AppendBinary(nil, &e))
	f.Add([]byte{1, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		var out Event
		if DecodeBinary(data, &out) != nil {
			return
		}
		// Anything that decodes must re-encode to something that decodes
		// to the same event.
		var again Event
		if err := DecodeBinary(AppendBinary(nil, &out), &again); err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if !reflect.DeepEqual(out, again) {
			t.Fatalf("unstable: %+v vs %+v", out, again)
		}
	})
}
