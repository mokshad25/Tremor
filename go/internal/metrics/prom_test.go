package metrics

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestRegistryExposesFamiliesAndHistograms(t *testing.T) {
	h := NewHistograms()
	h.ObserveWALFsync(0.003)
	var nilH *Histograms
	nilH.ObserveLLM(1) // must not panic
	reg := NewRegistry(h, []Family{
		{Name: "tremor_events_accepted_total", Help: "x", Counter: true, Read: func() []Sample { return One(42) }},
		{Name: "tremor_shard_queue_depth", Help: "y", LabelNames: []string{"shard"}, Read: func() []Sample {
			return []Sample{{Labels: []string{"0"}, Value: 3}, {Labels: []string{"1"}, Value: 0}}
		}},
	})
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	for _, want := range []string{
		"tremor_events_accepted_total 42",
		`tremor_shard_queue_depth{shard="0"} 3`,
		"tremor_wal_fsync_seconds_count 1",
		"go_goroutines",
		"process_resident_memory_bytes",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q", want)
		}
	}
}
