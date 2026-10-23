package metrics

import (
	"encoding/json"
	"expvar"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPublishMergesSources(t *testing.T) {
	var g Gateway
	var w WAL
	g.Requests.Add(3)
	g.Rejected429.Add(2)
	w.Syncs.Add(5)
	Publish(g.Snapshot, w.Snapshot, func() map[string]int64 { return map[string]int64{"queue_depth": 7} })

	var got map[string]int64
	if err := json.Unmarshal([]byte(expvar.Get("tremor").String()), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"requests_total": 3, "requests_429_total": 2, "wal_syncs_total": 5, "queue_depth": 7}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
}

func TestObserveMaxConcurrent(t *testing.T) {
	var m atomic.Int64
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Go(func() { ObserveMax(&m, int64(i)) })
	}
	wg.Wait()
	if m.Load() != 99 {
		t.Fatalf("max = %d", m.Load())
	}
}
