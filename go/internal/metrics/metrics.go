// Package metrics holds TREMOR's counters.
//
// Until Phase 6 they are exposed with the standard library's expvar
// (/debug/vars) so there are zero metrics dependencies. Phase 6 replaces the
// exporter with Prometheus client_golang; the counter names stay the same.
package metrics

import (
	"expvar"
	"sync"
	"sync/atomic"
)

// Gateway counts what happens to ingest requests and events. The zero value
// is ready to use, and tests can create as many as they like; only Publish
// touches global state.
type Gateway struct {
	Requests         atomic.Int64 // every POST /ingest
	RequestsAccepted atomic.Int64 // 200
	Rejected429      atomic.Int64 // queue full
	Rejected503      atomic.Int64 // draining, closed, WAL failure or ack timeout
	RejectedBad      atomic.Int64 // 400 / 413 / 415
	EventsAccepted   atomic.Int64 // events in batches that were acked OK
}

// Snapshot returns the counters as a plain map.
func (g *Gateway) Snapshot() map[string]int64 {
	return map[string]int64{
		"requests_total":          g.Requests.Load(),
		"requests_accepted_total": g.RequestsAccepted.Load(),
		"requests_429_total":      g.Rejected429.Load(),
		"requests_503_total":      g.Rejected503.Load(),
		"requests_bad_total":      g.RejectedBad.Load(),
		"events_accepted_total":   g.EventsAccepted.Load(),
	}
}

// WAL counts write-ahead log activity.
type WAL struct {
	RecordsAppended  atomic.Int64
	BytesAppended    atomic.Int64
	Syncs            atomic.Int64 // group commits (one fsync each)
	SyncNanos        atomic.Int64 // total time spent in Sync
	SyncMaxNanos     atomic.Int64 // slowest Sync since start
	SyncErrors       atomic.Int64
	RecordsReplayed  atomic.Int64
	SegmentsRemoved  atomic.Int64
	CheckpointsSaved atomic.Int64
}

func (w *WAL) Snapshot() map[string]int64 {
	return map[string]int64{
		"wal_records_appended_total": w.RecordsAppended.Load(),
		"wal_bytes_appended_total":   w.BytesAppended.Load(),
		"wal_syncs_total":            w.Syncs.Load(),
		"wal_sync_nanos_total":       w.SyncNanos.Load(),
		"wal_sync_max_nanos":         w.SyncMaxNanos.Load(),
		"wal_sync_errors_total":      w.SyncErrors.Load(),
		"wal_records_replayed_total": w.RecordsReplayed.Load(),
		"wal_segments_removed_total": w.SegmentsRemoved.Load(),
		"checkpoints_saved_total":    w.CheckpointsSaved.Load(),
	}
}

// ObserveMax raises m to v if v is larger.
func ObserveMax(m *atomic.Int64, v int64) {
	for {
		cur := m.Load()
		if v <= cur || m.CompareAndSwap(cur, v) {
			return
		}
	}
}

// Source produces a set of named values when metrics are read.
type Source func() map[string]int64

// Publish registers the merged sources under the expvar name "tremor". Call
// it once per process.
func Publish(sources ...Source) {
	expvar.Publish("tremor", expvar.Func(func() any {
		out := map[string]int64{}
		for _, src := range sources {
			for k, v := range src() {
				out[k] = v
			}
		}
		return out
	}))
}

// Detect counts alert notifications by signal type and severity.
type Detect struct {
	mu    sync.Mutex
	pairs map[[2]string]int64 // (type, severity or "RESOLVED") -> count

	ErrorRate, Silence, NewPattern, Latency                        atomic.Int64
	BruteForce, CredentialStuffing, PrivilegeChange, UnusualAccess atomic.Int64
	Info, Warning, High, Critical                                  atomic.Int64
	Resolved                                                       atomic.Int64
}

func (d *Detect) Snapshot() map[string]int64 {
	return map[string]int64{
		"alerts_error_rate_total":          d.ErrorRate.Load(),
		"alerts_silence_total":             d.Silence.Load(),
		"alerts_new_pattern_total":         d.NewPattern.Load(),
		"alerts_latency_total":             d.Latency.Load(),
		"alerts_brute_force_total":         d.BruteForce.Load(),
		"alerts_credential_stuffing_total": d.CredentialStuffing.Load(),
		"alerts_privilege_change_total":    d.PrivilegeChange.Load(),
		"alerts_unusual_access_total":      d.UnusualAccess.Load(),
		"alerts_info_total":                d.Info.Load(),
		"alerts_warning_total":             d.Warning.Load(),
		"alerts_high_total":                d.High.Load(),
		"alerts_critical_total":            d.Critical.Load(),
		"alerts_resolved_total":            d.Resolved.Load(),
	}
}

// Count records one notification of type t with severity sev ("RESOLVED"
// for resolutions).
func (d *Detect) Count(t, sev string) {
	d.mu.Lock()
	if d.pairs == nil {
		d.pairs = map[[2]string]int64{}
	}
	d.pairs[[2]string{t, sev}]++
	d.mu.Unlock()
}

// Pairs returns a copy of the (type, severity) counts.
func (d *Detect) Pairs() map[[2]string]int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[[2]string]int64, len(d.pairs))
	for k, v := range d.pairs {
		out[k] = v
	}
	return out
}
