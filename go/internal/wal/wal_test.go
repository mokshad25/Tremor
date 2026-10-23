package wal

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mokshad/tremor/internal/event"
	"github.com/mokshad/tremor/internal/metrics"
	"github.com/mokshad/tremor/internal/pipeline"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func opts(dir string) Options { return Options{Dir: dir, SegmentBytes: 64 << 20, Fsync: true} }

func mustOpen(t *testing.T, o Options) (*Log, Recovery) {
	t.Helper()
	l, rec, err := Open(o, quiet)
	if err != nil {
		t.Fatal(err)
	}
	return l, rec
}

// pad makes records ~150 bytes so small segment sizes force rotation.
var pad = strings.Repeat("x", 120)

func makeEvents(n int, tag string) []event.Event {
	evs := make([]event.Event, n)
	for i := range evs {
		evs[i] = event.Event{Service: "svc-" + tag, Message: fmt.Sprintf("%s message %d %s", tag, i, pad), Timestamp: int64(i)}
	}
	return evs
}

func replayAll(t *testing.T, l *Log, from uint64) []event.Event {
	t.Helper()
	var out []event.Event
	if _, err := l.Replay(from, func(e *event.Event) error { out = append(out, *e); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func appendSync(t *testing.T, l *Log, evs []event.Event) {
	t.Helper()
	if _, _, _, err := l.Append(evs); err != nil {
		t.Fatal(err)
	}
	if err := l.Sync(); err != nil {
		t.Fatal(err)
	}
}

func TestAppendReplayReopen(t *testing.T) {
	dir := t.TempDir()
	l, _ := mustOpen(t, opts(dir))
	evs := makeEvents(100, "a")
	first, last, _, err := l.Append(evs)
	if err != nil || first != 1 || last != 100 || evs[99].Seq != 100 {
		t.Fatalf("append: %d-%d %v", first, last, err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	l, rec := mustOpen(t, opts(dir))
	defer l.Close()
	if rec.LastSeq != 100 || rec.TruncatedBytes != 0 {
		t.Fatalf("recovery %+v", rec)
	}
	got := replayAll(t, l, 1)
	if !reflect.DeepEqual(got, evs) {
		t.Fatalf("replay mismatch: got %d events", len(got))
	}
	if got := replayAll(t, l, 91); len(got) != 10 || got[0].Seq != 91 {
		t.Fatalf("partial replay from 91: %d events", len(got))
	}
	// Appends continue the sequence after reopen.
	more := makeEvents(5, "b")
	if f, _, _, _ := l.Append(more); f != 101 {
		t.Fatalf("next seq after reopen = %d", f)
	}
}

func TestRotationAndReplayAcrossSegments(t *testing.T) {
	dir := t.TempDir()
	o := opts(dir)
	o.SegmentBytes = 4096
	l, _ := mustOpen(t, o)
	var all []event.Event
	for i := range 20 {
		evs := makeEvents(10, fmt.Sprint(i))
		appendSync(t, l, evs)
		all = append(all, evs...)
	}
	if l.Segments() < 5 {
		t.Fatalf("expected rotation, got %d segments", l.Segments())
	}
	l.Close()
	l, rec := mustOpen(t, o)
	defer l.Close()
	if rec.LastSeq != 200 {
		t.Fatalf("recovery %+v", rec)
	}
	if got := replayAll(t, l, 1); !reflect.DeepEqual(got, all) {
		t.Fatal("replay across segments mismatch")
	}
}

func lastSegmentPath(t *testing.T, dir string) string {
	t.Helper()
	segs, err := listSegments(dir)
	if err != nil || len(segs) == 0 {
		t.Fatal(err)
	}
	return segs[len(segs)-1].path
}

func TestTornTailIsTruncated(t *testing.T) {
	cases := map[string]func(t *testing.T, path string){
		"garbage appended": func(t *testing.T, path string) {
			f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			f.Write([]byte("\x10\x00\x00\x00garbage-from-a-torn-write"))
			f.Close()
		},
		"last record cut in half": func(t *testing.T, path string) {
			st, _ := os.Stat(path)
			os.Truncate(path, st.Size()-7)
		},
		"checksum flipped in last record": func(t *testing.T, path string) {
			f, _ := os.OpenFile(path, os.O_RDWR, 0)
			st, _ := f.Stat()
			b := make([]byte, 1)
			f.ReadAt(b, st.Size()-1)
			b[0] ^= 0xff
			f.WriteAt(b, st.Size()-1)
			f.Close()
		},
		"huge length field": func(t *testing.T, path string) {
			f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			f.Write([]byte{0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0})
			f.Close()
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			l, _ := mustOpen(t, opts(dir))
			appendSync(t, l, makeEvents(10, "a"))
			l.Close()
			corrupt(t, lastSegmentPath(t, dir))

			l, rec := mustOpen(t, opts(dir))
			defer l.Close()
			wantLast := uint64(10)
			if name == "last record cut in half" || name == "checksum flipped in last record" {
				wantLast = 9 // the damaged record itself is dropped
			}
			if rec.LastSeq != wantLast || rec.TruncatedBytes == 0 {
				t.Fatalf("recovery %+v, want last %d with truncation", rec, wantLast)
			}
			if got := replayAll(t, l, 1); uint64(len(got)) != wantLast {
				t.Fatalf("replayed %d", len(got))
			}
			// The log keeps working, and continues the sequence.
			appendSync(t, l, makeEvents(3, "b"))
			if l.LastSeq() != wantLast+3 {
				t.Fatalf("last seq %d", l.LastSeq())
			}
			if got := replayAll(t, l, 1); uint64(len(got)) != wantLast+3 {
				t.Fatalf("replayed %d after append", len(got))
			}
		})
	}
}

func TestEmptyOrTornSegmentHeader(t *testing.T) {
	for _, content := range []string{"", "TRM"} {
		dir := t.TempDir()
		l, _ := mustOpen(t, opts(dir))
		appendSync(t, l, makeEvents(5, "a"))
		l.Close()
		// Simulate a crash right after creating the next segment file.
		os.WriteFile(filepath.Join(dir, segmentName(6)), []byte(content), 0o644)

		l, rec := mustOpen(t, opts(dir))
		if rec.LastSeq != 5 {
			t.Fatalf("content %q: recovery %+v", content, rec)
		}
		appendSync(t, l, makeEvents(2, "b"))
		if got := replayAll(t, l, 1); len(got) != 7 {
			t.Fatalf("content %q: replayed %d", content, len(got))
		}
		l.Close()
	}
}

func TestCorruptionBeforeTailFailsReplay(t *testing.T) {
	dir := t.TempDir()
	o := opts(dir)
	o.SegmentBytes = 4096
	l, _ := mustOpen(t, o)
	for range 10 {
		appendSync(t, l, makeEvents(10, "x"))
	}
	l.Close()
	segs, _ := listSegments(dir)
	f, _ := os.OpenFile(segs[0].path, os.O_RDWR, 0)
	f.WriteAt([]byte{0xde, 0xad}, 100) // inside a record of the first segment
	f.Close()

	l, _ = mustOpen(t, o) // the tail is fine, so Open succeeds
	defer l.Close()
	if _, err := l.Replay(1, func(*event.Event) error { return nil }); err == nil {
		t.Fatal("corruption in a non-tail segment must fail replay, not be skipped")
	}
}

func TestCleanupKeepsUnprocessedAndActive(t *testing.T) {
	dir := t.TempDir()
	o := opts(dir)
	o.SegmentBytes = 4096
	l, _ := mustOpen(t, o)
	defer l.Close()
	for range 10 {
		appendSync(t, l, makeEvents(10, "x"))
	}
	segs, _ := listSegments(dir)
	if len(segs) < 3 {
		t.Fatalf("need >= 3 segments, have %d", len(segs))
	}
	// Checkpoint just short of the end of segment 1: nothing can go.
	if n, _ := l.Cleanup(segs[1].first - 2); n != 0 {
		t.Fatalf("removed %d with checkpoint inside segment 0", n)
	}
	// Checkpoint exactly at the last record of segment 1: segments 0 and 1 go.
	if n, _ := l.Cleanup(segs[2].first - 1); n != 2 {
		t.Fatalf("removed %d, want 2", n)
	}
	// A checkpoint past everything still keeps the active segment.
	l.Cleanup(1 << 62)
	if l.Segments() != 1 {
		t.Fatalf("active segment removed: %d left", l.Segments())
	}
	if _, err := os.Stat(segs[len(segs)-1].path); err != nil {
		t.Fatal("active segment file missing")
	}
	// Replaying from a checkpoint older than what exists replays what exists.
	if got := replayAll(t, l, 1); len(got) == 0 || got[len(got)-1].Seq != 100 {
		t.Fatal("replay after cleanup lost the tail")
	}
}

func TestCheckpointSaveLoadRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if _, found, err := LoadCheckpoint(path); found || err != nil {
		t.Fatalf("missing file: found=%v err=%v", found, err)
	}
	if err := SaveCheckpoint(path, Checkpoint{Router: "mod/4", Shards: []uint64{10, 20, 5, 30}}); err != nil {
		t.Fatal(err)
	}
	cp, found, err := LoadCheckpoint(path)
	if err != nil || !found {
		t.Fatal(err)
	}
	if got, reset := RestoreShards(cp, found, 4, "mod/4"); reset || !reflect.DeepEqual(got, []uint64{10, 20, 5, 30}) {
		t.Fatalf("same layout: %v reset=%v", got, reset)
	}
	if got, reset := RestoreShards(cp, found, 8, "mod/8"); !reset || !reflect.DeepEqual(got, []uint64{5, 5, 5, 5, 5, 5, 5, 5}) {
		t.Fatalf("changed layout must fall back to the minimum: %v", got)
	}
	if got, _ := RestoreShards(Checkpoint{}, false, 2, "x"); !reflect.DeepEqual(got, []uint64{0, 0}) {
		t.Fatalf("no checkpoint: %v", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
	os.WriteFile(path, []byte("{not json"), 0o644)
	if _, _, err := LoadCheckpoint(path); err == nil {
		t.Fatal("corrupt checkpoint accepted")
	}
}

// recorder is a Dispatcher that remembers what it was given.
type recorder struct {
	mu         sync.Mutex
	events     []event.Event
	watermarks []uint64
}

func (r *recorder) Dispatch(groups [][]event.Event, wm uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, g := range groups {
		r.events = append(r.events, g...)
	}
	r.watermarks = append(r.watermarks, wm)
}

func startCommitter(t *testing.T, l *Log, p SyncPolicy) (*pipeline.Queue, *recorder, *metrics.WAL, func()) {
	t.Helper()
	q := pipeline.NewQueue(64)
	rec := &recorder{}
	m := &metrics.WAL{}
	c := &Committer{Log: l, Policy: p, Dispatch: rec, Metrics: m, Logger: quiet}
	done := make(chan struct{})
	go func() { c.Run(q.Batches()); close(done) }()
	return q, rec, m, func() { q.Close(); <-done }
}

func submit(t *testing.T, q *pipeline.Queue, evs []event.Event) *pipeline.Batch {
	t.Helper()
	if err := q.Acquire(); err != nil {
		t.Fatal(err)
	}
	b := pipeline.NewBatch(evs, 0)
	if err := q.Submit(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCommitterAcksOnlyDurableRecords(t *testing.T) {
	dir := t.TempDir()
	l, _ := mustOpen(t, opts(dir))
	q, rec, m, stop := startCommitter(t, l, SyncPolicy{EveryRecords: 1 << 30, Interval: 5 * time.Millisecond})

	b := submit(t, q, makeEvents(7, "a"))
	if err := <-b.Done(); err != nil {
		t.Fatal(err)
	}
	if b.FirstSeq != 1 || b.LastSeq != 7 {
		t.Fatalf("seqs %d-%d", b.FirstSeq, b.LastSeq)
	}
	// At the moment of the ack the records must already be readable by an
	// independent reader of the files (flushed out of the process).
	other, _ := mustOpen(t, Options{Dir: dir, SegmentBytes: 64 << 20})
	if got := replayAll(t, other, 1); len(got) != 7 {
		t.Fatalf("acked batch not on disk: %d records", len(got))
	}
	stop()
	l.Close()
	if m.Syncs.Load() < 1 || len(rec.events) != 7 || rec.watermarks[len(rec.watermarks)-1] != 7 {
		t.Fatalf("dispatch %d events, watermarks %v", len(rec.events), rec.watermarks)
	}
}

func TestCommitterGroupsBySize(t *testing.T) {
	l, _ := mustOpen(t, opts(t.TempDir()))
	defer l.Close()
	// Interval is huge, so only the record count can trigger a sync.
	q, _, m, stop := startCommitter(t, l, SyncPolicy{EveryRecords: 30, Interval: time.Hour})
	var bs []*pipeline.Batch
	for range 3 {
		bs = append(bs, submit(t, q, makeEvents(10, "a")))
	}
	for _, b := range bs {
		select {
		case err := <-b.Done():
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("size-triggered sync never happened")
		}
	}
	if m.Syncs.Load() != 1 {
		t.Fatalf("syncs = %d, want one group commit for 3 batches", m.Syncs.Load())
	}
	stop()
}

func TestCommitterFinalSyncOnClose(t *testing.T) {
	l, _ := mustOpen(t, opts(t.TempDir()))
	defer l.Close()
	q, rec, _, stop := startCommitter(t, l, SyncPolicy{EveryRecords: 1 << 30, Interval: time.Hour})
	b := submit(t, q, makeEvents(4, "a"))
	stop() // close before any trigger fires: shutdown must still commit
	if err := <-b.Done(); err != nil || len(rec.events) != 4 {
		t.Fatalf("err=%v dispatched=%d", err, len(rec.events))
	}
}

func TestSyncFailureIsStickyAndRejects(t *testing.T) {
	l, _ := mustOpen(t, opts(t.TempDir()))
	q, rec, m, stop := startCommitter(t, l, SyncPolicy{EveryRecords: 1, Interval: time.Hour})
	l.f.Close() // make the next flush/fsync fail
	b := submit(t, q, makeEvents(10_000, "a"))
	if err := <-b.Done(); !errors.Is(err, ErrFailed) {
		t.Fatalf("ack err = %v, want ErrFailed", err)
	}
	b2 := submit(t, q, makeEvents(1, "b"))
	if err := <-b2.Done(); !errors.Is(err, ErrFailed) {
		t.Fatalf("log accepted work after failing: %v", err)
	}
	stop()
	if len(rec.events) != 0 || m.SyncErrors.Load() == 0 && m.RecordsAppended.Load() != 0 {
		t.Fatalf("failed records were dispatched: %d", len(rec.events))
	}
}

// TestPipelinedCommitAcrossRotations drives many small groups through tiny
// segments so rotations constantly race with in-flight fsyncs on the syncer
// goroutine. Every ack must be durable, in order, and contiguous.
func TestPipelinedCommitAcrossRotations(t *testing.T) {
	dir := t.TempDir()
	o := opts(dir)
	o.SegmentBytes = 4096
	l, _ := mustOpen(t, o)
	q, rec, m, stop := startCommitter(t, l, SyncPolicy{EveryRecords: 3, Interval: time.Millisecond})

	var wg sync.WaitGroup
	var mu sync.Mutex
	var acked [][2]uint64
	for p := range 8 {
		wg.Go(func() {
			for i := range 40 {
				for q.Acquire() != nil { // queue full: wait like a producer would
					time.Sleep(time.Millisecond)
				}
				b := pipeline.NewBatch(makeEvents(1+i%4, fmt.Sprint(p)), 0)
				if err := q.Submit(b); err != nil {
					t.Error(err)
					return
				}
				if err := <-b.Done(); err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				acked = append(acked, [2]uint64{b.FirstSeq, b.LastSeq})
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	stop()
	l.Close()

	if l.Segments() < 10 || m.Syncs.Load() < 10 {
		t.Fatalf("not enough rotation/sync pressure: %d segments, %d syncs", l.Segments(), m.Syncs.Load())
	}
	// Dispatch saw every event exactly once, in seq order.
	for i, ev := range rec.events {
		if ev.Seq != uint64(i+1) {
			t.Fatalf("dispatch position %d has seq %d", i, ev.Seq)
		}
	}
	for i := 1; i < len(rec.watermarks); i++ {
		if rec.watermarks[i] <= rec.watermarks[i-1] {
			t.Fatal("watermarks not increasing")
		}
	}
	// Everything acked is on disk after reopening.
	l2, recov := mustOpen(t, o)
	defer l2.Close()
	got := replayAll(t, l2, 1)
	if uint64(len(got)) != recov.LastSeq || len(got) != len(rec.events) {
		t.Fatalf("replayed %d, last seq %d, dispatched %d", len(got), recov.LastSeq, len(rec.events))
	}
	for _, a := range acked {
		if a[1] > recov.LastSeq {
			t.Fatalf("acked seq %d not on disk (last %d)", a[1], recov.LastSeq)
		}
	}
}

func TestFsyncOfRotatedSegmentIsSatisfied(t *testing.T) {
	o := opts(t.TempDir())
	o.SegmentBytes = 4096
	l, _ := mustOpen(t, o)
	defer l.Close()
	l.Append(makeEvents(5, "a"))
	target, err := l.Flush()
	if err != nil {
		t.Fatal(err)
	}
	l.Append(makeEvents(50, "b")) // forces rotation: the old file is synced and closed
	if l.Segments() < 2 {
		t.Fatal("expected a rotation")
	}
	if err := l.FsyncFile(target); err != nil {
		t.Fatalf("fsync of a rotated-out segment must be a no-op, got %v", err)
	}
	if l.Err() != nil {
		t.Fatal("log entered failed state")
	}
}
