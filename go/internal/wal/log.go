package wal

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/mokshad/tremor/internal/event"
)

const (
	segmentMagic  = "TRMWAL01"
	segmentSuffix = ".wal"
	writeBufSize  = 1 << 20
)

// Options configures a Log.
type Options struct {
	Dir          string
	SegmentBytes int64 // rotate when the active segment would exceed this
	// Fsync controls whether Sync calls fsync. Turning it off is only for
	// measuring what durability costs: acks then mean "in the page cache".
	Fsync bool
}

// Recovery describes what Open found on disk.
type Recovery struct {
	Segments       int
	FirstSeq       uint64 // first record still on disk (0 if none)
	LastSeq        uint64 // last valid record (0 if none)
	TruncatedBytes int64  // bytes cut from the tail of the last segment
	TruncateReason string
}

type segment struct {
	first uint64 // seq of the first record in the file (= the file name)
	path  string
}

// Log is a segmented write-ahead log. Append, Flush, Sync and Close must be
// called from a single goroutine (the committer). FsyncFile may run
// concurrently from one other goroutine (the syncer), and Cleanup from
// another. Replay must finish before the first Append.
type Log struct {
	opts Options
	log  *slog.Logger

	mu   sync.Mutex // guards segs against concurrent Cleanup
	segs []segment

	f       *os.File
	gen     uint64 // generation of f, from 1; bumped (under syncMu) on rotation
	w       *bufio.Writer
	size    int64 // bytes in the active segment, including buffered
	nextSeq uint64
	lastSeq atomic.Uint64 // last appended seq, for metrics and watermarks
	scratch []byte

	// syncMu serialises fsyncs with rotation, which fsyncs and closes the
	// old file. closedGen is the newest generation already fsynced and
	// closed by a rotation: an fsync request for it is already satisfied.
	syncMu    sync.Mutex
	closedGen uint64

	failed atomic.Pointer[error] // sticky: once a write or fsync fails, the log is unusable
}

// ErrFailed wraps the first I/O error after which the log refuses all work.
// After a failed fsync the kernel may have dropped dirty pages, so retrying
// can "succeed" without the data being on disk (PostgreSQL's fsyncgate). The
// only safe response is to stop and recover from what is known to be durable.
var ErrFailed = errors.New("wal: log failed")

// Open opens (or creates) the log in opts.Dir, validates the tail of the last
// segment, and truncates it at the first torn or corrupt record.
func Open(opts Options, logger *slog.Logger) (*Log, Recovery, error) {
	if opts.SegmentBytes < 4096 {
		return nil, Recovery{}, errors.New("wal: segment size must be at least 4 KiB")
	}
	if err := os.MkdirAll(opts.Dir, 0o755); err != nil {
		return nil, Recovery{}, err
	}
	l := &Log{opts: opts, log: logger, gen: 1} // closedGen 0 = nothing closed yet
	segs, err := listSegments(opts.Dir)
	if err != nil {
		return nil, Recovery{}, err
	}
	l.segs = segs

	var rec Recovery
	if len(segs) == 0 {
		if err := l.createSegment(1); err != nil {
			return nil, rec, err
		}
		l.nextSeq = 1
		rec.Segments = 1
		return l, rec, nil
	}

	last := segs[len(segs)-1]
	end, lastSeq, reason, err := scanTail(last)
	if err != nil {
		return nil, rec, err
	}
	f, err := os.OpenFile(last.path, os.O_RDWR, 0)
	if err != nil {
		return nil, rec, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, rec, err
	}
	if end < int64(len(segmentMagic)) || st.Size() > end {
		rec.TruncatedBytes = st.Size() - end
		rec.TruncateReason = reason
		if end < int64(len(segmentMagic)) {
			// Crash while creating the segment: rewrite the header.
			if err := f.Truncate(0); err != nil {
				f.Close()
				return nil, rec, err
			}
			if _, err := f.WriteAt([]byte(segmentMagic), 0); err != nil {
				f.Close()
				return nil, rec, err
			}
			rec.TruncatedBytes = st.Size()
			end = int64(len(segmentMagic))
		} else if err := f.Truncate(end); err != nil {
			f.Close()
			return nil, rec, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, rec, err
		}
		logger.Warn("wal: truncated torn tail", "segment", filepath.Base(last.path),
			"bytes", rec.TruncatedBytes, "reason", reason)
	}
	if _, err := f.Seek(end, io.SeekStart); err != nil {
		f.Close()
		return nil, rec, err
	}
	l.f = f
	l.w = bufio.NewWriterSize(f, writeBufSize)
	l.size = end
	if lastSeq == 0 { // empty last segment
		l.nextSeq = last.first
	} else {
		l.nextSeq = lastSeq + 1
	}
	l.lastSeq.Store(l.nextSeq - 1)

	rec.Segments = len(segs)
	rec.FirstSeq = segs[0].first
	rec.LastSeq = l.nextSeq - 1
	if rec.LastSeq < rec.FirstSeq {
		rec.FirstSeq = 0
	}
	return l, rec, nil
}

func segmentName(first uint64) string { return fmt.Sprintf("%020d%s", first, segmentSuffix) }

func listSegments(dir string) ([]segment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var segs []segment
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, segmentSuffix) {
			continue
		}
		first, err := strconv.ParseUint(strings.TrimSuffix(name, segmentSuffix), 10, 64)
		if err != nil || first == 0 {
			return nil, fmt.Errorf("wal: unexpected file %q in %s", name, dir)
		}
		segs = append(segs, segment{first: first, path: filepath.Join(dir, name)})
	}
	slices.SortFunc(segs, func(a, b segment) int { return int64Cmp(a.first, b.first) })
	return segs, nil
}

func int64Cmp(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// scanTail walks the last segment and returns the offset just past the last
// valid record whose seq continues the sequence, plus that seq.
func scanTail(s segment) (end int64, lastSeq uint64, reason string, err error) {
	f, err := os.Open(s.path)
	if err != nil {
		return 0, 0, "", err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, writeBufSize)
	magic := make([]byte, len(segmentMagic))
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != segmentMagic {
		return 0, 0, "segment header missing or torn", nil
	}
	end = int64(len(segmentMagic))
	want := s.first // a segment's records start at the seq in its name
	var scratch []byte
	for {
		seq, _, n, buf, err := readRecord(r, scratch)
		scratch = buf
		if err == io.EOF {
			return end, lastSeq, "", nil
		}
		if err != nil {
			return end, lastSeq, "torn or corrupt record", nil
		}
		if seq != want {
			return end, lastSeq, fmt.Sprintf("sequence gap: want %d got %d", want, seq), nil
		}
		end += int64(n)
		lastSeq = seq
		want++
	}
}

// createSegment creates a new segment file starting at first, makes its
// directory entry durable, and makes it the active segment.
func (l *Log) createSegment(first uint64) error {
	path := filepath.Join(l.opts.Dir, segmentName(first))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte(segmentMagic)); err != nil {
		f.Close()
		return err
	}
	if l.opts.Fsync {
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err := syncDir(l.opts.Dir); err != nil {
			f.Close()
			return err
		}
	}
	l.f = f
	if l.w == nil {
		l.w = bufio.NewWriterSize(f, writeBufSize)
	} else {
		l.w.Reset(f)
	}
	l.size = int64(len(segmentMagic))
	l.mu.Lock()
	if n := len(l.segs); n == 0 || l.segs[n-1].first != first {
		l.segs = append(l.segs, segment{first: first, path: path})
	}
	l.mu.Unlock()
	return nil
}

// rotate makes the active segment durable and starts a new one at first.
func (l *Log) rotate(first uint64) error {
	if err := l.w.Flush(); err != nil {
		return err
	}
	l.syncMu.Lock()
	err := l.fsync(l.f)
	if err == nil {
		err = l.f.Close()
		l.closedGen = l.gen
		l.gen++
	}
	l.syncMu.Unlock()
	if err != nil {
		return err
	}
	return l.createSegment(first)
}

// Append writes events to the log, assigning consecutive sequence numbers
// (stored into events[i].Seq). The records are buffered: they are not
// durable, and must not be acknowledged, until Sync returns nil.
func (l *Log) Append(events []event.Event) (first, last uint64, bytes int, err error) {
	if err := l.Err(); err != nil {
		return 0, 0, 0, err
	}
	first = l.nextSeq
	for i := range events {
		seq := l.nextSeq
		events[i].Seq = seq
		l.scratch = appendRecord(l.scratch[:0], seq, func(b []byte) []byte {
			return event.AppendBinary(b, &events[i])
		})
		if l.size+int64(len(l.scratch)) > l.opts.SegmentBytes && l.size > int64(len(segmentMagic)) {
			if err := l.rotate(seq); err != nil {
				return 0, 0, bytes, l.fail(err)
			}
		}
		if _, err := l.w.Write(l.scratch); err != nil {
			return 0, 0, bytes, l.fail(err)
		}
		l.size += int64(len(l.scratch))
		bytes += len(l.scratch)
		l.nextSeq++
	}
	last = l.nextSeq - 1
	l.lastSeq.Store(last)
	return first, last, bytes, nil
}

// SyncTarget identifies what an fsync must cover: the active segment as of
// a Flush. Earlier segments were fsynced when they were rotated out.
type SyncTarget struct {
	f   *os.File
	gen uint64
}

// Flush writes buffered records to the OS (not yet durable) and returns the
// target that FsyncFile must sync to make them durable.
func (l *Log) Flush() (SyncTarget, error) {
	if err := l.Err(); err != nil {
		return SyncTarget{}, err
	}
	if err := l.w.Flush(); err != nil {
		return SyncTarget{}, l.fail(err)
	}
	return SyncTarget{f: l.f, gen: l.gen}, nil
}

// FsyncFile makes everything flushed to t durable. It may run on another
// goroutine while the committer keeps appending: fsync covers every write
// the file has received so far, which includes everything up to the Flush
// that produced t.
func (l *Log) FsyncFile(t SyncTarget) error {
	if err := l.Err(); err != nil {
		return err
	}
	l.syncMu.Lock()
	defer l.syncMu.Unlock()
	if t.gen <= l.closedGen {
		return nil // rotation already fsynced and closed this segment
	}
	if err := l.fsync(t.f); err != nil {
		return l.fail(err)
	}
	return nil
}

func (l *Log) fsync(f *os.File) error {
	if !l.opts.Fsync {
		return nil
	}
	return f.Sync() // on macOS this is F_FULLFSYNC: through the drive's cache
}

// Sync is Flush followed by FsyncFile, for single-goroutine callers.
func (l *Log) Sync() error {
	t, err := l.Flush()
	if err != nil {
		return err
	}
	return l.FsyncFile(t)
}

// Err returns the sticky failure, if any.
func (l *Log) Err() error {
	if p := l.failed.Load(); p != nil {
		return *p
	}
	return nil
}

func (l *Log) fail(err error) error {
	wrapped := fmt.Errorf("%w: %v", ErrFailed, err)
	if l.failed.CompareAndSwap(nil, &wrapped) {
		l.log.Error("wal: entering failed state", "err", err)
	}
	return l.Err()
}

// LastSeq is the last appended sequence number (0 if none). Safe for
// concurrent use.
func (l *Log) LastSeq() uint64 { return l.lastSeq.Load() }

// Segments returns the number of segment files.
func (l *Log) Segments() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.segs)
}

// Replay calls fn for every record with seq >= from, in order. It must run
// before the first Append. Corruption anywhere except the (already
// truncated) tail is an error: a hole in the middle of the log means
// acknowledged data is gone, and silently skipping it would hide that.
func (l *Log) Replay(from uint64, fn func(*event.Event) error) (n int, err error) {
	l.mu.Lock()
	segs := slices.Clone(l.segs)
	l.mu.Unlock()
	if from == 0 {
		from = 1
	}
	if len(segs) > 0 && from < segs[0].first {
		l.log.Warn("wal: replay start is older than the oldest segment; replaying what exists",
			"from", from, "oldest", segs[0].first)
		from = segs[0].first
	}
	start := 0
	for i, s := range segs {
		if s.first <= from {
			start = i
		}
	}
	if l.w != nil {
		if err := l.w.Flush(); err != nil {
			return 0, err
		}
	}
	var scratch []byte
	want := uint64(0)
	for _, s := range segs[start:] {
		f, err := os.Open(s.path)
		if err != nil {
			return n, err
		}
		r := bufio.NewReaderSize(f, writeBufSize)
		magic := make([]byte, len(segmentMagic))
		if _, err := io.ReadFull(r, magic); err != nil || string(magic) != segmentMagic {
			f.Close()
			return n, fmt.Errorf("wal: segment %s: bad header", filepath.Base(s.path))
		}
		if want != 0 && s.first != want {
			f.Close()
			return n, fmt.Errorf("wal: segment %s starts at %d, want %d", filepath.Base(s.path), s.first, want)
		}
		want = s.first
		for {
			seq, payload, _, buf, err := readRecord(r, scratch)
			scratch = buf
			if err == io.EOF {
				break
			}
			if err != nil || seq != want {
				f.Close()
				return n, fmt.Errorf("wal: segment %s: corrupt record at seq %d", filepath.Base(s.path), want)
			}
			want++
			if seq < from {
				continue
			}
			var ev event.Event
			if err := event.DecodeBinary(payload, &ev); err != nil {
				f.Close()
				return n, fmt.Errorf("wal: seq %d: %w", seq, err)
			}
			ev.Seq = seq
			if err := fn(&ev); err != nil {
				f.Close()
				return n, err
			}
			n++
		}
		f.Close()
	}
	return n, nil
}

// Cleanup deletes segments whose every record has seq <= upTo. The active
// segment is never deleted. Pass the minimum *persisted* checkpoint, so a
// crash can never leave a checkpoint pointing before the oldest segment.
func (l *Log) Cleanup(upTo uint64) (removed int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for removed < len(l.segs)-1 && l.segs[removed+1].first-1 <= upTo {
		if err := os.Remove(l.segs[removed].path); err != nil && !errors.Is(err, os.ErrNotExist) {
			break
		}
		removed++
	}
	l.segs = l.segs[removed:]
	if removed > 0 && l.opts.Fsync {
		err = syncDir(l.opts.Dir)
	}
	return removed, err
}

// Close flushes, syncs and closes the active segment.
func (l *Log) Close() error {
	if l.f == nil {
		return nil
	}
	err := l.Sync()
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

// syncDir fsyncs a directory so that file creations, renames and deletions
// in it survive a power loss.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
