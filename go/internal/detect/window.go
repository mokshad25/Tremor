package detect

// Window counts the lines that arrived in (now - size, now] at each tick.
//
// The Python version keeps every line in a deque, which at 100k lines/s for
// one service is 3 million entries. Here lines are bucketed by the tick that
// first sees them: with ticks at whole seconds, a line arriving at a counts
// at tick k exactly when k-size < a <= k, i.e. for k in [ceil(a),
// ceil(a)+size-1]. So bucket b = ceil(a) holds the line, and tick k sums
// buckets [k-size+1, k]. That is the same set of lines as the deque, in
// O(size) memory per service.
type Window struct {
	size    int64
	buckets []bucket // ring indexed by b mod len
}

type bucket struct {
	b      int64 // absolute bucket (tick second); -1 = empty
	n      int
	errors int
	// For alert context: first/last WAL seq seen and error counts by template.
	minSeq, maxSeq uint64
	errTemplates   map[int]int
}

// NewWindow creates a window of size seconds.
func NewWindow(size int) *Window {
	w := &Window{size: int64(size), buckets: make([]bucket, size+1)}
	for i := range w.buckets {
		w.buckets[i].b = -1
	}
	return w
}

// ceilSec is ceil(ns / 1e9) for a unix-nanosecond time.
func ceilSec(ns int64) int64 {
	s := ns / 1e9
	if ns%1e9 > 0 {
		s++
	}
	return s
}

// Add records one line. It returns false if the line is too old to ever be
// counted again by a tick at or after now (it is then dropped).
func (w *Window) Add(arrivalNs int64, isError bool, seq uint64, templateID int, nowTick int64) bool {
	b := ceilSec(arrivalNs)
	if b <= nowTick-w.size {
		return false
	}
	slot := &w.buckets[mod(b, int64(len(w.buckets)))]
	if slot.b != b {
		*slot = bucket{b: b, minSeq: seq, maxSeq: seq, errTemplates: slot.errTemplates}
		clear(slot.errTemplates)
	}
	slot.n++
	if seq != 0 {
		slot.minSeq, slot.maxSeq = minNonZero(slot.minSeq, seq), max(slot.maxSeq, seq)
	}
	if isError {
		slot.errors++
		if slot.errTemplates == nil {
			slot.errTemplates = map[int]int{}
		}
		slot.errTemplates[templateID]++
	}
	return true
}

func minNonZero(a, b uint64) uint64 {
	if a == 0 {
		return b
	}
	return min(a, b)
}

func mod(a, m int64) int64 { return ((a % m) + m) % m }

// Counts returns (lines, errors) for the window ending at tick k.
func (w *Window) Counts(k int64) (n, errors int) {
	for i := range w.buckets {
		bk := &w.buckets[i]
		if bk.b > k-w.size && bk.b <= k {
			n += bk.n
			errors += bk.errors
		}
	}
	return n, errors
}

// Context returns the WAL seq range of lines in the window ending at k and
// the most frequent error template in it (-1 if there were no errors).
func (w *Window) Context(k int64) (first, last uint64, topErrTemplate, topErrCount int) {
	topErrTemplate = -1
	counts := map[int]int{}
	for i := range w.buckets {
		bk := &w.buckets[i]
		if bk.b <= k-w.size || bk.b > k {
			continue
		}
		if bk.minSeq != 0 {
			first, last = minNonZero(first, bk.minSeq), max(last, bk.maxSeq)
		}
		for t, c := range bk.errTemplates {
			counts[t] += c
		}
	}
	for t, c := range counts {
		if c > topErrCount || (c == topErrCount && t < topErrTemplate) {
			topErrTemplate, topErrCount = t, c
		}
	}
	return first, last, topErrTemplate, topErrCount
}
