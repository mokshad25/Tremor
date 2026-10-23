package shard

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/mokshad/tremor/internal/event"
)

// ProcessedLog is a test-only Processor that appends the sequence number of
// every event it processes to a file (8 bytes, little endian). cmd/chaos
// reads these files to prove that every acknowledged event was processed.
//
// Because Flush (fsync) runs before each checkpoint is saved, the set of
// seqs in these files always covers everything a checkpoint claims.
type ProcessedLog struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer
	b  [8]byte
}

// OpenProcessedLog creates processed-<run>-<shard>.seq in dir. run should be
// unique per process start (e.g. the PID plus a timestamp) so restarts never
// overwrite each other's files.
func OpenProcessedLog(dir, run string, shard int) (*ProcessedLog, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, fmt.Sprintf("processed-%s-%03d.seq", run, shard))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &ProcessedLog{f: f, w: bufio.NewWriterSize(f, 64<<10)}, nil
}

func (p *ProcessedLog) Process(ev *event.Event) {
	p.mu.Lock()
	binary.LittleEndian.PutUint64(p.b[:], ev.Seq)
	p.w.Write(p.b[:]) // errors surface on Flush
	p.mu.Unlock()
}

func (p *ProcessedLog) Flush() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.w.Flush(); err != nil {
		return err
	}
	return p.f.Sync()
}

func (p *ProcessedLog) Close() error {
	err := p.Flush()
	if cerr := p.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// ReadProcessedLogs returns every seq recorded in dir's processed-*.seq
// files, with how many times each was seen. A trailing partial record (a
// write cut short by kill -9) is ignored.
func ReadProcessedLogs(dir string) (map[uint64]int, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "processed-*.seq"))
	if err != nil {
		return nil, err
	}
	seen := map[uint64]int{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		for i := 0; i+8 <= len(data); i += 8 {
			seen[binary.LittleEndian.Uint64(data[i:])]++
		}
	}
	return seen, nil
}
