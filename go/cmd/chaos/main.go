// Command chaos is TREMOR's crash test. It runs the real server binary under
// continuous load, kill -9s it at random moments (including during startup
// replay), optionally appends garbage to the WAL tail to imitate a torn
// write, restarts it, and repeats. At the end it starts the server once more,
// lets it recover and shut down cleanly, and checks:
//
//   - every acknowledged sequence number was processed (zero loss), and
//   - no sequence number was acknowledged twice (no seq reuse after a crash).
//
// Processing is observed through the server's test-only processed log
// (testing.processed_log_dir): each shard appends the seq of every event it
// processes, fsynced before every checkpoint.
//
// What this does NOT prove: kill -9 kills the process, not the machine. The
// OS page cache survives, so data that was write()n but never fsynced is not
// lost here. This test checks the ordering logic (ack only after the WAL has
// it, checkpoint only after processing, replay from the checkpoint, safe tail
// truncation); fsync itself protects against power loss, which needs a VM or
// a power-cut rig to test.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mokshad/tremor/internal/shard"
)

type options struct {
	server       string
	cycles       int
	workdir      string
	keep         bool
	port         int
	producers    int
	batch        int
	minUp, maxUp time.Duration
	garbageProb  float64
	earlyProb    float64
	seed         uint64
	out          string
	segmentBytes int64
	syncInterval time.Duration
	shards       int
}

func main() {
	var o options
	flag.StringVar(&o.server, "server", "bin/tremor", "path to the tremor binary")
	flag.IntVar(&o.cycles, "cycles", 50, "number of kill -9 crashes")
	flag.StringVar(&o.workdir, "workdir", "", "working directory (default: a new temp dir)")
	flag.BoolVar(&o.keep, "keep", false, "keep the working directory afterwards")
	flag.IntVar(&o.port, "port", 18080, "port for the server under test")
	flag.IntVar(&o.producers, "producers", 16, "concurrent producers")
	flag.IntVar(&o.batch, "batch", 50, "events per request")
	flag.DurationVar(&o.minUp, "min-up", 0, "minimum time from process start to kill")
	flag.DurationVar(&o.maxUp, "max-up", 3*time.Second, "maximum time from process start to kill")
	flag.Float64Var(&o.garbageProb, "garbage", 0.3, "probability of appending garbage to the WAL tail after a kill")
	flag.Float64Var(&o.earlyProb, "early", 0.2, "probability of killing within the first 50ms (during recovery/replay)")
	flag.Uint64Var(&o.seed, "seed", uint64(time.Now().UnixNano()), "RNG seed (printed, for reproducing a run)")
	flag.StringVar(&o.out, "out", "", "write the JSON report here")
	flag.Int64Var(&o.segmentBytes, "segment-bytes", 1<<20, "WAL segment size (small = more rotation and cleanup)")
	flag.DurationVar(&o.syncInterval, "sync-interval", 5*time.Millisecond, "WAL group-commit interval")
	flag.IntVar(&o.shards, "shards", 4, "shard count")
	flag.Parse()

	rep, err := run(o)
	enc, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(enc))
	if o.out != "" {
		_ = os.WriteFile(o.out, append(enc, '\n'), 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "chaos:", err)
		os.Exit(1)
	}
	if !rep.Pass {
		os.Exit(1)
	}
}

// Report is the outcome of a chaos run.
type Report struct {
	Seed               uint64   `json:"seed"`
	Cycles             int      `json:"cycles"`
	KilledBeforeReady  int      `json:"killed_before_ready"`
	GarbageInjections  int      `json:"garbage_injections"`
	TruncatedTails     int      `json:"recoveries_that_truncated_a_tail"`
	AckedRequests      int      `json:"acked_requests"`
	AckedEvents        uint64   `json:"acked_events"`
	ProcessedUnique    int      `json:"processed_unique_seqs"`
	ProcessedTotal     int      `json:"processed_total"`
	DuplicateSeqs      int      `json:"seqs_processed_more_than_once"`
	UnackedProcessed   int      `json:"processed_but_never_acked"`
	LostEvents         uint64   `json:"lost_acked_events"`
	OverlappingAcks    int      `json:"overlapping_acked_ranges"`
	MaxRecoveryMS      float64  `json:"max_recovery_ms"`
	MaxReplayedRecords int64    `json:"max_replayed_records"`
	FinalExitClean     bool     `json:"final_shutdown_clean"`
	ElapsedS           float64  `json:"elapsed_s"`
	Pass               bool     `json:"pass"`
	FirstLost          []uint64 `json:"first_lost,omitempty"`
}

type ackRange struct{ first, last uint64 }

func run(o options) (Report, error) {
	rep := Report{Seed: o.seed, Cycles: o.cycles}
	start := time.Now()
	rng := rand.New(rand.NewPCG(o.seed, 0xc4a05))

	if o.workdir == "" {
		d, err := os.MkdirTemp("", "tremor-chaos-")
		if err != nil {
			return rep, err
		}
		o.workdir = d
	}
	if !o.keep {
		defer os.RemoveAll(o.workdir)
	}
	walDir := filepath.Join(o.workdir, "wal")
	procDir := filepath.Join(o.workdir, "processed")
	cfgPath := filepath.Join(o.workdir, "config.yaml")
	logPath := filepath.Join(o.workdir, "server.log")
	cfg := fmt.Sprintf(`server:
  listen_addr: "127.0.0.1:%d"
  debug_addr: ""
  metrics_addr: ""
  shutdown_timeout: 30s
ingest:
  queue_capacity: 64
  ack_timeout: 5s
wal:
  dir: %q
  segment_bytes: %d
  sync_every_records: 5000
  sync_interval: %s
  fsync: true
checkpoint:
  interval: 200ms
shards:
  count: %d
otlp:
  http_addr: ""
  grpc_addr: ""
testing:
  processed_log_dir: %q
`, o.port, walDir, o.segmentBytes, o.syncInterval, o.shards, procDir)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return rep, err
	}
	logf, err := os.Create(logPath)
	if err != nil {
		return rep, err
	}
	defer logf.Close()

	base := fmt.Sprintf("http://127.0.0.1:%d", o.port)
	acks := &ackLog{}
	stopProducers := make(chan struct{})
	var pwg sync.WaitGroup
	for i := range o.producers {
		pwg.Go(func() { producer(base+"/ingest", i, o.batch, acks, stopProducers) })
	}

	for c := range o.cycles {
		cmd, err := startServer(o.server, cfgPath, logf)
		if err != nil {
			close(stopProducers)
			return rep, err
		}
		up := o.minUp + time.Duration(rng.Int64N(int64(o.maxUp-o.minUp)+1))
		if rng.Float64() < o.earlyProb {
			up = time.Duration(rng.Int64N(int64(50 * time.Millisecond)))
		}
		// Watch readiness concurrently so probing never delays the kill.
		var ready atomic.Bool
		stopWatch := make(chan struct{})
		var watch sync.WaitGroup
		watch.Go(func() {
			for !ready.Load() {
				select {
				case <-stopWatch:
					return
				case <-time.After(5 * time.Millisecond):
					ready.Store(healthy(base))
				}
			}
		})
		time.Sleep(up)
		_ = cmd.Process.Signal(syscall.SIGKILL)
		close(stopWatch)
		watch.Wait()
		if !ready.Load() {
			rep.KilledBeforeReady++
		}
		_ = cmd.Wait()
		if rng.Float64() < o.garbageProb {
			if err := appendGarbage(walDir, rng); err != nil {
				fmt.Fprintln(os.Stderr, "garbage:", err)
			} else {
				rep.GarbageInjections++
			}
		}
		fmt.Fprintf(os.Stderr, "cycle %2d/%d: killed after %v; acked so far %d events\n",
			c+1, o.cycles, up.Round(time.Millisecond), acks.events())
	}
	close(stopProducers)
	pwg.Wait()

	// Final run: recover, then shut down cleanly so the last checkpoint and
	// processed logs are flushed.
	cmd, err := startServer(o.server, cfgPath, logf)
	if err != nil {
		return rep, err
	}
	deadline := time.Now().Add(2 * time.Minute)
	for !healthy(base) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	rep.FinalExitClean = cmd.Wait() == nil

	seen, err := shard.ReadProcessedLogs(procDir)
	if err != nil {
		return rep, err
	}
	logf.Sync()
	recoveryStats(logPath, &rep)
	verify(acks.ranges, seen, &rep)
	rep.ElapsedS = time.Since(start).Seconds()
	rep.Pass = rep.LostEvents == 0 && rep.OverlappingAcks == 0 && rep.FinalExitClean && rep.AckedEvents > 0
	return rep, nil
}

func startServer(bin, cfg string, log io.Writer) (*exec.Cmd, error) {
	cmd := exec.Command(bin, "-config", cfg)
	cmd.Stdout, cmd.Stderr = log, log
	return cmd, cmd.Start()
}

func healthy(base string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// appendGarbage imitates a torn write: random bytes after the last record.
func appendGarbage(walDir string, rng *rand.Rand) error {
	segs, err := filepath.Glob(filepath.Join(walDir, "*.wal"))
	if err != nil || len(segs) == 0 {
		return errors.New("no segment")
	}
	slices.Sort(segs)
	f, err := os.OpenFile(segs[len(segs)-1], os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	junk := make([]byte, 1+rng.IntN(64))
	for i := range junk {
		junk[i] = byte(rng.IntN(256))
	}
	_, err = f.Write(junk)
	return err
}

type ackLog struct {
	mu     sync.Mutex
	ranges []ackRange
	n      uint64
}

func (a *ackLog) add(r ackRange) {
	a.mu.Lock()
	a.ranges = append(a.ranges, r)
	a.n += r.last - r.first + 1
	a.mu.Unlock()
}

func (a *ackLog) events() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}

func producer(url string, id, batch int, acks *ackLog, stop <-chan struct{}) {
	var sb strings.Builder
	sb.WriteString(`{"events":[`)
	for i := range batch {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"service":"svc-%02d","level":"info","message":"chaos producer %d event %d"}`, id%12, id, i)
	}
	sb.WriteString(`]}`)
	body := []byte(sb.String())
	client := &http.Client{Timeout: 10 * time.Second}
	for {
		select {
		case <-stop:
			return
		default:
		}
		resp, err := client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			time.Sleep(20 * time.Millisecond) // server is down; wait for the restart
			continue
		}
		if resp.StatusCode == http.StatusOK {
			var ok struct {
				First uint64 `json:"first_seq"`
				Last  uint64 `json:"last_seq"`
			}
			if json.NewDecoder(resp.Body).Decode(&ok) == nil && ok.First > 0 {
				acks.add(ackRange{ok.First, ok.Last})
			}
		} else {
			time.Sleep(10 * time.Millisecond) // 429/503: back off briefly
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// verify compares acknowledged ranges with processed seqs.
func verify(ranges []ackRange, seen map[uint64]int, rep *Report) {
	sorted := slices.Clone(ranges)
	slices.SortFunc(sorted, func(a, b ackRange) int {
		switch {
		case a.first < b.first:
			return -1
		case a.first > b.first:
			return 1
		}
		return 0
	})
	acked := make(map[uint64]bool)
	for i, r := range sorted {
		if i > 0 && r.first <= sorted[i-1].last {
			rep.OverlappingAcks++ // the same seq acked twice: seq reuse after a crash
		}
		for s := r.first; s <= r.last; s++ {
			acked[s] = true
			rep.AckedEvents++
			if seen[s] == 0 {
				rep.LostEvents++
				if len(rep.FirstLost) < 10 {
					rep.FirstLost = append(rep.FirstLost, s)
				}
			}
		}
	}
	rep.AckedRequests = len(ranges)
	rep.ProcessedUnique = len(seen)
	for s, n := range seen {
		rep.ProcessedTotal += n
		if n > 1 {
			rep.DuplicateSeqs++
		}
		if !acked[s] {
			rep.UnackedProcessed++
		}
	}
}

// recoveryStats scans the server's JSON log for recovery lines.
func recoveryStats(path string, rep *Report) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		var l struct {
			Msg            string `json:"msg"`
			Took           string `json:"took"`
			Replayed       int64  `json:"replayed"`
			TruncatedBytes int64  `json:"truncated_bytes"`
		}
		if json.Unmarshal(line, &l) != nil || l.Msg != "recovery complete" {
			continue
		}
		if d, err := time.ParseDuration(l.Took); err == nil {
			rep.MaxRecoveryMS = max(rep.MaxRecoveryMS, float64(d)/float64(time.Millisecond))
		}
		rep.MaxReplayedRecords = max(rep.MaxReplayedRecords, l.Replayed)
		if l.TruncatedBytes > 0 {
			rep.TruncatedTails++
		}
	}
}
