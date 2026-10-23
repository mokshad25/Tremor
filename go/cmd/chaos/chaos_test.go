package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyDetectsLossOverlapAndDuplicates(t *testing.T) {
	ranges := []ackRange{{1, 5}, {6, 10}, {9, 12}} // 9-10 acked twice
	seen := map[uint64]int{1: 1, 2: 2, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 9: 1, 10: 1, 11: 1, 12: 1, 99: 1}
	var rep Report
	verify(ranges, seen, &rep)
	if rep.LostEvents != 1 || rep.FirstLost[0] != 8 {
		t.Fatalf("lost %d %v, want seq 8", rep.LostEvents, rep.FirstLost)
	}
	if rep.OverlappingAcks != 1 || rep.DuplicateSeqs != 1 || rep.UnackedProcessed != 1 {
		t.Fatalf("%+v", rep)
	}
}

func TestVerifyClean(t *testing.T) {
	var rep Report
	verify([]ackRange{{3, 4}, {1, 2}}, map[uint64]int{1: 1, 2: 1, 3: 1, 4: 1}, &rep)
	if rep.LostEvents != 0 || rep.OverlappingAcks != 0 || rep.AckedEvents != 4 {
		t.Fatalf("%+v", rep)
	}
}

// TestChaosSmoke builds the real server and runs a few crash cycles. The
// full 50-cycle run is bench/chaos.sh.
func TestChaosSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and kills a real server")
	}
	bin := filepath.Join(t.TempDir(), "tremor")
	if out, err := exec.Command("go", "build", "-o", bin, "../tremor").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	rep, err := run(options{
		server: bin, cycles: 3, workdir: t.TempDir(), keep: true, port: 18181,
		producers: 4, batch: 20, minUp: time.Second, maxUp: 1500 * time.Millisecond,
		garbageProb: 1, seed: 1, segmentBytes: 64 << 10, syncInterval: 2 * time.Millisecond, shards: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Pass {
		t.Fatalf("chaos failed: %+v", rep)
	}
	// A kill before the first startup created the WAL has no tail to damage.
	if rep.GarbageInjections == 0 || rep.TruncatedTails == 0 {
		t.Fatalf("garbage was not exercised: %+v", rep)
	}
	_ = os.Remove(bin)
}
