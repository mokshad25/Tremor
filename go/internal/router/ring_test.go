package router

import (
	"fmt"
	"testing"
)

func services(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("svc-%05d", i)
	}
	return out
}

func TestRingDeterministic(t *testing.T) {
	a, b := NewRing(8, DefaultVNodes), NewRing(8, DefaultVNodes)
	for _, s := range services(1000) {
		if a.Shard(s) != b.Shard(s) {
			t.Fatal("two identical rings disagree")
		}
	}
	if a.ID() != "ring-fnv1a-splitmix/8x512" {
		t.Fatalf("ID %s", a.ID())
	}
}

func TestRingBalance(t *testing.T) {
	const n, svcs = 8, 80_000
	r := NewRing(n, DefaultVNodes)
	counts := make([]int, n)
	for _, s := range services(svcs) {
		counts[r.Shard(s)]++
	}
	want := svcs / n
	for i, c := range counts {
		// Every shard within 15% of a fair share (measured: about ±11% at 512 vnodes).
		if c < want*85/100 || c > want*115/100 {
			t.Fatalf("shard %d has %d services (want ~%d): %v", i, c, want, counts)
		}
	}
	// One point per shard is much worse; this is why vnodes exist.
	single := NewRing(n, 1)
	spread := make([]int, n)
	for _, s := range services(svcs) {
		spread[single.Shard(s)]++
	}
	lo, hi := spread[0], spread[0]
	for _, c := range spread {
		lo, hi = min(lo, c), max(hi, c)
	}
	if hi < 2*lo {
		t.Logf("note: single-point ring happened to balance well: %v", spread)
	}
}

func TestRingMovesFewServicesWhenAShardIsAdded(t *testing.T) {
	const svcs = 50_000
	before, after := NewRing(8, DefaultVNodes), NewRing(9, DefaultVNodes)
	moved, movedNotToNew := 0, 0
	for _, s := range services(svcs) {
		a, b := before.Shard(s), after.Shard(s)
		if a != b {
			moved++
			if b != 8 {
				movedNotToNew++ // consistent hashing: services only move TO the new shard
			}
		}
	}
	frac := float64(moved) / svcs
	if frac > 0.16 { // ideal is 1/9 = 11.1%
		t.Fatalf("%.1f%% of services moved; want about 11%%", frac*100)
	}
	if movedNotToNew != 0 {
		t.Fatalf("%d services moved between existing shards", movedNotToNew)
	}
	// Compare with hash mod N, which reshuffles almost everything.
	modMoved := 0
	m8, m9 := NewModulo(8), NewModulo(9)
	for _, s := range services(svcs) {
		if m8.Shard(s) != m9.Shard(s) {
			modMoved++
		}
	}
	t.Logf("8->9 shards: ring moved %.1f%%, mod-N moved %.1f%%", frac*100, float64(modMoved)/svcs*100)
	if modMoved < moved*4 {
		t.Fatal("expected mod-N to move far more services than the ring")
	}
}

func TestRingSingleShard(t *testing.T) {
	r := NewRing(0, 0) // clamps to 1 x 1
	if r.Shard("anything") != 0 || r.Shards() != 1 {
		t.Fatal("single shard ring")
	}
}

func BenchmarkRingShard(b *testing.B) {
	r := NewRing(8, DefaultVNodes)
	for i := 0; b.Loop(); i++ {
		r.Shard("payment-gateway")
	}
}
