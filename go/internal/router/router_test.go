package router

import (
	"fmt"
	"testing"
)

func TestModuloDeterministicAndInRange(t *testing.T) {
	r := NewModulo(8)
	counts := make([]int, 8)
	for i := range 10_000 {
		svc := fmt.Sprintf("svc-%d", i)
		s := r.Shard(svc)
		if s < 0 || s >= 8 {
			t.Fatalf("shard %d out of range", s)
		}
		if r.Shard(svc) != s {
			t.Fatal("not deterministic")
		}
		counts[s]++
	}
	for i, c := range counts {
		if c < 1000 || c > 1500 { // 1250 expected per shard
			t.Fatalf("shard %d got %d of 10000: badly unbalanced %v", i, c, counts)
		}
	}
	if r.ID() != "mod-fnv1a/8" || NewModulo(0).Shards() != 1 {
		t.Fatal("ID or clamp wrong")
	}
}
