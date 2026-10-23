package router

import (
	"encoding/binary"
	"hash/fnv"
	"slices"
	"strconv"
)

// Ring is a consistent-hash router: each shard owns `vnodes` points on a
// 64-bit hash ring, and a service belongs to the first point clockwise from
// its own hash.
//
// Why consistent hashing rather than hash mod N: per-service state (Drain
// trees, baselines) lives on exactly one shard. With mod N, changing N from
// 8 to 9 remaps about 8/9 of services, and all of that state is lost. With a
// ring only about 1/9 move: the ones whose points the new shard took over.
//
// Why virtual nodes: with one point per shard, arc lengths (and therefore
// the number of services per shard) vary wildly. Each shard's share has a
// relative spread of roughly 1/sqrt(vnodes). Measured with 200k services,
// the worst of 8 shards was +23% off a fair share at 128 vnodes, +14% at
// 256, and within about ±11% at 512 (see TestRingBalance).
//
// This balances the number of services per shard, not traffic: one hot
// service still lands on one shard. Splitting a hot service would need a
// different shard key and would break per-service state ownership.
type Ring struct {
	shards int
	vnodes int
	points []point // sorted by hash
}

type point struct {
	hash  uint64
	shard int
}

// DefaultVNodes keeps the busiest shard within about ±11% of a fair share of
// services for 4 to 16 shards, with a small ring (8 shards x 512 = 4096
// points, 64 KiB; a lookup is a 12-step binary search).
const DefaultVNodes = 512

// NewRing builds a ring of n shards with vnodes points each.
func NewRing(n, vnodes int) *Ring {
	n = max(n, 1)
	vnodes = max(vnodes, 1)
	r := &Ring{shards: n, vnodes: vnodes, points: make([]point, 0, n*vnodes)}
	var buf [16]byte
	for s := range n {
		for v := range vnodes {
			// Points depend only on (shard, vnode), so shard s keeps exactly
			// the same points when other shards are added or removed.
			binary.LittleEndian.PutUint64(buf[:8], uint64(s))
			binary.LittleEndian.PutUint64(buf[8:], uint64(v))
			r.points = append(r.points, point{hash: hash64(buf[:]), shard: s})
		}
	}
	slices.SortFunc(r.points, func(a, b point) int {
		switch {
		case a.hash < b.hash:
			return -1
		case a.hash > b.hash:
			return 1
		}
		return a.shard - b.shard // deterministic on (astronomically unlikely) ties
	})
	return r
}

func hash64(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	// FNV-1a's low bits are weak for short, similar keys ("svc-01",
	// "svc-02"); a final avalanche step (from SplitMix64) spreads them.
	x := h.Sum64()
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// Shard returns the shard owning service.
func (r *Ring) Shard(service string) int {
	h := hash64([]byte(service))
	i, _ := slices.BinarySearchFunc(r.points, h, func(p point, h uint64) int {
		switch {
		case p.hash < h:
			return -1
		case p.hash > h:
			return 1
		}
		return 0
	})
	if i == len(r.points) {
		i = 0 // wrap around the ring
	}
	return r.points[i].shard
}

func (r *Ring) Shards() int { return r.shards }

func (r *Ring) ID() string {
	return "ring-fnv1a-splitmix/" + strconv.Itoa(r.shards) + "x" + strconv.Itoa(r.vnodes)
}
