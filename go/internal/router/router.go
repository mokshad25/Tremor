// Package router maps a service name to a shard.
//
// Phase 2 ships a plain hash-mod-N router so the WAL, checkpoints and
// replay can be built against the Router interface. Phase 3 replaces it with
// consistent hashing (virtual nodes), which moves far fewer services when the
// shard count changes.
package router

import (
	"hash/fnv"
	"strconv"
)

// Router assigns services to shards. Implementations must be deterministic:
// the same service always maps to the same shard for a given ID, because
// per-shard checkpoints are only meaningful under the routing that produced
// them.
type Router interface {
	Shard(service string) int
	Shards() int
	// ID identifies the algorithm and layout, e.g. "mod-fnv1a/8". A
	// checkpoint written under a different ID is not trusted per shard.
	ID() string
}

// Modulo is FNV-1a(service) mod n.
type Modulo struct{ n int }

func NewModulo(n int) Modulo {
	if n < 1 {
		n = 1
	}
	return Modulo{n: n}
}

func (m Modulo) Shard(service string) int {
	h := fnv.New32a()
	h.Write([]byte(service))
	return int(h.Sum32() % uint32(m.n))
}

func (m Modulo) Shards() int { return m.n }
func (m Modulo) ID() string  { return "mod-fnv1a/" + strconv.Itoa(m.n) }
