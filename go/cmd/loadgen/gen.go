package main

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
)

// GenConfig controls the synthetic traffic mix.
type GenConfig struct {
	Services       int           // 1-3 use the catalogue services; more add svc-04, svc-05, ...
	Seed           uint64        //
	SpikeEvery     time.Duration // 0 disables error spikes
	SpikeLen       time.Duration
	SpikeErrorRate float64 // ERROR probability for the spiking service
}

// Spike is a ground-truth label: Service's error rate is SpikeErrorRate in
// [Start, End) measured from the start of the run.
type Spike struct {
	Service string  `json:"service"`
	StartS  float64 `json:"start_s"`
	EndS    float64 `json:"end_s"`
}

type service struct {
	name      string
	cumWeight float64
	errorRate float64
	templates map[string][]tmpl
}

// wireEvent is the POST /ingest event shape (see internal/event.Wire).
type wireEvent struct {
	Service    string            `json:"service"`
	Timestamp  string            `json:"timestamp"`
	Level      string            `json:"level"`
	Message    string            `json:"message"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Generator produces events. It is not safe for concurrent use; each loadgen
// worker owns one, seeded with (seed, worker id), so a run is reproducible
// per worker.
type Generator struct {
	cfg   GenConfig
	rng   *rand.Rand
	svcs  []service
	total float64
	sb    strings.Builder
}

func NewGenerator(cfg GenConfig, stream uint64) *Generator {
	if cfg.Services < 1 {
		cfg.Services = 1
	}
	g := &Generator{cfg: cfg, rng: rand.New(rand.NewPCG(cfg.Seed, stream))}
	for i := range cfg.Services {
		s := service{name: "svc-" + pad2(i+1), errorRate: 0.02, templates: genericTemplates}
		w := 3.0
		if i < len(catalogue) {
			p := catalogue[i]
			s = service{name: p.name, errorRate: p.errorRate, templates: p.templates}
			w = p.weight
		}
		g.total += w
		s.cumWeight = g.total
		g.svcs = append(g.svcs, s)
	}
	return g
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// ServiceNames returns the services in generation order.
func (g *Generator) ServiceNames() []string {
	out := make([]string, len(g.svcs))
	for i, s := range g.svcs {
		out[i] = s.name
	}
	return out
}

// spikeAt reports which service (index) is spiking at elapsed, if any. Spike
// k (k >= 1) covers [k*every, k*every+len) and hits service (k-1) mod n, so
// the first period is always clean (baselines can warm up) and spikes rotate
// across services.
func (g *Generator) spikeAt(elapsed time.Duration) (int, bool) {
	every, length := g.cfg.SpikeEvery, g.cfg.SpikeLen
	if every <= 0 || length <= 0 || elapsed < every {
		return 0, false
	}
	k := int(elapsed / every)
	if elapsed-time.Duration(k)*every >= length {
		return 0, false
	}
	return (k - 1) % len(g.svcs), true
}

// Spikes lists the ground-truth spike windows for a run of the given length.
func (g *Generator) Spikes(duration time.Duration) []Spike {
	var out []Spike
	every, length := g.cfg.SpikeEvery, g.cfg.SpikeLen
	if every <= 0 || length <= 0 {
		return nil
	}
	for k := 1; time.Duration(k)*every < duration; k++ {
		start := time.Duration(k) * every
		end := min(start+length, duration)
		out = append(out, Spike{
			Service: g.svcs[(k-1)%len(g.svcs)].name,
			StartS:  start.Seconds(),
			EndS:    end.Seconds(),
		})
	}
	return out
}

// Event generates one event at run offset elapsed, stamped with ts.
func (g *Generator) Event(elapsed time.Duration, ts time.Time) wireEvent {
	x := g.rng.Float64() * g.total
	idx := 0
	for idx < len(g.svcs)-1 && x >= g.svcs[idx].cumWeight {
		idx++
	}
	s := &g.svcs[idx]

	errRate := s.errorRate
	if spiking, ok := g.spikeAt(elapsed); ok && spiking == idx {
		errRate = g.cfg.SpikeErrorRate
	}
	level := "INFO"
	switch u := g.rng.Float64(); {
	case u < errRate:
		level = "ERROR"
	case u < errRate+0.03:
		level = "WARNING"
	}
	ts2 := s.templates[level]
	msg := ts2[g.rng.IntN(len(ts2))].render(g.rng, &g.sb)
	return wireEvent{
		Service:    s.name,
		Timestamp:  ts.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		Level:      level,
		Message:    msg,
		Attributes: map[string]string{"host": s.name + "-" + strconv.Itoa(g.rng.IntN(4))},
	}
}

// Batch generates n events.
func (g *Generator) Batch(elapsed time.Duration, ts time.Time, n int) []wireEvent {
	out := make([]wireEvent, n)
	for i := range out {
		out[i] = g.Event(elapsed, ts)
	}
	return out
}
