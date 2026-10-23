package detect

import (
	"slices"
	"strings"
	"time"

	"github.com/mokshad/tremor/internal/drain"
	"github.com/mokshad/tremor/internal/event"
)

// Processor is the per-shard detection stage (it implements
// shard.Processor). For every service routed to the shard it owns a Drain
// tree and a detection Engine; one goroutine drives it, so none of that
// state needs a lock.
//
// Time comes from the events themselves: each event's gateway receive time
// (ReceivedAt) advances the shard's clock, and before an event is observed
// every whole-second tick strictly before its arrival is run. That is the
// rule the Python eval harness uses, which makes live processing, crash
// replay and offline evaluation produce the same alerts for the same input.
// A wall-clock ticker (shard.Ticker) keeps ticks flowing when no events
// arrive, so silence can be detected.
type Processor struct {
	cfg      Config
	drainCfg drain.Config
	masker   *drain.Masker
	emit     func(Alert)
	onTick   func(service string, t Tick, r ErrorRateReading)

	allowed  map[string]bool // tokenized security.allowed_sources
	services map[string]*serviceState
	names    []string // sorted: services are ticked in name order (deterministic)
	nextTick int64    // unix seconds of the next tick to run
	started  bool

	Stats ProcessorStats
}

type serviceState struct {
	drain      *drain.Drain
	engine     *Engine
	sec        *Security // nil when security rules are disabled
	lastDeploy int64     // last deploy notice (unix seconds), to rate-limit them
}

// deployWords mark a line that announces a deploy or release.
var deployWords = []string{"deployed", "deploying", "deployment ", "rolled out", "rollout ", "released version", "release v", "new version", "upgraded to"}

// deployNotice turns a deploy line into a NOTICE for the correlator (at most
// one per service per minute). It carries the redacted line as context for
// incident summaries; it is never an alert.
func (p *Processor) deployNotice(s *serviceState, ev *event.Event, templateText string) {
	k := ev.ReceivedAt / int64(time.Second)
	if k-s.lastDeploy < 60 {
		return
	}
	lower := strings.ToLower(templateText)
	for _, w := range deployWords {
		if strings.Contains(lower, w) {
			s.lastDeploy = k
			msg := ev.Message
			if len(msg) > 200 {
				msg = msg[:200]
			}
			if p.emit != nil {
				p.emit(Alert{Type: SignalDeploy, Status: StatusNotice, Service: ev.Service, Reason: msg,
					WindowStart: k, WindowEnd: k, CreatedAt: k, UpdatedAt: k, SourceSeqs: SeqRange{First: ev.Seq, Last: ev.Seq}})
			}
			return
		}
	}
}

type ProcessorStats struct {
	Events, Ticks, SkippedTicks, LateEvents int64
	AlertsByType                            map[SignalType]int64
}

// NewProcessor returns a processor that sends alert notifications to emit.
func NewProcessor(cfg Config, drainCfg drain.Config, emit func(Alert)) *Processor {
	return &Processor{
		cfg: cfg, drainCfg: drainCfg, masker: drain.TremorMasker(), emit: emit,
		services: map[string]*serviceState{},
		Stats:    ProcessorStats{AlertsByType: map[SignalType]int64{}},
	}
}

// OnTick registers a callback for every per-service tick (the live chart).
func (p *Processor) OnTick(f func(service string, t Tick, r ErrorRateReading)) { p.onTick = f }

// SetAllowedSources sets the tokenized IPs exempt from the single-source
// credential-stuffing rule (e.g. a known office NAT).
func (p *Processor) SetAllowedSources(tokens map[string]bool) { p.allowed = tokens }

// SetOrigin fixes the first tick at origin+1 (unix seconds). Without it the
// first tick is the second after the first event's arrival.
func (p *Processor) SetOrigin(originSec int64) {
	p.nextTick, p.started = originSec+1, true
}

func (p *Processor) service(name string) *serviceState {
	s := p.services[name]
	if s == nil {
		d := drain.New(p.drainCfg)
		s = &serviceState{drain: d}
		s.engine = NewEngine(p.cfg, name, func(id int) string {
			if c := d.Get(id); c != nil {
				return c.Template()
			}
			return ""
		})
		if p.cfg.Security.Enabled {
			s.sec = NewSecurity(p.cfg.Security, name, p.allowed)
		}
		p.services[name] = s
		i, _ := slices.BinarySearch(p.names, name)
		p.names = slices.Insert(p.names, i, name)
	}
	return s
}

// Process mines the event's template and feeds the service's engine.
func (p *Processor) Process(ev *event.Event) {
	if !p.started {
		p.nextTick, p.started = ev.ReceivedAt/int64(time.Second)+1, true
	}
	p.TickBefore(ev.ReceivedAt)
	s := p.service(ev.Service)
	c, change := s.drain.Add(p.masker.Mask(drain.MaskTokens(ev.Message)))
	if ev.ReceivedAt <= (p.nextTick-1-int64(p.cfg.WindowS))*int64(time.Second) {
		p.Stats.LateEvents++ // arrived before the window already passed; templated, not counted
	}
	s.engine.Observe(ev.ReceivedAt, ev.Level == event.LevelError, ev.Seq, c.ID, p.nextTick-1)
	if s.sec != nil {
		p.send(s.sec.Observe(ev, c.ID, c.Template(), change != drain.ChangeNone))
	}
	p.deployNotice(s, ev, c.Template())
	p.Stats.Events++
}

// TickBefore runs every tick k with k seconds < ns (a line arriving exactly
// on a tick boundary is observed before that tick).
func (p *Processor) TickBefore(ns int64) {
	last := ns / int64(time.Second)
	if ns%int64(time.Second) == 0 {
		last--
	}
	p.tickThrough(last)
}

// Advance runs every tick up to and including the wall-clock second ns
// (implements shard.Ticker).
func (p *Processor) Advance(ns int64) {
	if !p.started {
		return // nothing seen yet: nothing to tick
	}
	p.tickThrough(ns / int64(time.Second))
}

func (p *Processor) tickThrough(last int64) {
	if !p.started || last < p.nextTick {
		return
	}
	if gap := last - p.nextTick + 1; gap > int64(p.cfg.MaxCatchUpS) {
		// A clock jump this large means the shard was not running (or the
		// clock changed). Replaying an hour of empty ticks would only
		// manufacture silence alerts about our own downtime.
		p.Stats.SkippedTicks += gap - 1
		p.nextTick = last
	}
	for ; p.nextTick <= last; p.nextTick++ {
		k := p.nextTick
		for _, name := range p.names {
			svc := p.services[name]
			t, r, alerts := svc.engine.Tick(k)
			if p.onTick != nil {
				p.onTick(name, t, r)
			}
			p.send(alerts)
			if svc.sec != nil {
				p.send(svc.sec.Tick(k))
			}
		}
		p.Stats.Ticks++
	}
}

func (p *Processor) send(alerts []Alert) {
	for _, a := range alerts {
		p.Stats.AlertsByType[a.Type]++
		if p.emit != nil {
			p.emit(a)
		}
	}
}

// Services returns the number of services this processor has seen.
func (p *Processor) Services() int { return len(p.services) }

// Templates returns the number of live templates across services.
func (p *Processor) Templates() int {
	n := 0
	for _, s := range p.services {
		n += s.drain.Len()
	}
	return n
}

// Flush has nothing durable to write: detection state is rebuilt from the
// WAL (see docs/phase3-detection.md for what that means after a crash).
func (p *Processor) Flush() error { return nil }
func (p *Processor) Close() error { return nil }
