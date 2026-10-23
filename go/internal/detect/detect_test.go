package detect

import (
	"encoding/json"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/mokshad/tremor/internal/drain"
	"github.com/mokshad/tremor/internal/event"
)

func TestPySumMatchesCPython(t *testing.T) {
	id := func(x float64) float64 { return x }
	xs := append(slices.Repeat([]float64{0.1}, 10), 1e16, 1.0, -1e16)
	// Values printed by CPython 3.14: sum(xs) and sum(x*x for x in ys).
	if got := PySum(xs, id); got != 2.0 {
		t.Fatalf("PySum = %v, CPython 2.0", got)
	}
	naive := 0.0
	for _, x := range xs {
		naive += x
	}
	if naive == 2.0 {
		t.Fatal("test input does not distinguish naive from compensated summation")
	}
	ys := []float64{0.1, 0.2, 0.3, 1e8, 0.7}
	if got := PySum(ys, func(x float64) float64 { return x * x }); got != 1e16 {
		t.Fatalf("PySum squares = %v, CPython 1e+16", got)
	}
}

func TestWindowMatchesNaiveDeque(t *testing.T) {
	// Python keeps every arrival and evicts ts <= now - 30 at each tick;
	// the bucketed window must count exactly the same lines.
	rng := rand.New(rand.NewPCG(1, 2))
	const start = int64(1_767_621_600)
	w := NewWindow(30)
	type line struct {
		ns  int64
		err bool
	}
	var all []line
	next := start + 1
	ns := start * int64(time.Second)
	for range 20000 {
		ns += rng.Int64N(int64(400 * time.Millisecond)) // gaps, including > 1 s bursts of silence
		if rng.IntN(50) == 0 {
			ns = (ns/int64(time.Second) + 1) * int64(time.Second) // exactly on a tick boundary
		}
		for ; next*int64(time.Second) < ns; next++ {
			n, e := w.Counts(next)
			var wn, we int
			for _, l := range all {
				if l.ns > (next-30)*int64(time.Second) && l.ns <= next*int64(time.Second) {
					wn++
					if l.err {
						we++
					}
				}
			}
			if n != wn || e != we {
				t.Fatalf("tick %d: window %d/%d, deque %d/%d", next-start, n, e, wn, we)
			}
		}
		isErr := rng.IntN(10) == 0
		w.Add(ns, isErr, 0, 0, next-1)
		all = append(all, line{ns, isErr})
	}
}

func TestBaselineSeedAndGatedUpdate(t *testing.T) {
	b := Baseline{Alpha: 0.5, WarmupTicks: 4, SigmaMin: 0.01, MaxUpdateZ: 2, NoiseFloor: BinomialFloor}
	for _, v := range []float64{0.1, 0.2, 0.3} {
		b.AddWarmup(v)
	}
	if b.Seeded() || b.WarmupCount() != 3 {
		t.Fatal("seeded early")
	}
	b.AddWarmup(0.4)
	mu, ok := b.Mu()
	if !ok || mu != 0.25 || b.Sigma() < 0.111 || b.Sigma() > 0.112 { // pop. sd of .1..4 = 0.1118
		t.Fatalf("seed mu %v sigma %v", mu, b.Sigma())
	}
	if b.Update(0.9, 2.5, false) {
		t.Fatal("updated on z >= MaxUpdateZ")
	}
	if b.Update(0.3, 0.5, true) {
		t.Fatal("updated during an incident")
	}
	if !b.Update(0.35, 0.5, false) {
		t.Fatal("did not update on a normal tick")
	}
	if mu, _ := b.Mu(); mu != 0.30000000000000004 && mu != 0.3 {
		t.Fatalf("EWMA mu %v", mu)
	}
	// Noise floor: with n=20 at mu=0.3 the binomial floor beats sigma_min.
	if got := b.SigmaEff(20); got < BinomialFloor(0.3, 20)-1e-12 {
		t.Fatalf("sigma_eff %v below binomial floor", got)
	}
}

func cfgFast() Config {
	c := DefaultConfig()
	c.WarmupTicks, c.MinEvents, c.ClearTicks, c.CooldownS = 3, 10, 3, 60
	return c
}

func TestErrorRateStates(t *testing.T) {
	d := NewErrorRateDetector(cfgFast())
	if r := d.Measure(5, 1, false); r.State != "insufficient" || r.Clear != 0 || r.Z != nil {
		t.Fatalf("insufficient: %+v", r)
	}
	if r := d.Measure(100, 80, false); r.Severity != SevCritical || r.State != "learning" || r.Clear != -1 {
		t.Fatalf("critical while learning: %+v", r)
	}
	if d.Baseline.WarmupCount() != 0 {
		t.Fatal("critical tick was used for warm-up")
	}
	for range 3 {
		d.Measure(100, 2, false)
	}
	if !d.Baseline.Seeded() {
		t.Fatal("not seeded after warm-up")
	}
	r := d.Measure(100, 30, false) // 30% vs ~2%: well above z_high
	if r.State != "active" || r.Severity != SevHigh || r.Clear != -1 || *r.Mu != 0.02 {
		t.Fatalf("spike: %+v mu %v z %v", r, *r.Mu, *r.Z)
	}
	if mu, _ := d.Baseline.Mu(); mu != 0.02 {
		t.Fatal("baseline absorbed the spike")
	}
}

func sig(sev Severity, clear int8) Signal {
	return Signal{Type: SignalErrorRate, Service: "svc", Severity: sev, Clear: clear, Reason: "r"}
}

func TestAlertLifecycle(t *testing.T) {
	m := NewAlertManager(cfgFast())
	if n := m.Process(sig(SevNone, 1), 100); n != nil {
		t.Fatal("alert without severity")
	}
	n := m.Process(sig(SevInfo, -1), 101)
	if n == nil || n.status != StatusOpen {
		t.Fatal("no OPEN")
	}
	id := n.inc.id
	if m.Process(sig(SevInfo, -1), 102) != nil {
		t.Fatal("re-emitted at the same severity")
	}
	if n := m.Process(sig(SevHigh, -1), 103); n == nil || n.status != StatusEscalated {
		t.Fatal("no ESCALATED")
	}
	if m.Process(sig(SevWarning, -1), 104) != nil {
		t.Fatal("emitted on a drop below the peak")
	}
	m.Process(sig(SevNone, 1), 105)
	m.Process(sig(SevNone, 0), 106) // neutral: neither counts nor resets
	m.Process(sig(SevNone, 1), 107)
	if !m.IsOpen(SignalErrorRate, "svc", "") {
		t.Fatal("resolved too early")
	}
	n = m.Process(sig(SevNone, 1), 108)
	if n == nil || n.status != StatusResolved || m.IsOpen(SignalErrorRate, "svc", "") {
		t.Fatal("not resolved after 3 clear ticks")
	}
	// Re-open within the cooldown reuses the incident id.
	if n := m.Process(sig(SevWarning, -1), 150); n == nil || n.inc.id != id || n.status != StatusOpen {
		t.Fatal("cooldown did not reuse the incident")
	}
	m.Process(sig(SevNone, 1), 151)
	m.Process(sig(SevNone, 1), 152)
	m.Process(sig(SevNone, 1), 153)
	if n := m.Process(sig(SevWarning, -1), 400); n == nil || n.inc.id == id {
		t.Fatal("re-open after the cooldown must be a new incident")
	}
	// Ids are deterministic: same key and time, same id.
	if incidentID(incidentKey{SignalErrorRate, "svc", ""}, 101) != id {
		t.Fatal("incident id not deterministic")
	}
}

func ev(service string, ns int64, level event.Level, seq uint64) *event.Event {
	return &event.Event{Seq: seq, Service: service, ReceivedAt: ns, Timestamp: ns, Level: level, Message: "request handled in 12ms"}
}

func TestProcessorBoundaryAndSilence(t *testing.T) {
	cfg := cfgFast()
	cfg.SilenceS = 5
	var alerts []Alert
	p := NewProcessor(cfg, drain.TremorConfig(), func(a Alert) { alerts = append(alerts, a) })
	var ticks []int64
	p.OnTick(func(_ string, tk Tick, _ ErrorRateReading) {
		ts, _ := time.Parse(time.RFC3339, tk.TS)
		ticks = append(ticks, ts.Unix())
	})
	const s0 = int64(1_000_000)
	sec := int64(time.Second)
	p.SetOrigin(s0)
	p.Process(ev("a", s0*sec+sec/2, event.LevelInfo, 1))
	p.Process(ev("a", (s0+2)*sec, event.LevelInfo, 2)) // exactly on a boundary: ticks 1 and... 1 only
	if !slices.Equal(ticks, []int64{s0 + 1}) {
		t.Fatalf("ticks before a boundary line: %v", ticks)
	}
	// Warm up with steady traffic, then go quiet.
	seq := uint64(3)
	for k := s0 + 2; k < s0+12; k++ {
		for i := range 20 {
			p.Process(ev("a", k*sec+int64(i)*sec/20, event.LevelInfo, seq))
			seq++
		}
	}
	p.Advance((s0 + 30) * sec)
	var silence []Alert
	for _, a := range alerts {
		if a.Type == SignalSilence {
			silence = append(silence, a)
		}
	}
	if len(silence) != 1 || silence[0].Severity != "HIGH" || silence[0].Status != StatusOpen {
		t.Fatalf("silence alerts: %+v", silence)
	}
	// Lines return: the next tick resolves it.
	p.Process(ev("a", (s0+30)*sec+1, event.LevelInfo, seq))
	p.Advance((s0 + 31) * sec)
	if last := alerts[len(alerts)-1]; last.Type != SignalSilence || last.Status != StatusResolved {
		t.Fatalf("silence not resolved: %+v", last)
	}
}

func TestProcessorSkipsHugeClockJumps(t *testing.T) {
	cfg := cfgFast()
	cfg.MaxCatchUpS = 100
	p := NewProcessor(cfg, drain.TremorConfig(), nil)
	p.SetOrigin(0)
	p.Process(ev("a", int64(time.Second)/2, event.LevelInfo, 1))
	p.Advance(10_000 * int64(time.Second))
	if p.Stats.SkippedTicks == 0 || p.Stats.Ticks > 10 {
		t.Fatalf("ticks %d skipped %d", p.Stats.Ticks, p.Stats.SkippedTicks)
	}
}

func TestTickJSONMatchesUIContract(t *testing.T) {
	e := NewEngine(cfgFast(), "svc", nil)
	tk, _, _ := e.Tick(1_767_621_600)
	b, _ := json.Marshal(tk)
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"ts", "error_rate", "baseline", "z", "lines", "state", "severity", "is_anomaly"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("tick JSON missing %q: %s", k, b)
		}
	}
	if m["ts"] != "2026-01-05T14:00:00+00:00" || m["state"] != "insufficient" {
		t.Fatalf("tick %s", b)
	}
}

func TestSilenceNeedsABusyServiceBeforeTheGap(t *testing.T) {
	cfg := cfgFast()
	cfg.SilenceS = 5
	var alerts []Alert
	p := NewProcessor(cfg, drain.TremorConfig(), func(a Alert) { alerts = append(alerts, a) })
	const s0 = int64(2_000_000)
	sec := int64(time.Second)
	p.SetOrigin(s0)
	seq := uint64(1)
	// Busy for 20 s (warms up), then a slow trickle: one line every 15 s.
	for k := s0; k < s0+20; k++ {
		for i := range 20 {
			p.Process(ev("a", k*sec+int64(i)*sec/20, event.LevelInfo, seq))
			seq++
		}
	}
	p.Advance((s0 + 60) * sec) // a gap right after busy traffic: real silence
	n := len(alerts)
	if n == 0 || alerts[n-1].Type != SignalSilence {
		t.Fatalf("silence after busy traffic not raised: %+v", alerts)
	}
	for k := s0 + 60; k < s0+600; k += 15 { // now a trickle: its gaps are normal
		p.Process(ev("a", k*sec, event.LevelInfo, seq))
		seq++
		p.Advance((k + 14) * sec)
	}
	for _, a := range alerts[n:] {
		if a.Type == SignalSilence && a.Status != StatusResolved {
			t.Fatalf("trickle traffic raised silence: %+v", a)
		}
	}
}
