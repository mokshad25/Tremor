package eval

import (
	"slices"
	"time"

	"github.com/mokshad/tremor/internal/detect"
	"github.com/mokshad/tremor/internal/drain"
	"github.com/mokshad/tremor/internal/event"
)

// Detector is what the harness drives: Run replays one scenario through a
// fresh detector and returns the incidents it opened.
type Detector struct {
	Name string
	Run  func(s *Scenario) []Alert
}

// Detectors mirrors the Python harness's DETECTORS (eval/detectors.py).
func Detectors(cfg detect.Config) []Detector {
	return []Detector{
		{Name: "TREMOR", Run: func(s *Scenario) []Alert { return runTremor(s, cfg, detect.SevInfo) }},
		{Name: "TREMOR (WARNING+)", Run: func(s *Scenario) []Alert { return runTremor(s, cfg, detect.SevWarning) }},
		{Name: "Static 5%", Run: runStatic},
		{Name: "Rolling mean", Run: runRollingMean},
	}
}

var severityByName = map[string]detect.Severity{
	"INFO": detect.SevInfo, "WARNING": detect.SevWarning, "HIGH": detect.SevHigh, "CRITICAL": detect.SevCritical,
}

// runTremor drives the production shard processor (Drain + per-service
// engines) exactly as the shards do, ticking once per scenario second. An
// incident is reported once, at its first OPEN/ESCALATED notification whose
// severity is at least minSev; a fresh OPEN is a new incident (Python
// TremorDetector).
func runTremor(s *Scenario, cfg detect.Config, minSev detect.Severity) []Alert {
	start := int64(s.StartTS)
	var out []Alert
	reported := map[string]bool{}
	p := detect.NewProcessor(cfg, drain.TremorConfig(), func(a detect.Alert) {
		if a.Status != detect.StatusOpen && a.Status != detect.StatusEscalated {
			return
		}
		if a.Status == detect.StatusOpen {
			delete(reported, a.IncidentID)
		}
		if reported[a.IncidentID] || severityByName[a.Severity] < minSev {
			return
		}
		reported[a.IncidentID] = true
		out = append(out, Alert{TS: float64(a.UpdatedAt - start), Type: string(a.Type), Service: a.Service})
	})
	p.SetOrigin(start)
	for i := range s.Events {
		p.Process(&s.Events[i])
	}
	p.TickBefore((start + int64(s.DurationS) + 1) * int64(time.Second))
	return out
}

// incidents is the baselines' simple open/resolve rule: open on the first
// firing tick, resolve after 10 quiet ticks in a row.
type incidents struct {
	open  map[string]bool
	quiet map[string]int
}

const clearTicks = 10

func (in *incidents) update(service string, firing bool) bool {
	if in.open == nil {
		in.open, in.quiet = map[string]bool{}, map[string]int{}
	}
	if firing {
		in.quiet[service] = 0
		if !in.open[service] {
			in.open[service] = true
			return true
		}
	} else if in.open[service] {
		in.quiet[service]++
		if in.quiet[service] >= clearTicks {
			in.open[service], in.quiet[service] = false, 0
		}
	}
	return false
}

// replayWindows feeds lines into per-service 30 s windows and calls tick
// once per second with the services seen so far (sorted).
func replayWindows(s *Scenario, tick func(k int64, svc string, n, errs int)) {
	start := int64(s.StartTS)
	windows := map[string]*detect.Window{}
	var names []string
	next := start + 1
	runTicks := func(limitNs int64) {
		for ; next*int64(time.Second) < limitNs; next++ {
			for _, svc := range names {
				n, e := windows[svc].Counts(next)
				tick(next, svc, n, e)
			}
		}
	}
	for i := range s.Events {
		ev := &s.Events[i]
		runTicks(ev.ReceivedAt)
		w := windows[ev.Service]
		if w == nil {
			w = detect.NewWindow(30)
			windows[ev.Service] = w
			j, _ := slices.BinarySearch(names, ev.Service)
			names = slices.Insert(names, j, ev.Service)
		}
		w.Add(ev.ReceivedAt, ev.Level == event.LevelError, 0, 0, next-1)
	}
	runTicks((start + int64(s.DurationS) + 1) * int64(time.Second))
}

// runStatic: ERROR_RATE when errors/lines over the last 30 s exceed 5%.
func runStatic(s *Scenario) []Alert {
	var out []Alert
	var in incidents
	start := int64(s.StartTS)
	replayWindows(s, func(k int64, svc string, n, errs int) {
		firing := n >= 20 && float64(errs)/float64(n) > 0.05
		if in.update(svc, firing) {
			out = append(out, Alert{TS: float64(k - start), Type: "ERROR_RATE", Service: svc})
		}
	})
	return out
}

// runRollingMean: ERROR_RATE when the rate exceeds max(2 x mean, mean +
// 0.02) of its own last 300 rates, with no freeze (anomalies leak into the
// mean).
func runRollingMean(s *Scenario) []Alert {
	var out []Alert
	var in incidents
	start := int64(s.StartTS)
	history := map[string][]float64{}
	replayWindows(s, func(k int64, svc string, n, errs int) {
		firing := false
		if n >= 20 {
			rate := float64(errs) / float64(n)
			h := history[svc]
			if len(h) >= 60 {
				mean := detect.PySum(h, func(x float64) float64 { return x }) / float64(len(h))
				firing = rate > max(2*mean, mean+0.02)
			}
			h = append(h, rate)
			if len(h) > 300 {
				h = h[1:]
			}
			history[svc] = h
		}
		if in.update(svc, firing) {
			out = append(out, Alert{TS: float64(k - start), Type: "ERROR_RATE", Service: svc})
		}
	})
	return out
}
