package detect

import (
	"strconv"
	"time"
)

// Tick is the per-second snapshot for the live chart (the UI's "metric"
// message; Python Tick.to_dict).
type Tick struct {
	TS        string   `json:"ts"` // UTC ISO 8601, as the UI expects
	ErrorRate *float64 `json:"error_rate"`
	Baseline  *float64 `json:"baseline"`
	Z         *float64 `json:"z"`
	Lines     int      `json:"lines"`
	State     string   `json:"state"` // incident > insufficient > learning > active
	Severity  *string  `json:"severity"`
	IsAnomaly bool     `json:"is_anomaly"`
}

// Engine is the detection state for one service. It is driven by Observe
// (every line) and Tick (once per second) and never reads a clock.
type Engine struct {
	cfg     Config
	service string
	window  *Window
	er      *ErrorRateDetector
	alerts  *AlertManager

	lastArrival int64
	seen        bool
	errSeqs     []uint64 // ring of recent error-line seqs, for alert context
	errSeqNext  int

	templateText func(id int) string
}

func NewEngine(cfg Config, service string, templateText func(int) string) *Engine {
	return &Engine{
		cfg: cfg, service: service, window: NewWindow(cfg.WindowS),
		er: NewErrorRateDetector(cfg), alerts: NewAlertManager(cfg),
		errSeqs: make([]uint64, 0, cfg.SampleErrSeqs), templateText: templateText,
	}
}

// Observe records one line. lastTick is the most recent tick already run.
func (e *Engine) Observe(arrivalNs int64, isError bool, seq uint64, templateID int, lastTick int64) {
	e.window.Add(arrivalNs, isError, seq, templateID, lastTick)
	if !e.seen || arrivalNs > e.lastArrival {
		e.lastArrival, e.seen = arrivalNs, true
	}
	if isError && seq != 0 && e.cfg.SampleErrSeqs > 0 {
		if len(e.errSeqs) < e.cfg.SampleErrSeqs {
			e.errSeqs = append(e.errSeqs, seq)
		} else {
			e.errSeqs[e.errSeqNext] = seq
			e.errSeqNext = (e.errSeqNext + 1) % e.cfg.SampleErrSeqs
		}
	}
}

// WarmedUp reports whether the error-rate baseline is seeded.
func (e *Engine) WarmedUp() bool { return e.er.Baseline.Seeded() }

// Tick runs every detector for the second ending at k (unix seconds) and
// returns the chart snapshot and any alert notifications, in order.
func (e *Engine) Tick(k int64) (Tick, ErrorRateReading, []Alert) {
	nowNs := k * int64(time.Second)
	warmed := e.er.Baseline.Seeded() // as of before this tick, like Python's TickContext
	n, errs := e.window.Counts(k)
	reading := e.er.Measure(n, errs, e.alerts.IsOpen(SignalErrorRate, e.service, ""))

	var out []Alert
	if note := e.alerts.Process(reading.signal(e.service, e.cfg.WindowS), k); note != nil {
		out = append(out, e.alert(note, k))
	}
	sil := silenceSignal(e.cfg, e.service, warmed, e.lastArrival, nowNs, e.seen, func() bool {
		// No line has arrived since lastArrival, so the window's buckets for
		// the 30 s before it are still intact.
		n, _ := e.window.Counts(ceilSec(e.lastArrival))
		return n >= e.cfg.MinEvents
	})
	if note := e.alerts.Process(sil, k); note != nil {
		out = append(out, e.alert(note, k))
	}

	t := Tick{
		TS:        time.Unix(k, 0).UTC().Format("2006-01-02T15:04:05+00:00"),
		ErrorRate: reading.Rate, Baseline: reading.Mu, Z: reading.Z, Lines: reading.N,
		State: reading.State,
	}
	if sev := e.alerts.HighestOpen(); sev != SevNone {
		name := sev.String()
		t.State, t.Severity, t.IsAnomaly = "incident", &name, true
	}
	return t, reading, out
}

func (e *Engine) alert(n *notification, k int64) Alert {
	sig := n.inc.last
	first, last, topT, topN := e.window.Context(k)
	a := Alert{
		ID:          alertID(n.inc.id, n.status, n.now),
		IncidentID:  n.inc.id,
		Type:        n.inc.key.t,
		Status:      n.status,
		Severity:    n.inc.peak.String(),
		Service:     e.service,
		Template:    n.inc.key.template,
		Value:       sig.Value,
		Baseline:    sig.Baseline,
		Z:           sig.Z,
		Lines:       sig.Lines,
		Errors:      sig.Errors,
		Reason:      n.reason,
		WindowStart: k - int64(e.cfg.WindowS),
		WindowEnd:   k,
		SourceSeqs:  SeqRange{First: first, Last: last},
		CreatedAt:   n.inc.createdAt,
		UpdatedAt:   n.now,
	}
	if topT >= 0 {
		a.TopErrorTemplate = "T" + strconv.Itoa(topT)
		a.TopErrorTemplateCount = topN
		if e.templateText != nil {
			a.TopErrorTemplateText = e.templateText(topT)
		}
	}
	if len(e.errSeqs) > 0 {
		a.SourceSeqs.ErrorSeqs = append([]uint64(nil), e.errSeqs...)
	}
	return a
}
