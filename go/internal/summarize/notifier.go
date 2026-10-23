package summarize

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/mokshad/tremor/internal/detect"
)

// NotifierConfig controls who gets paged and when.
type NotifierConfig struct {
	MinSeverity string        // incidents below this are recorded, never sent
	Delay       time.Duration // wait before asking the LLM, so related alerts can join
}

// NotifierStats counts incidents.
type NotifierStats struct {
	Opened, Closed, Paged atomic.Int64
	Open                  atomic.Int64
}

// Notifier owns the correlator and drives notifications:
//
//  1. an incident reaching MinSeverity is paged at once with the template
//     summary: paging latency never waits for a model;
//  2. Delay later, the LLM summary (one call per incident, cached) is sent
//     as an "incident.summary" follow-up;
//  3. when the incident closes, "incident.closed" carries the summary.
//
// The summary has no other effect: nothing reads it back.
type Notifier struct {
	cfg   NotifierConfig
	corr  *Correlator
	sum   *Guarded
	out   *Dispatcher
	log   *slog.Logger
	in    chan detect.Alert
	jobs  chan job
	Stats NotifierStats

	// OnNotify, if set, sees every notification (tests, the UI bridge).
	OnNotify func(Notification)

	paged   map[string]bool
	pending map[string]time.Time // incident -> when to summarize
	latest  map[string]Incident
	done    chan struct{}
}

type job struct {
	kind string // "summary" | "closed"
	inc  Incident
}

func NewNotifier(cfg NotifierConfig, corr *Correlator, sum *Guarded, out *Dispatcher, log *slog.Logger) *Notifier {
	return &Notifier{cfg: cfg, corr: corr, sum: sum, out: out, log: log,
		in: make(chan detect.Alert, 1024), jobs: make(chan job, 256),
		paged: map[string]bool{}, pending: map[string]time.Time{}, latest: map[string]Incident{}, done: make(chan struct{})}
}

// Alerts is where the pipeline sends alerts and notices.
func (n *Notifier) Alerts() chan<- detect.Alert { return n.in }

// Run processes alerts until the Alerts channel is closed, then closes
// every open incident, finishes pending summaries and returns.
func (n *Notifier) Run() {
	workerDone := make(chan struct{})
	go func() { n.worker(); close(workerDone) }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case a, ok := <-n.in:
			if !ok {
				n.handle(n.corr.CloseAll())
				close(n.jobs)
				<-workerDone
				close(n.done)
				return
			}
			if a.Status == detect.StatusNotice {
				n.corr.Notice(a)
				continue
			}
			n.handle(n.corr.Add(a))
		case now := <-tick.C:
			n.handle(n.corr.Expire(now.Unix()))
			for id, due := range n.pending {
				if now.After(due) {
					delete(n.pending, id)
					n.submit(job{"summary", n.latest[id]})
				}
			}
		}
	}
}

func (n *Notifier) handle(evs []Event) {
	for _, ev := range evs {
		in := ev.Incident
		switch ev.Type {
		case "opened", "updated", "escalated":
			if ev.Type == "opened" {
				n.Stats.Opened.Add(1)
				n.Stats.Open.Add(1)
			}
			n.latest[in.ID] = in
			if !SeverityAtLeast(in.Severity, n.cfg.MinSeverity) {
				continue
			}
			if !n.paged[in.ID] {
				n.paged[in.ID] = true
				n.Stats.Paged.Add(1)
				n.send(NewNotification("incident.opened", in, n.template(in), time.Now()))
				n.pending[in.ID] = time.Now().Add(n.cfg.Delay)
			} else if ev.Type == "escalated" {
				n.send(NewNotification("incident.escalated", in, n.template(in), time.Now()))
			}
		case "closed":
			n.Stats.Closed.Add(1)
			n.Stats.Open.Add(-1)
			delete(n.latest, in.ID)
			if n.paged[in.ID] {
				delete(n.paged, in.ID)
				if _, waiting := n.pending[in.ID]; waiting {
					delete(n.pending, in.ID)
					n.submit(job{"summary", in})
				}
				n.submit(job{"closed", in})
			}
		}
	}
}

func (n *Notifier) template(in Incident) Summary {
	s, _ := Template{}.Summarize(context.Background(), in)
	return s
}

func (n *Notifier) submit(j job) {
	select {
	case n.jobs <- j:
	default:
		// Summary queue full: send with the template rather than block.
		kind := "incident.summary"
		if j.kind == "closed" {
			kind = "incident.closed"
		}
		n.send(NewNotification(kind, j.inc, n.template(j.inc), time.Now()))
	}
}

// worker runs summaries one at a time, so an incident's summary and close
// never race and the cache answers the second.
func (n *Notifier) worker() {
	for j := range n.jobs {
		s, err := n.sum.Summarize(context.Background(), j.inc)
		if err != nil {
			s = n.template(j.inc)
		}
		kind := "incident.summary"
		if j.kind == "closed" {
			kind = "incident.closed"
		}
		n.send(NewNotification(kind, j.inc, s, time.Now()))
	}
}

func (n *Notifier) send(note Notification) {
	if n.OnNotify != nil {
		n.OnNotify(note)
	}
	if n.out != nil {
		n.out.Enqueue(note)
	}
}

// Wait blocks until Run has returned.
func (n *Notifier) Wait() { <-n.done }
