package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Prometheus exposition. The atomic counters in this package stay the
// source of truth (they are cheap on the hot path and expvar keeps working
// for the bench scripts); a custom Collector turns them into Prometheus
// metrics when /metrics is scraped. Latencies need distributions, so those
// are real Histograms observed where they happen.

// Histograms that stages observe directly. A nil histogram is a no-op, so
// tests can use zero-value structs.
type Histograms struct {
	WALFsync   prometheus.Histogram
	WALWrite   prometheus.Histogram
	LLMRequest prometheus.Histogram
}

// NewHistograms creates the latency histograms with buckets suited to each.
func NewHistograms() *Histograms {
	return &Histograms{
		WALFsync: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "tremor_wal_fsync_seconds", Help: "Time to fsync one WAL group (F_FULLFSYNC on macOS).",
			Buckets: []float64{0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1},
		}),
		WALWrite: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "tremor_wal_write_seconds", Help: "Time to write one WAL group to the OS (before fsync).",
			Buckets: []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05},
		}),
		LLMRequest: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "tremor_llm_request_seconds", Help: "LLM summary request latency (successful and failed calls).",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2, 4, 8, 15, 30},
		}),
	}
}

func observe(h prometheus.Histogram, v float64) {
	if h != nil {
		h.Observe(v)
	}
}

// ObserveWALFsync / ObserveWALWrite / ObserveLLM record a duration in seconds.
func (h *Histograms) ObserveWALFsync(s float64) {
	if h != nil {
		observe(h.WALFsync, s)
	}
}
func (h *Histograms) ObserveWALWrite(s float64) {
	if h != nil {
		observe(h.WALWrite, s)
	}
}
func (h *Histograms) ObserveLLM(s float64) {
	if h != nil {
		observe(h.LLMRequest, s)
	}
}

// Sample is one labelled value read at scrape time.
type Sample struct {
	Labels []string // values, in the order of the family's label names
	Value  float64
}

// Family is a metric computed at scrape time.
type Family struct {
	Name, Help string
	Counter    bool // counter (monotonic) vs gauge
	LabelNames []string
	Read       func() []Sample
}

type familyCollector struct {
	fams  []Family
	descs []*prometheus.Desc
}

func (c *familyCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descs {
		ch <- d
	}
}

func (c *familyCollector) Collect(ch chan<- prometheus.Metric) {
	for i, f := range c.fams {
		vt := prometheus.GaugeValue
		if f.Counter {
			vt = prometheus.CounterValue
		}
		for _, s := range f.Read() {
			ch <- prometheus.MustNewConstMetric(c.descs[i], vt, s.Value, s.Labels...)
		}
	}
}

// NewRegistry returns a registry with Go runtime and process collectors,
// the given histograms, and the scrape-time families.
func NewRegistry(h *Histograms, fams []Family) *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	if h != nil {
		reg.MustRegister(h.WALFsync, h.WALWrite, h.LLMRequest)
	}
	c := &familyCollector{fams: fams}
	for _, f := range fams {
		c.descs = append(c.descs, prometheus.NewDesc(f.Name, f.Help, f.LabelNames, nil))
	}
	reg.MustRegister(c)
	return reg
}

// One returns a single unlabelled sample.
func One(v float64) []Sample { return []Sample{{Value: v}} }
