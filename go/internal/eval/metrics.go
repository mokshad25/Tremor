package eval

import (
	"slices"
	"sort"
)

// Matching rule (identical to the Python harness, eval/metrics.py):
//   - an alert matches a label when the type and service agree (service "*"
//     matches any) and label.Start <= alert.TS <= label.End + grace;
//   - the first alert matching a still-undetected label is a true positive;
//     its delay is alert.TS - label.Start (earliest-starting fresh label wins);
//   - further alerts matching only already-detected labels are duplicates,
//     neither TP nor FP;
//   - an alert matching no label is a false positive;
//   - a label with no matching alert is a false negative.

const (
	WholeStream  = "*"
	DefaultGrace = 60.0
)

type Outcome struct {
	Scenario     string
	DurationS    float64
	Labels       int
	TP, FP, Dups int
	Delays       []float64 // one per detected label, in label order
}

func (o Outcome) Detected() int { return len(o.Delays) }
func (o Outcome) FN() int       { return o.Labels - o.Detected() }
func (o Outcome) Correct() bool { return o.FN() == 0 && o.FP == 0 }

func matches(a Alert, l Label, grace float64) bool {
	return a.Type == l.Type && (a.Service == l.Service || a.Service == WholeStream) &&
		l.Start <= a.TS && a.TS <= l.End+grace
}

// Match applies the matching rule to one scenario.
func Match(scenario string, alerts []Alert, labels []Label, durationS, grace float64) Outcome {
	sorted := slices.Clone(alerts)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].TS < sorted[j].TS })
	firstHit := map[int]float64{}
	o := Outcome{Scenario: scenario, DurationS: durationS, Labels: len(labels)}
	for _, a := range sorted {
		target := -1
		any := false
		for i, l := range labels {
			if !matches(a, l, grace) {
				continue
			}
			any = true
			if _, done := firstHit[i]; done {
				continue
			}
			if target < 0 || l.Start < labels[target].Start {
				target = i
			}
		}
		switch {
		case !any:
			o.FP++
		case target >= 0:
			firstHit[target] = a.TS - labels[target].Start
			o.TP++
		default:
			o.Dups++
		}
	}
	for i := range labels {
		if d, ok := firstHit[i]; ok {
			o.Delays = append(o.Delays, d)
		}
	}
	return o
}

// Result is the micro-averaged score of one detector over many scenarios.
type Result struct {
	Detector               string
	Precision, Recall, F1  *float64 // nil when undefined
	MeanDelay, MedianDelay *float64
	FPPerHour              float64
	TP, FP, FN, Dups       int
	Scenarios              []Outcome
}

func ptr(v float64) *float64 { return &v }

// Aggregate micro-averages outcomes.
func Aggregate(detector string, outcomes []Outcome) Result {
	r := Result{Detector: detector, Scenarios: outcomes}
	labels, detected := 0, 0
	hours := 0.0
	var delays []float64
	for _, o := range outcomes {
		r.TP += o.TP
		r.FP += o.FP
		r.FN += o.FN()
		r.Dups += o.Dups
		labels += o.Labels
		detected += o.Detected()
		delays = append(delays, o.Delays...)
		hours += o.DurationS / 3600
	}
	if r.TP+r.FP > 0 {
		r.Precision = ptr(float64(r.TP) / float64(r.TP+r.FP))
	}
	if labels > 0 {
		r.Recall = ptr(float64(detected) / float64(labels))
	}
	if r.Precision != nil && r.Recall != nil {
		if *r.Precision+*r.Recall == 0 {
			r.F1 = ptr(0)
		} else {
			r.F1 = ptr(2 * *r.Precision * *r.Recall / (*r.Precision + *r.Recall))
		}
	}
	if len(delays) > 0 {
		sum := 0.0
		for _, d := range delays {
			sum += d
		}
		r.MeanDelay = ptr(sum / float64(len(delays)))
		s := slices.Sorted(slices.Values(delays))
		if n := len(s); n%2 == 1 {
			r.MedianDelay = ptr(s[n/2])
		} else {
			r.MedianDelay = ptr((s[n/2-1] + s[n/2]) / 2)
		}
	}
	if hours > 0 {
		r.FPPerHour = float64(r.FP) / hours
	}
	return r
}

// OnlyType keeps one signal type's alerts and labels (the ERROR_RATE-only,
// apples-to-apples table).
func OnlyType(alerts []Alert, labels []Label, t string) ([]Alert, []Label) {
	var as []Alert
	for _, a := range alerts {
		if a.Type == t {
			as = append(as, a)
		}
	}
	var ls []Label
	for _, l := range labels {
		if l.Type == t {
			ls = append(ls, l)
		}
	}
	return as, ls
}
