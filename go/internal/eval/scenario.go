// Package eval replays TREMOR's labelled scenarios through detectors and
// scores them with the same matching rule as the Python harness
// (eval/metrics.py), so Go and Python results are directly comparable.
package eval

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/mokshad/tremor/internal/event"
)

// Label is ground truth: Service should raise Type during [Start, End]
// (scenario-relative seconds).
type Label struct {
	Start, End float64
	Type       string
	Service    string
}

// Alert is an incident opening as eval sees it.
type Alert struct {
	TS      float64 // scenario-relative seconds
	Type    string
	Service string
}

// Scenario is one exported scenario (bench/eval/export_scenarios.py).
type Scenario struct {
	Name         string
	DurationS    float64
	StartTS      float64
	TotalLines   int
	Malformed    int
	Labels       []Label
	Events       []event.Event
	PythonAlerts map[string][]Alert // detector name -> alerts Python opened
}

// Order is the scenario order used by the Python harness and EVAL.md.
var Order = []string{"steady", "drift", "burst", "outage", "silence", "new_pattern",
	"latency_spike", "noisy_normal", "rotation", "malformed_flood"}

// LoadAll loads every scenario in Order from dir.
func LoadAll(dir string) ([]*Scenario, error) {
	var out []*Scenario
	for _, name := range Order {
		s, err := Load(filepath.Join(dir, name+".jsonl.gz"))
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Load reads one scenario file.
func Load(path string) (*Scenario, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	if !sc.Scan() {
		return nil, fmt.Errorf("%s: empty", path)
	}
	var hdr struct {
		Name         string              `json:"name"`
		DurationS    float64             `json:"duration_s"`
		StartTS      float64             `json:"start_ts"`
		TotalLines   int                 `json:"total_lines"`
		Malformed    int                 `json:"malformed"`
		Labels       [][4]any            `json:"labels"`
		PythonAlerts map[string][][3]any `json:"python_alerts"`
	}
	if err := json.Unmarshal(sc.Bytes(), &hdr); err != nil {
		return nil, fmt.Errorf("%s header: %w", path, err)
	}
	if hdr.StartTS != math.Trunc(hdr.StartTS) {
		return nil, fmt.Errorf("%s: start_ts %v is not a whole second", path, hdr.StartTS)
	}
	s := &Scenario{Name: hdr.Name, DurationS: hdr.DurationS, StartTS: hdr.StartTS,
		TotalLines: hdr.TotalLines, Malformed: hdr.Malformed, PythonAlerts: map[string][]Alert{}}
	for _, l := range hdr.Labels {
		s.Labels = append(s.Labels, Label{Start: l[0].(float64), End: l[1].(float64), Type: l[2].(string), Service: l[3].(string)})
	}
	for det, as := range hdr.PythonAlerts {
		s.PythonAlerts[det] = []Alert{} // present even when Python raised nothing
		for _, a := range as {
			s.PythonAlerts[det] = append(s.PythonAlerts[det], Alert{TS: a[0].(float64), Type: a[1].(string), Service: a[2].(string)})
		}
	}
	for sc.Scan() {
		var line [4]any
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			return nil, err
		}
		arrival := line[0].(float64)
		ns := int64(math.Round(arrival * float64(time.Second)))
		s.Events = append(s.Events, event.Event{
			Seq: uint64(len(s.Events) + 1), Service: line[1].(string), Timestamp: ns, ReceivedAt: ns,
			Level: event.ParseLevel(line[2].(string)), Message: line[3].(string),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !slices.IsSortedFunc(s.Events, func(a, b event.Event) int { return int(a.ReceivedAt - b.ReceivedAt) }) {
		return nil, fmt.Errorf("%s: arrivals not sorted", path)
	}
	return s, nil
}
