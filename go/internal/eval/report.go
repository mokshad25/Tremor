package eval

import (
	"fmt"
	"math"
	"slices"
	"strings"
)

// Run is one detector over every scenario.
type Run struct {
	Detector  string
	Alerts    [][]Alert // per scenario, Go
	All       Result
	ErrorRate Result
	Parity    []ParityDiff // per scenario: Go vs Python alerts
}

// ParityDiff lists alerts only one implementation opened.
type ParityDiff struct {
	Scenario   string
	OnlyGo     []Alert
	OnlyPython []Alert
}

func (p ParityDiff) Identical() bool { return len(p.OnlyGo) == 0 && len(p.OnlyPython) == 0 }

// Evaluate runs every detector on every scenario.
func Evaluate(scenarios []*Scenario, detectors []Detector, grace float64) []Run {
	var runs []Run
	for _, d := range detectors {
		run := Run{Detector: d.Name}
		var all, er []Outcome
		for _, s := range scenarios {
			alerts := d.Run(s)
			run.Alerts = append(run.Alerts, alerts)
			all = append(all, Match(s.Name, alerts, s.Labels, s.DurationS, grace))
			ea, el := OnlyType(alerts, s.Labels, "ERROR_RATE")
			er = append(er, Match(s.Name, ea, el, s.DurationS, grace))
			if py, ok := s.PythonAlerts[d.Name]; ok {
				run.Parity = append(run.Parity, diff(s.Name, alerts, py))
			}
		}
		run.All, run.ErrorRate = Aggregate(d.Name, all), Aggregate(d.Name, er)
		runs = append(runs, run)
	}
	return runs
}

func key(a Alert) string { return fmt.Sprintf("%.3f|%s|%s", a.TS, a.Type, a.Service) }

func diff(scenario string, goAlerts, pyAlerts []Alert) ParityDiff {
	count := map[string]int{}
	for _, a := range pyAlerts {
		count[key(a)]++
	}
	d := ParityDiff{Scenario: scenario}
	for _, a := range goAlerts {
		if count[key(a)] > 0 {
			count[key(a)]--
		} else {
			d.OnlyGo = append(d.OnlyGo, a)
		}
	}
	for _, a := range pyAlerts {
		if count[key(a)] > 0 {
			count[key(a)]--
			d.OnlyPython = append(d.OnlyPython, a)
		}
	}
	return d
}

func fmtPct(v *float64) string {
	if v == nil || math.IsNaN(*v) {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", *v*100)
}

func fmtNum(v *float64, digits int) string {
	if v == nil || math.IsNaN(*v) {
		return "—"
	}
	return fmt.Sprintf("%.*f", digits, *v)
}

func metricTable(runs []Run, pick func(Run) Result) []string {
	names := make([]string, len(runs))
	for i, r := range runs {
		names[i] = r.Detector
	}
	rows := []struct {
		label string
		f     func(Result) string
	}{
		{"Precision", func(r Result) string { return fmtPct(r.Precision) }},
		{"Recall", func(r Result) string { return fmtPct(r.Recall) }},
		{"F1", func(r Result) string { return fmtNum(r.F1, 3) }},
		{"Mean detection delay (s)", func(r Result) string { return fmtNum(r.MeanDelay, 1) }},
		{"Median detection delay (s)", func(r Result) string { return fmtNum(r.MedianDelay, 1) }},
		{"False positives / hour", func(r Result) string { return fmt.Sprintf("%.2f", r.FPPerHour) }},
		{"TP / FP / FN / dup", func(r Result) string { return fmt.Sprintf("%d / %d / %d / %d", r.TP, r.FP, r.FN, r.Dups) }},
	}
	out := []string{"| Metric | " + strings.Join(names, " | ") + " |", "|---|" + strings.Repeat("---|", len(runs))}
	for _, row := range rows {
		cells := make([]string, len(runs))
		for i, r := range runs {
			cells[i] = row.f(pick(r))
		}
		out = append(out, "| "+row.label+" | "+strings.Join(cells, " | ")+" |")
	}
	return out
}

func scenarioCell(o Outcome) string {
	mark := "✅"
	if !o.Correct() {
		mark = "❌"
	}
	var parts []string
	if o.Labels > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d detected", o.Detected(), o.Labels))
	}
	if o.FP > 0 {
		parts = append(parts, fmt.Sprintf("%d FP", o.FP))
	}
	if len(o.Delays) > 0 {
		ds := make([]string, len(o.Delays))
		for i, d := range o.Delays {
			ds[i] = fmt.Sprintf("%.0fs", d)
		}
		parts = append(parts, "delay "+strings.Join(ds, ", "))
	}
	if len(parts) == 0 {
		return mark + " quiet"
	}
	return mark + " " + strings.Join(parts, "; ")
}

// Markdown renders the report. It is deterministic (no timestamps).
func Markdown(scenarios []*Scenario, runs []Run, grace float64, header string) string {
	lines, hours := 0, 0.0
	for _, s := range scenarios {
		lines += len(s.Events)
		hours += s.DurationS / 3600
	}
	var b strings.Builder
	w := func(s ...string) {
		for _, l := range s {
			b.WriteString(l + "\n")
		}
	}
	w(header, "", fmt.Sprintf("%d scenarios, %d parsed lines, %.2f h of simulated traffic. Matching grace: %.0f s (same rule as eval/metrics.py).", len(scenarios), lines, hours, grace), "")
	w("## Headline", "")
	for _, r := range runs {
		correct := 0
		for _, o := range r.All.Scenarios {
			if o.Correct() {
				correct++
			}
		}
		w(fmt.Sprintf("- **%s**: %d/%d scenarios fully correct; ERROR_RATE recall %s at %.2f false positives/hour; all signals F1 %s, %.2f FP/hour.",
			r.Detector, correct, len(r.All.Scenarios), fmtPct(r.ErrorRate.Recall), r.ErrorRate.FPPerHour, fmtNum(r.All.F1, 3), r.All.FPPerHour))
	}
	w("", "## ERROR_RATE only (the signal the baselines and the acceptance claim cover)", "")
	w(metricTable(runs, func(r Run) Result { return r.ErrorRate })...)
	w("", "## All signals", "")
	w(metricTable(runs, func(r Run) Result { return r.All })...)
	w("", "## Per-scenario breakdown (all signals)", "")
	names := make([]string, len(runs))
	for i, r := range runs {
		names[i] = r.Detector
	}
	w("| Scenario | Expected | "+strings.Join(names, " | ")+" |", "|---|---|"+strings.Repeat("---|", len(runs)))
	for i, s := range scenarios {
		var exp []string
		for _, l := range s.Labels {
			exp = append(exp, fmt.Sprintf("%s %s [%.0f–%.0fs]", l.Type, l.Service, l.Start, l.End))
		}
		e := strings.Join(exp, ", ")
		if e == "" {
			e = "no alerts"
		}
		cells := make([]string, len(runs))
		for j, r := range runs {
			cells[j] = scenarioCell(r.All.Scenarios[i])
		}
		w("| " + s.Name + " | " + e + " | " + strings.Join(cells, " | ") + " |")
	}
	w("", "## Parity with the Python implementation", "")
	w("Alert-by-alert comparison with the alerts Python opened on the same exported input (time, signal, service).", "")
	w("| Detector | Scenarios identical | Alerts only in Go | Alerts only in Python |", "|---|---|---|---|")
	for _, r := range runs {
		same, onlyGo, onlyPy := 0, 0, 0
		for _, p := range r.Parity {
			if p.Identical() {
				same++
			}
			onlyGo += len(p.OnlyGo)
			onlyPy += len(p.OnlyPython)
		}
		w(fmt.Sprintf("| %s | %d/%d | %d | %d |", r.Detector, same, len(r.Parity), onlyGo, onlyPy))
	}
	for _, r := range runs {
		for _, p := range r.Parity {
			if p.Identical() {
				continue
			}
			w("", fmt.Sprintf("- %s / %s: only Go %s; only Python %s", r.Detector, p.Scenario, fmtAlerts(p.OnlyGo), fmtAlerts(p.OnlyPython)))
		}
	}
	return b.String()
}

func fmtAlerts(as []Alert) string {
	if len(as) == 0 {
		return "none"
	}
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = fmt.Sprintf("%s %s @%.0fs", a.Type, a.Service, a.TS)
	}
	slices.Sort(s)
	return strings.Join(s, ", ")
}
