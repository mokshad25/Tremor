package eval

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/mokshad/tremor/internal/detect"
	"github.com/mokshad/tremor/internal/drain"
	"github.com/mokshad/tremor/internal/event"
	"github.com/mokshad/tremor/internal/redact"
	"github.com/mokshad/tremor/internal/sim"
)

// EvalKey is the HMAC key used for evaluation runs.
var EvalKey = []byte("security-eval-key-0123456789abcdef")

var labelSignal = map[string]detect.SignalType{
	"brute_force":         detect.SignalBruteForce,
	"credential_stuffing": detect.SignalCredentialStuffing,
	"privilege_change":    detect.SignalPrivilegeChange,
	"unusual_access":      detect.SignalUnusualAccess,
}

func isSecurity(t detect.SignalType) bool {
	switch t {
	case detect.SignalBruteForce, detect.SignalCredentialStuffing, detect.SignalPrivilegeChange, detect.SignalUnusualAccess:
		return true
	}
	return false
}

// RunSecurityLines redacts lines with the evaluation key and replays them
// through the production shard processor (Drain + baselines + security
// rules), returning every security alert.
func RunSecurityLines(lines []sim.Line, start time.Time, end time.Time, cfg detect.Config, allowedRaw []string) ([]detect.Alert, *redact.Redactor) {
	red := redact.New(EvalKey)
	var alerts []detect.Alert
	p := detect.NewProcessor(cfg, drain.TremorConfig(), func(a detect.Alert) {
		if isSecurity(a.Type) {
			alerts = append(alerts, a)
		}
	})
	allowed := map[string]bool{}
	for _, ip := range allowedRaw {
		allowed[red.Pseudonym(redact.KindIP, ip)] = true
	}
	p.SetAllowedSources(allowed)
	p.SetOrigin(start.Unix())
	feedSim(p, lines, red)
	p.TickBefore(end.Add(time.Second).UnixNano())
	return alerts, red
}

// TypeResult is the detection score for one attack type.
type TypeResult struct {
	Type      string
	Instances int
	Detected  int
	Delays    []float64 // seconds from attack start to first matching alert
	Missed    []string  // descriptions of missed instances
}

// Scores is one scoring of the alerts at a minimum severity.
type Scores struct {
	Level        string
	PerType      []*TypeResult
	PerVariant   map[string][2]int // variant -> detected, instances
	AttackAlerts int
	AttackFP     int // alerts in the attack run unrelated to any attack
	Clean        []detect.Alert
	Ablation     []detect.Alert // attack-free run with the NAT guards off
}

// SecurityReport scores the attack and attack-free runs at two levels: all
// alerts, and paging alerts (WARNING and above).
type SecurityReport struct {
	Levels      []Scores
	AttackHours float64
	CleanHours  float64
}

var sevRank = map[string]detect.Severity{"INFO": detect.SevInfo, "WARNING": detect.SevWarning, "HIGH": detect.SevHigh, "CRITICAL": detect.SevCritical}

func atLeast(alerts []detect.Alert, min detect.Severity) []detect.Alert {
	var out []detect.Alert
	for _, a := range alerts {
		if sevRank[a.Severity] >= min {
			out = append(out, a)
		}
	}
	return out
}

const securityGrace = 5 * time.Minute

func secMatches(a detect.Alert, l sim.Label, red *redact.Redactor, anyType bool) bool {
	if !anyType && a.Type != labelSignal[l.Type] {
		return false
	}
	if a.Service != l.Service {
		return false
	}
	t := time.Unix(a.UpdatedAt, 0)
	if t.Before(l.Start.Add(-time.Second)) || t.After(l.End.Add(securityGrace)) {
		return false
	}
	u, s := "", ""
	if l.User != "" {
		u = red.Pseudonym(redact.KindUser, l.User)
	}
	if l.Source != "" {
		s = red.Pseudonym(redact.KindIP, l.Source)
	}
	switch {
	case u == "" && s == "":
		return true // distributed: no single key
	case u != "" && s != "":
		return a.User == u || a.Source == s
	case u != "":
		return a.User == u
	default:
		return a.Source == s
	}
}

// ScoreSecurity matches alerts to labels.
func ScoreSecurity(alerts []detect.Alert, labels []sim.Label, red *redact.Redactor) ([]*TypeResult, map[string][2]int, int) {
	byType := map[string]*TypeResult{}
	variants := map[string][2]int{}
	for _, l := range labels {
		r := byType[l.Type]
		if r == nil {
			r = &TypeResult{Type: l.Type}
			byType[l.Type] = r
		}
		r.Instances++
		v := variants[l.Type+"/"+l.Variant]
		v[1]++
		first := -1.0
		for _, a := range alerts {
			if secMatches(a, l, red, false) {
				d := float64(a.UpdatedAt) - float64(l.Start.Unix())
				if first < 0 || d < first {
					first = d
				}
			}
		}
		if first >= 0 {
			r.Detected++
			r.Delays = append(r.Delays, first)
			v[0]++
		} else {
			r.Missed = append(r.Missed, fmt.Sprintf("%s/%s at %s", l.Type, l.Variant, l.Start.Format(time.DateTime)))
		}
		variants[l.Type+"/"+l.Variant] = v
	}
	fp := 0
	for _, a := range alerts {
		related := false
		for _, l := range labels {
			if secMatches(a, l, red, true) {
				related = true // e.g. the unusual-access alert a successful brute force also causes
				break
			}
		}
		if !related {
			fp++
		}
	}
	var out []*TypeResult
	for _, t := range []string{"brute_force", "credential_stuffing", "privilege_change", "unusual_access"} {
		if r := byType[t]; r != nil {
			out = append(out, r)
		}
	}
	return out, variants, fp
}

// EvaluateSecurity runs the attack scenario, an attack-free scenario, and
// the attack-free scenario again with the NAT guards disabled.
func EvaluateSecurity(attack, clean sim.Config, cfg detect.Config) SecurityReport {
	lines, labels := sim.Generate(attack)
	alerts, red := RunSecurityLines(lines, attack.Start, attack.Start.AddDate(0, 0, attack.Days), cfg, nil)
	cl, _ := sim.Generate(clean)
	cend := clean.Start.AddDate(0, 0, clean.Days)
	cleanAlerts, _ := RunSecurityLines(cl, clean.Start, cend, cfg, nil)
	off := cfg
	off.Security.StuffingMinFailureRatio = 0
	off.Security.DistributedMinSources = 0
	ablation, _ := RunSecurityLines(cl, clean.Start, cend, off, nil)

	rep := SecurityReport{AttackHours: float64(attack.Days) * 24, CleanHours: float64(clean.Days) * 24}
	for _, lv := range []struct {
		name string
		min  detect.Severity
	}{{"all severities", detect.SevInfo}, {"paging (WARNING and above)", detect.SevWarning}} {
		a := atLeast(alerts, lv.min)
		sc := Scores{Level: lv.name, AttackAlerts: len(a), Clean: atLeast(cleanAlerts, lv.min), Ablation: atLeast(ablation, lv.min)}
		sc.PerType, sc.PerVariant, sc.AttackFP = ScoreSecurity(a, labels, red)
		rep.Levels = append(rep.Levels, sc)
	}
	return rep
}

// SecurityMarkdown renders the report.
func SecurityMarkdown(rep SecurityReport, attack, clean sim.Config) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("Attack scenario: %d days, seed %d, %d employees (%d behind one office NAT), %d admins, attacks from day %d (the first %d days are learning). Attack-free scenario: %d days, seed %d, same population and behaviour: a daily 09:00 IST login rush through the NAT, a weekly password-rotation day with 25%% typos, and employees occasionally logging in from brand-new addresses (travel, new ISP).",
		attack.Days, attack.Seed, attack.Employees, attack.NATEmployees, attack.Admins, attack.AttackFromDay, attack.AttackFromDay, clean.Days, clean.Seed)
	w("")
	w("Matching: same type and service, same tokenized user or source, alert between attack start and end + %s.", securityGrace)
	for _, sc := range rep.Levels {
		w("")
		w("## Counting %s", sc.Level)
		w("")
		w("| attack type | detected | rate | median delay (s) | max delay (s) |")
		w("|---|---|---|---|---|")
		tot, det := 0, 0
		for _, r := range sc.PerType {
			tot += r.Instances
			det += r.Detected
			med, mx := "—", "—"
			if len(r.Delays) > 0 {
				d := slices.Sorted(slices.Values(r.Delays))
				med, mx = fmt.Sprintf("%.0f", d[len(d)/2]), fmt.Sprintf("%.0f", d[len(d)-1])
			}
			w("| %s | %d/%d | %.0f%% | %s | %s |", r.Type, r.Detected, r.Instances, 100*float64(r.Detected)/float64(r.Instances), med, mx)
		}
		w("| **all** | **%d/%d** | **%.0f%%** | | |", det, tot, 100*float64(det)/float64(tot))
		w("")
		w("By variant: %s", fmtVariants(sc.PerVariant))
		w("")
		w("| false alarms | count | per hour |")
		w("|---|---|---|")
		w("| attack-free run (%.0f h) | %d | %.3f |", rep.CleanHours, len(sc.Clean), float64(len(sc.Clean))/rep.CleanHours)
		w("| attack-free run, NAT guards off | %d | %.3f |", len(sc.Ablation), float64(len(sc.Ablation))/rep.CleanHours)
		w("| attack run, alerts unrelated to any attack (%.0f h) | %d | %.3f |", rep.AttackHours, sc.AttackFP, float64(sc.AttackFP)/rep.AttackHours)
		w("")
		w("False alarms on attack-free traffic by type: %s; with the NAT guards off: %s.", countTypes(sc.Clean), countTypes(sc.Ablation))
		for _, r := range sc.PerType {
			for _, m := range r.Missed {
				w("- missed: %s", m)
			}
		}
	}
	return b.String()
}

func countTypes(as []detect.Alert) string {
	c := map[string]int{}
	for _, a := range as {
		c[string(a.Type)+"/"+a.Severity]++
	}
	if len(c) == 0 {
		return "none"
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(c)) {
		parts = append(parts, fmt.Sprintf("%s %d", k, c[k]))
	}
	return strings.Join(parts, ", ")
}

func fmtVariants(v map[string][2]int) string {
	var parts []string
	for _, k := range slices.Sorted(func(yield func(string) bool) {
		for k := range v {
			if !yield(k) {
				return
			}
		}
	}) {
		parts = append(parts, fmt.Sprintf("%s %d/%d", k, v[k][0], v[k][1]))
	}
	return strings.Join(parts, ", ")
}

// simEvent turns a simulator line into an event arriving at its timestamp.
func simEvent(i int, l sim.Line) event.Event {
	ns := l.TS.UnixNano()
	return event.Event{Seq: uint64(i + 1), Service: l.Service, Timestamp: ns, ReceivedAt: ns,
		Level: event.ParseLevel(l.Level), Message: l.Message}
}
