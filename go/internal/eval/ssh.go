package eval

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mokshad/tremor/internal/detect"
	"github.com/mokshad/tremor/internal/redact"
	"github.com/mokshad/tremor/internal/sim"
)

// failedRE is used only for the independent cross-check, never by the rules.
var failedRE = regexp.MustCompile(`Failed (?:password|none|publickey) for (?:invalid user )?\S+ from (\d+\.\d+\.\d+\.\d+)`)

// SSHReplayReport summarises a replay of real sshd logs (no labels exist).
func SSHReplayReport(name string, lines []sim.Line, skipped int, cfg detect.Config) string {
	if len(lines) == 0 {
		return "no lines parsed\n"
	}
	start := lines[0].TS.Truncate(24 * time.Hour)
	end := lines[len(lines)-1].TS.Add(time.Minute)
	// Real logs can be slightly out of order; the replay clock needs order.
	slices.SortStableFunc(lines, func(a, b sim.Line) int { return a.TS.Compare(b.TS) })
	alerts, red := RunSecurityLines(lines, start, end, cfg, nil)

	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	span := lines[len(lines)-1].TS.Sub(lines[0].TS)
	w("Replayed %s: %d lines (%d unparseable), %s of log time (%s to %s).", name, len(lines), skipped,
		span.Round(time.Minute), lines[0].TS.Format(time.DateTime), lines[len(lines)-1].TS.Format(time.DateTime))
	w("")
	byType := map[string]int{}
	sources := map[string]map[detect.SignalType]bool{}
	for _, a := range alerts {
		byType[string(a.Type)+" "+a.Severity]++
		if a.Source != "" {
			if sources[a.Source] == nil {
				sources[a.Source] = map[detect.SignalType]bool{}
			}
			sources[a.Source][a.Type] = true
		}
	}
	w("| alert type / severity | count |")
	w("|---|---|")
	for _, k := range slices.Sorted(maps.Keys(byType)) {
		w("| %s | %d |", k, byType[k])
	}
	w("")
	w("Distinct (tokenized) sources alerted on: %d.", len(sources))

	// Independent cross-check from the raw text (not ground truth): IPs with
	// >= threshold failed attempts inside any brute-force window.
	thr, win := cfg.Security.BruteForceThreshold, time.Duration(cfg.Security.BruteForceWindowS)*time.Second
	fails := map[string][]time.Time{}
	for _, l := range lines {
		if m := failedRE.FindStringSubmatch(l.Message); m != nil {
			fails[m[1]] = append(fails[m[1]], l.TS)
		}
	}
	heavy, covered := 0, 0
	var missed []string
	for ip, ts := range fails {
		hit := false
		for i := range ts {
			j := i
			for j < len(ts) && ts[j].Sub(ts[i]) < win {
				j++
			}
			if j-i >= thr {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		heavy++
		if len(sources[red.Pseudonym(redact.KindIP, ip)]) > 0 {
			covered++
		} else {
			missed = append(missed, ip)
		}
	}
	w("")
	w("Cross-check (heuristic, not ground truth): %d source IPs have >= %d failed attempts within %s in the raw log; TREMOR raised a brute-force or stuffing alert for %d of them.", heavy, thr, win, covered)
	if len(missed) > 0 {
		slices.Sort(missed)
		w("Not alerted: %s", strings.Join(missed, ", "))
	}
	w("")
	w("Examples:")
	shown := map[detect.SignalType]int{}
	for _, a := range alerts {
		if shown[a.Type] < 2 {
			shown[a.Type]++
			w("- %s %s %s [%s] user=%s source=%s: %s", time.Unix(a.UpdatedAt, 0).UTC().Format(time.DateTime), a.Type, a.Severity,
				strings.Join(a.Techniques, ","), a.User, a.Source, a.Reason)
		}
	}
	return b.String()
}
