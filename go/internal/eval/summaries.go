package eval

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mokshad/tremor/internal/detect"
	"github.com/mokshad/tremor/internal/drain"
	"github.com/mokshad/tremor/internal/redact"
	"github.com/mokshad/tremor/internal/sim"
	"github.com/mokshad/tremor/internal/summarize"
)

// scenarioTruth describes what each TREMOR scenario injects, for the
// scoring sheet (from simulator/scenarios.py).
var scenarioTruth = map[string]string{
	"steady":          "nothing (normal traffic)",
	"drift":           "payment-gateway error rate drifts from 2% to 15% (gradual degradation)",
	"burst":           "payment-gateway errors jump to 80% for 30 s",
	"outage":          "ledger outage: 95% errors, a new 'connection refused to ledger-db' template, volume down to 30%",
	"silence":         "payment-gateway stops logging for 60 s",
	"new_pattern":     "auth-service starts logging a new 'HSM key rotation failed' warning at 2/s",
	"latency_spike":   "payment-gateway latency x15 (200 ms to ~3 s)",
	"noisy_normal":    "nothing (low-volume service with a steady 3% error rate)",
	"rotation":        "nothing (log file rotated twice)",
	"malformed_flood": "nothing (50% malformed lines)",
}

var attackTruth = map[string]string{
	"brute_force/sshd":                  "SSH password brute force from one IP against one account (some end in a successful login)",
	"brute_force/app":                   "app login brute force from one IP against one employee",
	"credential_stuffing/single_source": "credential stuffing: one IP trying many leaked usernames once each",
	"credential_stuffing/distributed":   "distributed (low and slow) credential stuffing: hundreds of IPs, hundreds of usernames, over an hour",
	"privilege_change/sudo":             "an employee who never used sudo runs sudo to a root shell",
	"privilege_change/role_admin":       "a role admin who only granted viewer/editor grants the admin role",
	"privilege_change/group_wheel":      "an admin outside the role team adds a user to the wheel group",
	"unusual_access/new_source":         "a known user logs in from an address never seen for them",
	"unusual_access/unusual_hour":       "a known user logs in at an hour they never use",
	"unusual_access/takeover":           "account takeover shape: new address and unusual hour together",
}

// SummaryRecord is one saved summary.
type SummaryRecord struct {
	Group            string            `json:"group"` // "tremor" | "attacks"
	Scenario         string            `json:"scenario"`
	IncidentID       string            `json:"incident_id"`
	Severity         string            `json:"severity"`
	Services         []string          `json:"services"`
	Alerts           int               `json:"alerts"`
	ExpectedServices []string          `json:"expected_services"`
	ExpectedTrigger  string            `json:"expected_trigger"`
	Input            summarize.Input   `json:"llm_input"` // exactly what the model saw (before the scrub pass)
	Summary          summarize.Summary `json:"summary"`
}

// replayIncidents runs events through the production processor and the
// correlator and returns every closed incident.
func replayIncidents(feed func(p *detect.Processor), cfg detect.Config, origin int64, end int64) []summarize.Incident {
	corr := summarize.NewCorrelator(summarize.DefaultCorrelatorConfig())
	var incidents []summarize.Incident
	collect := func(evs []summarize.Event) {
		for _, e := range evs {
			if e.Type == "closed" {
				incidents = append(incidents, e.Incident)
			}
		}
	}
	p := detect.NewProcessor(cfg, drain.TremorConfig(), func(a detect.Alert) {
		if a.Status == detect.StatusNotice {
			corr.Notice(a)
			return
		}
		collect(corr.Add(a))
	})
	p.SetOrigin(origin)
	feed(p)
	p.TickBefore((end + 1) * int64(time.Second))
	collect(corr.Expire(end + 3600))
	collect(corr.CloseAll())
	return incidents
}

// summarizeAll summarizes paging incidents with g, pacing calls and
// retrying transient failures once.
func summarizeAll(ctx context.Context, g *summarize.Guarded, incs []summarize.Incident, pace time.Duration, log func(string)) []summarize.Summary {
	out := make([]summarize.Summary, len(incs))
	for i, in := range incs {
		var s summarize.Summary
		for attempt := range 3 {
			s, _ = g.Summarize(ctx, in)
			if s.Source == "llm" || s.FallbackReason == "llm_disabled" || s.FallbackReason == "invalid_output" {
				break
			}
			time.Sleep(pace * time.Duration(4*(attempt+1))) // transient: back off and retry
		}
		out[i] = s
		log(fmt.Sprintf("  %s %s %v: %s%s", in.ID, in.Severity, in.Services, s.Source, map[bool]string{true: " (" + s.FallbackReason + ")", false: ""}[s.FallbackReason != ""]))
		if g.LLM != nil {
			time.Sleep(pace)
		}
	}
	return out
}

// GenerateSummaries replays the 10 TREMOR scenarios and the attack
// simulator, summarizes every paging incident, and writes JSON files plus a
// scoring sheet into dir.
func GenerateSummaries(ctx context.Context, dir, scenarioDir string, g *summarize.Guarded, log func(string)) error {
	cfg := detect.DefaultConfig()
	var records []SummaryRecord
	noIncident := map[string]bool{}

	scenarios, err := LoadAll(scenarioDir)
	if err != nil {
		return err
	}
	for _, s := range scenarios {
		start := int64(s.StartTS)
		incs := replayIncidents(func(p *detect.Processor) {
			for i := range s.Events {
				p.Process(&s.Events[i])
			}
		}, cfg, start, start+int64(s.DurationS))
		incs = paging(incs)
		log(fmt.Sprintf("%s: %d paging incident(s)", s.Name, len(incs)))
		if len(incs) == 0 {
			noIncident[s.Name] = true
			continue
		}
		var exp []string
		for _, l := range s.Labels {
			if !slices.Contains(exp, l.Service) {
				exp = append(exp, l.Service)
			}
		}
		for i, sum := range summarizeAll(ctx, g, incs, 2500*time.Millisecond, log) {
			records = append(records, record("tremor", s.Name, incs[i], exp, scenarioTruth[s.Name], sum))
		}
	}

	attack := sim.DefaultConfig()
	lines, labels := sim.Generate(attack)
	red := redact.New(EvalKey)
	incs := paging(replayIncidents(func(p *detect.Processor) {
		feedSim(p, lines, red)
	}, cfg, attack.Start.Unix(), attack.Start.AddDate(0, 0, attack.Days).Unix()))
	log(fmt.Sprintf("attack simulator: %d paging incident(s)", len(incs)))
	sums := summarizeAll(ctx, g, incs, 2500*time.Millisecond, log)
	for i, in := range incs {
		name, exp, truth := "unlabelled", []string(nil), "no injected attack overlaps this incident"
		for _, l := range labels {
			if in.OpenedAt <= l.End.Unix()+300 && in.UpdatedAt >= l.Start.Unix() && slices.Contains(in.Services, l.Service) {
				name, exp, truth = l.Type+"/"+l.Variant+" @ "+l.Start.Format("01-02 15:04"), []string{l.Service}, attackTruth[l.Type+"/"+l.Variant]
				break
			}
		}
		records = append(records, record("attacks", name, in, exp, truth, sums[i]))
	}
	return writeSummaries(dir, records, noIncident)
}

func paging(incs []summarize.Incident) []summarize.Incident {
	var out []summarize.Incident
	for _, in := range incs {
		if summarize.SeverityAtLeast(in.Severity, "WARNING") {
			out = append(out, in)
		}
	}
	return out
}

func feedSim(p *detect.Processor, lines []sim.Line, red *redact.Redactor) {
	for i, l := range lines {
		ev := simEvent(i, l)
		red.Event(&ev)
		p.Process(&ev)
	}
}

func record(group, scenario string, in summarize.Incident, exp []string, truth string, s summarize.Summary) SummaryRecord {
	return SummaryRecord{Group: group, Scenario: scenario, IncidentID: in.ID, Severity: in.Severity, Services: in.Services,
		Alerts: len(in.Alerts), ExpectedServices: exp, ExpectedTrigger: truth, Input: summarize.BuildInput(in), Summary: s}
}

func writeSummaries(dir string, recs []SummaryRecord, noIncident map[string]bool) error {
	for _, g := range []string{"tremor", "attacks"} {
		if err := os.MkdirAll(filepath.Join(dir, g), 0o755); err != nil {
			return err
		}
	}
	csvF, err := os.Create(filepath.Join(dir, "scoring-sheet.csv"))
	if err != nil {
		return err
	}
	defer csvF.Close()
	cw := csv.NewWriter(csvF)
	cw.Write([]string{"file", "scenario", "expected_services", "expected_trigger", "summary_source", "affected_services",
		"likely_trigger", "auto_service_named", "right_service (Y/N)", "right_trigger (Y/N)", "notes"})
	var md strings.Builder
	md.WriteString("# Incident summary scoring sheet\n\n")
	md.WriteString("Fill in **Right service?** and **Right trigger?** (Y/N) for each row; `auto` is a mechanical check (an expected service appears in `affected_services`), not a judgement of the text. Each row's file has the full model input and output.\n\n")
	md.WriteString("Scenarios with no paging incident (expected for normal traffic): ")
	var none []string
	for _, s := range Order {
		if noIncident[s] {
			none = append(none, s)
		}
	}
	md.WriteString(strings.Join(none, ", ") + ".\n\n")
	md.WriteString("| # | file | scenario | expected | summary source | likely trigger (model) | auto | Right service? | Right trigger? |\n|---|---|---|---|---|---|---|---|---|\n")
	for i, r := range recs {
		file := fmt.Sprintf("%s/%02d-%s.json", r.Group, i+1, strings.NewReplacer("/", "_", " ", "_", "@", "", ":", "").Replace(r.Scenario))
		b, _ := json.MarshalIndent(r, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, file), append(b, '\n'), 0o644); err != nil {
			return err
		}
		auto := "no"
		for _, e := range r.ExpectedServices {
			if slices.Contains(r.Summary.AffectedServices, e) {
				auto = "yes"
			}
		}
		if len(r.ExpectedServices) == 0 {
			auto = "n/a"
		}
		src := r.Summary.Source
		if r.Summary.FallbackReason != "" {
			src += " (" + r.Summary.FallbackReason + ")"
		}
		cw.Write([]string{file, r.Scenario, strings.Join(r.ExpectedServices, " "), r.ExpectedTrigger, src,
			strings.Join(r.Summary.AffectedServices, " "), r.Summary.LikelyTrigger, auto, "", "", ""})
		trig := strings.ReplaceAll(r.Summary.LikelyTrigger, "|", "/")
		if len(trig) > 160 {
			trig = trig[:157] + "..."
		}
		fmt.Fprintf(&md, "| %d | `%s` | %s | %s: %s | %s | %s | %s |  |  |\n", i+1, file, r.Scenario,
			strings.Join(r.ExpectedServices, ", "), r.ExpectedTrigger, src, trig, auto)
	}
	cw.Flush()
	return os.WriteFile(filepath.Join(dir, "scoring-sheet.md"), []byte(md.String()), 0o644)
}
