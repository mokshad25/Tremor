package eval

import (
	"os"
	"testing"

	"github.com/mokshad/tremor/internal/detect"
	"github.com/mokshad/tremor/internal/sim"
)

const scenarioDir = "../../bench/eval/scenarios"

// TestAcceptanceOnTremorScenarios is the Phase 3 acceptance check: on the
// 10 labelled TREMOR scenarios, paging alerts (WARNING+) must have 100%
// recall on ERROR_RATE anomalies with 0 false alarms per hour, and every
// detector must raise exactly the alerts the Python implementation raised.
func TestAcceptanceOnTremorScenarios(t *testing.T) {
	if _, err := os.Stat(scenarioDir); err != nil {
		t.Skip("scenarios not exported; run bench/eval/export_scenarios.py")
	}
	scenarios, err := LoadAll(scenarioDir)
	if err != nil {
		t.Fatal(err)
	}
	runs := Evaluate(scenarios, Detectors(detect.DefaultConfig()), DefaultGrace)
	for _, r := range runs {
		for _, p := range r.Parity {
			if !p.Identical() {
				t.Errorf("%s/%s differs from Python: only Go %v, only Python %v", r.Detector, p.Scenario, p.OnlyGo, p.OnlyPython)
			}
		}
		if len(r.Parity) != len(scenarios) {
			t.Errorf("%s: parity checked on %d of %d scenarios", r.Detector, len(r.Parity), len(scenarios))
		}
		if r.Detector == "TREMOR (WARNING+)" {
			er := r.ErrorRate
			if er.Recall == nil || *er.Recall != 1 || er.FPPerHour != 0 {
				t.Errorf("acceptance: ERROR_RATE recall %v, FP/hour %v", er.Recall, er.FPPerHour)
			}
			t.Logf("TREMOR (WARNING+), ERROR_RATE: recall %.0f%%, %.2f FP/hour, TP %d FP %d",
				*er.Recall*100, er.FPPerHour, er.TP, er.FP)
		}
	}
}

func TestMatchRule(t *testing.T) {
	labels := []Label{{Start: 100, End: 200, Type: "ERROR_RATE", Service: "a"}, {Start: 150, End: 300, Type: "ERROR_RATE", Service: "a"}}
	alerts := []Alert{
		{TS: 120, Type: "ERROR_RATE", Service: "a"}, // TP on label 0
		{TS: 160, Type: "ERROR_RATE", Service: "*"}, // TP on label 1 (whole stream matches)
		{TS: 170, Type: "ERROR_RATE", Service: "a"}, // duplicate
		{TS: 359, Type: "ERROR_RATE", Service: "a"}, // inside grace of label 1: duplicate
		{TS: 361, Type: "ERROR_RATE", Service: "a"}, // past grace: FP
		{TS: 130, Type: "SILENCE", Service: "a"},    // wrong type: FP
		{TS: 130, Type: "ERROR_RATE", Service: "b"}, // wrong service: FP
	}
	o := Match("x", alerts, labels, 3600, 60)
	if o.TP != 2 || o.FP != 3 || o.Dups != 2 || o.FN() != 0 || o.Delays[0] != 20 || o.Delays[1] != 10 {
		t.Fatalf("%+v", o)
	}
	r := Aggregate("d", []Outcome{o, Match("y", nil, labels[:1], 3600, 60)})
	if *r.Recall != 2.0/3 || r.FN != 1 || r.FPPerHour != 1.5 || *r.Precision != 0.4 {
		t.Fatalf("%+v", r)
	}
	if empty := Aggregate("e", []Outcome{Match("z", nil, nil, 3600, 60)}); empty.Precision != nil || empty.Recall != nil || empty.F1 != nil {
		t.Fatal("undefined metrics must be nil")
	}
}

// TestSecurityAcceptance is the Phase 5 acceptance check on the attack
// simulator: every attack type detected, no paging false alarms on
// attack-free traffic, and the NAT guards demonstrably doing work.
func TestSecurityAcceptance(t *testing.T) {
	if testing.Short() {
		t.Skip("replays 3 x 21 simulated days")
	}
	attack, clean := sim.DefaultConfig(), sim.DefaultConfig()
	clean.Attacks, clean.Seed = false, 11
	rep := EvaluateSecurity(attack, clean, detect.DefaultConfig())
	all, paging := rep.Levels[0], rep.Levels[1]
	for _, r := range all.PerType {
		if r.Detected != r.Instances {
			t.Errorf("all severities: %s detected %d/%d (missed %v)", r.Type, r.Detected, r.Instances, r.Missed)
		}
	}
	for _, r := range paging.PerType {
		if r.Type != "unusual_access" && r.Detected != r.Instances {
			t.Errorf("paging: %s detected %d/%d", r.Type, r.Detected, r.Instances)
		}
	}
	if len(paging.Clean) != 0 || paging.AttackFP != 0 {
		t.Errorf("paging false alarms: %d on attack-free traffic, %d unrelated in the attack run", len(paging.Clean), paging.AttackFP)
	}
	if len(paging.Ablation) == 0 {
		t.Error("NAT guards off produced no false alarms: the scenario no longer tests them")
	}
}
