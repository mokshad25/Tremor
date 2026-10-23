package redact

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

var labelKinds = map[string]Kind{
	"api_key": KindAPIKey, "token": KindToken, "secret": KindSecret, "username": KindUser, "email": KindEmail,
	"card": KindCard, "aadhaar": KindAadhaar, "phone": KindPhone, "pan": KindPAN, "ip": KindIP,
}

type prCounts struct{ tp, fp, fn int }

// TestPIIPrecisionRecall measures the redactor on the labelled synthetic
// set (testdata/pii_labelled.jsonl, from testdata/gen). Strict scoring: a
// label counts as found only if a finding of the SAME kind covers its whole
// value; a finding that covers no label of its kind is a false positive.
// "Leaks" are labelled values still present verbatim after redaction.
func TestPIIPrecisionRecall(t *testing.T) {
	f, err := os.Open("testdata/pii_labelled.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := New([]byte("evaluation-key-0123456789abcdef"))
	per := map[Kind]*prCounts{}
	for k := range numKinds {
		per[k] = &prCounts{}
	}
	var lines, labels, leaks int
	var fpExamples []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l struct {
			Text string
			PII  []struct{ Kind, Value string }
		}
		// The generator splices "{{fake}}" into keys/tokens/secrets on disk
		// so secret scanners skip the corpus; restore the real values.
		raw := strings.ReplaceAll(sc.Text(), "{{fake}}", "")
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			t.Fatal(err)
		}
		lines++
		out, fs := r.Redact(l.Text)
		type span struct {
			k    Kind
			a, b int
		}
		var spans []span
		for _, p := range l.PII {
			a := strings.Index(l.Text, p.Value)
			if a < 0 {
				t.Fatalf("label %q not in %q", p.Value, l.Text)
			}
			spans = append(spans, span{labelKinds[p.Kind], a, a + len(p.Value)})
			labels++
			if strings.Contains(out, p.Value) {
				leaks++
			}
		}
		for _, s := range spans {
			found := false
			for _, f := range fs {
				if f.Kind == s.k && f.Start <= s.a && f.End >= s.b {
					found = true
				}
			}
			if found {
				per[s.k].tp++
			} else {
				per[s.k].fn++
			}
		}
		for _, f := range fs {
			hit := false
			for _, s := range spans {
				if s.k == f.Kind && f.Start < s.b && s.a < f.End {
					hit = true
				}
			}
			if !hit {
				per[f.Kind].fp++
				if len(fpExamples) < 12 {
					fpExamples = append(fpExamples, fmt.Sprintf("%s %q in %q", f.Kind, l.Text[f.Start:f.End], l.Text))
				}
			}
		}
	}
	var tot prCounts
	report := []string{"| kind | precision | recall | TP | FP | FN |", "|---|---|---|---|---|---|"}
	for k := range numKinds {
		c := per[k]
		tot.tp, tot.fp, tot.fn = tot.tp+c.tp, tot.fp+c.fp, tot.fn+c.fn
		report = append(report, fmt.Sprintf("| %s | %s | %s | %d | %d | %d |", k, ratio(c.tp, c.tp+c.fp), ratio(c.tp, c.tp+c.fn), c.tp, c.fp, c.fn))
	}
	report = append(report, fmt.Sprintf("| **all** | **%s** | **%s** | %d | %d | %d |", ratio(tot.tp, tot.tp+tot.fp), ratio(tot.tp, tot.tp+tot.fn), tot.tp, tot.fp, tot.fn))
	t.Logf("%d lines, %d labelled values, %d leaked verbatim after redaction\n%s", lines, labels, leaks, strings.Join(report, "\n"))
	t.Logf("first false positives:\n  %s", strings.Join(fpExamples, "\n  "))

	// Regression guards at the measured level (2026-10-14: recall 100%,
	// precision 94.5%, 0 leaks). The remaining false positives are random
	// numeric ids that happen to pass Verhoeff/Luhn or look like a mobile
	// number; see docs/phase4-otlp-redaction.md.
	if leaks != 0 {
		t.Errorf("%d labelled values leaked", leaks)
	}
	if rec := float64(tot.tp) / float64(tot.tp+tot.fn); rec < 0.99 {
		t.Errorf("overall recall %.3f below 0.99", rec)
	}
	if prec := float64(tot.tp) / float64(tot.tp+tot.fp); prec < 0.93 {
		t.Errorf("overall precision %.3f below 0.93", prec)
	}
}

func ratio(a, b int) string {
	if b == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", float64(a)/float64(b)*100)
}
