package summarize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/mokshad/tremor/internal/detect"
)

// Summary is the explanation attached to an incident notification. Its
// content is never read back by the system: it cannot open, suppress, close
// or re-rank anything.
type Summary struct {
	Summary            string   `json:"summary"`
	LikelyTrigger      string   `json:"likely_trigger"`
	AffectedServices   []string `json:"affected_services"`
	SuggestedNextCheck string   `json:"suggested_next_check"`
	CitedAlertIDs      []string `json:"cited_alert_ids"`

	// Provenance, not produced by the model.
	Source           string `json:"source"`                    // "llm" or "template"
	Model            string `json:"model,omitempty"`           // when Source is "llm"
	FallbackReason   string `json:"fallback_reason,omitempty"` // why the template was used
	PromptTokens     int    `json:"prompt_tokens,omitempty"`
	CompletionTokens int    `json:"completion_tokens,omitempty"`
}

// Summarizer explains an incident. Implementations must only see redacted
// data; Input builds that view.
type Summarizer interface {
	Summarize(ctx context.Context, in Incident) (Summary, error)
}

// ── what the model is shown ──────────────────────────────────────────

// InputAlert is one alert as the model sees it: redacted fields only (users
// and sources are already HMAC tokens), no WAL bytes, no raw log lines.
type InputAlert struct {
	ID            string   `json:"id"`
	Type          string   `json:"type"`
	Status        string   `json:"status"`
	Severity      string   `json:"severity"`
	Service       string   `json:"service"`
	At            string   `json:"at"`
	Reason        string   `json:"reason"`
	Observed      *float64 `json:"observed,omitempty"`
	ObservedIs    string   `json:"observed_is,omitempty"` // what "observed" counts, for security rules
	Baseline      *float64 `json:"baseline,omitempty"`    // anomalies: the learned normal value
	Threshold     *float64 `json:"threshold,omitempty"`   // security rules: the configured trigger level
	Z             *float64 `json:"z_score,omitempty"`
	Lines         int      `json:"lines_in_window,omitempty"`
	Errors        int      `json:"errors_in_window,omitempty"`
	WindowSeconds int64    `json:"window_seconds,omitempty"`
	MitreAttack   []string `json:"mitre_attack,omitempty"`
	User          string   `json:"user,omitempty"`
	Source        string   `json:"source,omitempty"`
}

// InputTemplate is a log template that stood out, with its count.
type InputTemplate struct {
	Service  string `json:"service"`
	Template string `json:"template"`
	Count    int    `json:"error_lines_in_window"`
}

// Input is the whole prompt payload.
type Input struct {
	IncidentID string          `json:"incident_id"`
	Kind       string          `json:"kind"`
	OpenedAt   string          `json:"opened_at"`
	Severity   string          `json:"severity"`
	Services   []string        `json:"services"`
	Alerts     []InputAlert    `json:"alerts"`
	Templates  []InputTemplate `json:"top_error_templates,omitempty"`
	Deploys    []string        `json:"recent_deploys,omitempty"`
	Omitted    int             `json:"alerts_omitted,omitempty"`
}

// maxInputAlerts keeps prompts small; the rest are counted, not sent.
const maxInputAlerts = 40

// BuildInput turns an incident into the model's view of it.
func BuildInput(in Incident) Input {
	x := Input{IncidentID: in.ID, Kind: string(in.Kind), OpenedAt: unixTime(in.OpenedAt), Severity: in.Severity,
		Services: in.Services, Omitted: in.Truncated}
	seenT := map[string]bool{}
	for i, a := range in.Alerts {
		if i >= maxInputAlerts {
			x.Omitted += len(in.Alerts) - maxInputAlerts
			break
		}
		ia := InputAlert{
			ID: a.ID, Type: string(a.Type), Status: string(a.Status), Severity: a.Severity, Service: a.Service,
			At: unixTime(a.UpdatedAt), Reason: a.Reason, Observed: a.Value, Baseline: a.Baseline, Z: a.Z,
			Lines: a.Lines, Errors: a.Errors, WindowSeconds: a.WindowEnd - a.WindowStart,
			MitreAttack: a.Techniques, User: a.User, Source: a.Source,
		}
		if kindOf(a.Type) == KindSecurity {
			// A rule's "baseline" is its threshold (or history size), not a
			// learned normal value: name it so the model does not say "at
			// baseline" about an attack.
			ia.Threshold, ia.Baseline = a.Baseline, nil
			ia.ObservedIs, ia.Threshold = observedMeaning(a)
		}
		x.Alerts = append(x.Alerts, ia)
		if a.TopErrorTemplateText != "" && !seenT[a.Service+a.TopErrorTemplateText] {
			seenT[a.Service+a.TopErrorTemplateText] = true
			x.Templates = append(x.Templates, InputTemplate{a.Service, a.TopErrorTemplateText, a.TopErrorTemplateCount})
		}
	}
	for _, d := range in.Deploys {
		x.Deploys = append(x.Deploys, fmt.Sprintf("%s %s: %s", unixTime(d.UpdatedAt), d.Service, d.Reason))
	}
	return x
}

// ── validation ───────────────────────────────────────────────────────

const maxField = 800

// ErrInvalidSummary wraps every reason a model's output is rejected.
var ErrInvalidSummary = errors.New("invalid summary")

// Validate checks a model's output against the incident: every field
// present and bounded, affected services a subset of the incident's, and
// every cited alert ID one of the incident's alerts. A summary that cites
// an alert that does not exist is rejected whole: a fabricated citation
// means the rest cannot be trusted either.
func Validate(s Summary, in Incident) error {
	for name, v := range map[string]string{"summary": s.Summary, "likely_trigger": s.LikelyTrigger, "suggested_next_check": s.SuggestedNextCheck} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%w: %s is empty", ErrInvalidSummary, name)
		}
		if len(v) > maxField {
			return fmt.Errorf("%w: %s longer than %d characters", ErrInvalidSummary, name, maxField)
		}
	}
	if len(s.AffectedServices) == 0 {
		return fmt.Errorf("%w: affected_services is empty", ErrInvalidSummary)
	}
	for _, svc := range s.AffectedServices {
		if !slices.Contains(in.Services, svc) {
			return fmt.Errorf("%w: affected service %q is not in the incident", ErrInvalidSummary, svc)
		}
	}
	if len(s.CitedAlertIDs) == 0 {
		return fmt.Errorf("%w: no cited_alert_ids", ErrInvalidSummary)
	}
	ids := in.AlertIDs()
	for _, id := range s.CitedAlertIDs {
		if !slices.Contains(ids, id) {
			return fmt.Errorf("%w: cited alert %q is not in the incident", ErrInvalidSummary, id)
		}
	}
	return nil
}

// ParseSummary decodes the model's JSON strictly: unknown fields are
// rejected so the schema cannot silently drift.
func ParseSummary(content string) (Summary, error) {
	dec := json.NewDecoder(strings.NewReader(content))
	dec.DisallowUnknownFields()
	var s struct {
		Summary            string   `json:"summary"`
		LikelyTrigger      string   `json:"likely_trigger"`
		AffectedServices   []string `json:"affected_services"`
		SuggestedNextCheck string   `json:"suggested_next_check"`
		CitedAlertIDs      []string `json:"cited_alert_ids"`
	}
	if err := dec.Decode(&s); err != nil {
		return Summary{}, fmt.Errorf("%w: not the expected JSON object: %v", ErrInvalidSummary, err)
	}
	return Summary{Summary: s.Summary, LikelyTrigger: s.LikelyTrigger, AffectedServices: s.AffectedServices,
		SuggestedNextCheck: s.SuggestedNextCheck, CitedAlertIDs: s.CitedAlertIDs}, nil
}

// ── deterministic fallback ───────────────────────────────────────────

// Template writes a summary from the alerts alone, with no model. It is used
// whenever the LLM is disabled, unavailable, slow, rate-limited or returns
// something invalid, and as the immediate summary on the first page.
type Template struct{}

var nextChecks = map[string]string{
	"ERROR_RATE":          "Check the top error template's recent occurrences and the service's dependencies; compare with any deploy in the incident.",
	"SILENCE":             "Check whether the service is running and its log shipping is healthy (agent, collector, network).",
	"NEW_PATTERN":         "Look at the first occurrences of the new template and what changed just before it appeared.",
	"LATENCY":             "Check the slowest dependency and resource saturation (CPU, connection pools) for the service.",
	"BRUTE_FORCE":         "Block or rate-limit the source, check whether any login from it succeeded, and force a password reset if one did.",
	"CREDENTIAL_STUFFING": "Rate-limit or challenge the sources, check which accounts logged in successfully during the window, and reset those.",
	"PRIVILEGE_CHANGE":    "Confirm with the actor that the change was intended; review what was run or granted and revert if not.",
	"UNUSUAL_ACCESS":      "Confirm the login with the user; if they did not make it, revoke sessions and reset credentials.",
}

func (Template) Summarize(_ context.Context, in Incident) (Summary, error) {
	if len(in.Alerts) == 0 {
		return Summary{}, errors.New("incident has no alerts")
	}
	// The most severe, then earliest, alert drives the text.
	lead := in.Alerts[0]
	for _, a := range in.Alerts[1:] {
		if sevRank[a.Severity] > sevRank[lead.Severity] {
			lead = a
		}
	}
	types := map[string]int{}
	for _, a := range in.Alerts {
		if a.Status != "RESOLVED" {
			types[string(a.Type)]++
		}
	}
	var parts []string
	for _, t := range slices.Sorted(func(yield func(string) bool) {
		for t := range types {
			if !yield(t) {
				return
			}
		}
	}) {
		parts = append(parts, fmt.Sprintf("%d %s", types[t], t))
	}
	trigger := fmt.Sprintf("%s on %s: %s", lead.Type, lead.Service, lead.Reason)
	if lead.TopErrorTemplateText != "" {
		trigger += fmt.Sprintf(" (top error: %q, %d lines)", lead.TopErrorTemplateText, lead.TopErrorTemplateCount)
	}
	if len(lead.Techniques) > 0 {
		trigger += " [ATT&CK " + strings.Join(lead.Techniques, ", ") + "]"
	}
	if len(in.Deploys) > 0 {
		trigger += "; deploy before the incident: " + in.Deploys[len(in.Deploys)-1].Reason
	}
	s := Summary{
		Summary: fmt.Sprintf("%s %s incident on %s since %s: %s.", in.Severity, in.Kind, strings.Join(in.Services, ", "),
			unixTime(in.OpenedAt), strings.Join(parts, ", ")),
		LikelyTrigger:      trigger,
		AffectedServices:   slices.Clone(in.Services),
		SuggestedNextCheck: nextChecks[string(lead.Type)],
		CitedAlertIDs:      []string{lead.ID},
		Source:             "template",
	}
	if s.SuggestedNextCheck == "" {
		s.SuggestedNextCheck = "Review the cited alerts and the service's recent changes."
	}
	return s, nil
}

// observedMeaning says what a security alert's value counts: each rule
// measures something different, and a bare "observed: 30" reads as "30
// attempts" when it is the size of a user's login history.
func observedMeaning(a detect.Alert) (string, *float64) {
	switch a.Type {
	case detect.SignalBruteForce:
		return "failed logins in the window (threshold: the rule's trigger count)", a.Baseline
	case detect.SignalCredentialStuffing:
		if a.Source == "" {
			return "distinct usernames that failed in the window, from many sources (threshold: the learned baseline)", a.Baseline
		}
		return "distinct usernames that failed from one source in the window (threshold: the rule's trigger count)", a.Baseline
	case detect.SignalUnusualAccess:
		return "this user's previous successful logins, i.e. the size of the history the login was compared with; this is ONE login", nil
	case detect.SignalPrivilegeChange:
		return "one action outside the learned baseline", nil
	}
	return "", a.Baseline
}
