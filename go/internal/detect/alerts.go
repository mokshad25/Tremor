package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// SignalType names match the Python SignalType enum and the UI contract.
type SignalType string

const (
	SignalErrorRate  SignalType = "ERROR_RATE"
	SignalSilence    SignalType = "SILENCE"
	SignalNewPattern SignalType = "NEW_PATTERN"
	SignalLatency    SignalType = "LATENCY"
)

// Severity is ordered: a higher value is more severe. 0 means none.
type Severity uint8

const (
	SevNone Severity = iota
	SevInfo
	SevWarning
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	return [...]string{"", "INFO", "WARNING", "HIGH", "CRITICAL"}[s]
}

// Status of an alert notification (the UI's AlertStatus).
type Status string

const (
	StatusOpen      Status = "OPEN"
	StatusEscalated Status = "ESCALATED"
	StatusResolved  Status = "RESOLVED"
	// StatusNotice marks context that is not an alert (e.g. a deploy): it
	// is passed to the correlator for summaries, never paged or counted.
	StatusNotice Status = "NOTICE"
)

// SignalDeploy is a deploy/release notice seen in a service's logs.
const SignalDeploy SignalType = "DEPLOY"

// Signal is one detector's verdict for one key on one tick.
type Signal struct {
	Type     SignalType
	Service  string
	Severity Severity
	// Clear: +1 counts toward resolution, -1 resets the count, 0 neutral
	// (e.g. not enough data).
	Clear    int8
	Resolve  bool // the detector's own rule says the incident is over
	Template string
	Value    *float64
	Baseline *float64
	Z        *float64
	Lines    int
	Errors   int
	Reason   string
}

// Alert is one notification. Field names follow the UI contract
// (docs/ui-contract.md); Window, SourceSeqs and Template* are additions.
type Alert struct {
	ID                    string     `json:"id"`
	IncidentID            string     `json:"incident_id"`
	Type                  SignalType `json:"signal_type"`
	Status                Status     `json:"status"`
	Severity              string     `json:"severity"`
	Service               string     `json:"service"`
	Template              string     `json:"template_id"`                  // key template (NEW_PATTERN), "" otherwise
	TopErrorTemplate      string     `json:"top_error_template,omitempty"` // most frequent error template in the window
	TopErrorTemplateText  string     `json:"top_error_template_text,omitempty"`
	TopErrorTemplateCount int        `json:"top_error_template_count,omitempty"` // its error lines in the window
	Value                 *float64   `json:"value"`                              // observed: error rate, or silent seconds
	Baseline              *float64   `json:"baseline"`                           // the mu it was judged against
	Z                     *float64   `json:"z_score"`
	Lines                 int        `json:"lines"`
	Errors                int        `json:"errors"`
	Reason                string     `json:"reason"`
	WindowStart           int64      `json:"window_start"` // unix seconds; the window is (start, end]
	WindowEnd             int64      `json:"window_end"`
	SourceSeqs            SeqRange   `json:"source_seqs"`
	// Security rules: MITRE ATT&CK technique IDs and the (tokenized) user
	// and source involved. Never raw values: redaction ran before the WAL.
	Techniques []string `json:"mitre_attack,omitempty"`
	User       string   `json:"user,omitempty"`
	Source     string   `json:"source,omitempty"`

	CreatedAt int64 `json:"created_at"` // unix seconds the incident opened
	UpdatedAt int64 `json:"updated_at"` // unix seconds of this notification

	// Ingest-to-alert latency, never serialized. EvidenceReceivedAt is the
	// gateway receive time (unix nanos) of the alert's newest line,
	// SourceSeqs.Last, when the processor knows it (0 otherwise): detection
	// fills it from event data and reads no clock. IngestToAlert is set by
	// the server from its wall clock when the alert leaves detection (0 when
	// not measured).
	EvidenceReceivedAt int64         `json:"-"`
	IngestToAlert      time.Duration `json:"-"`
}

// SeqRange points back into the WAL: the seq range of lines in the alert's
// window, plus a sample of error-line seqs, so a responder (or the LLM
// summary) can pull the exact evidence.
type SeqRange struct {
	First     uint64   `json:"first"`
	Last      uint64   `json:"last"`
	ErrorSeqs []uint64 `json:"error_sample,omitempty"`
}

type incidentKey struct {
	t        SignalType
	service  string
	template string
}

type incident struct {
	id          string
	key         incidentKey
	peak        Severity
	createdAt   int64
	last        Signal
	emittedPeak Severity
	escalated   bool
	clearCount  int
}

// AlertManager is the alert lifecycle state machine (Python alerts.py):
//
//   - at most one open incident per (type, service, template);
//   - a notification only when severity rises above what was already
//     emitted for the incident: OPEN first, then ESCALATED;
//   - resolve after ClearTicks consecutive clear ticks, or when the
//     detector says so; neutral ticks neither advance nor reset the count;
//   - re-opening within CooldownS of resolving reuses the incident id.
//
// Ack and silence (UI actions) arrive with the API in Phase 6.
type AlertManager struct {
	cfg    Config
	open   map[incidentKey]*incident
	recent map[incidentKey]recentIncident
}

type recentIncident struct {
	inc        *incident
	resolvedAt int64
}

func NewAlertManager(cfg Config) *AlertManager {
	return &AlertManager{cfg: cfg, open: map[incidentKey]*incident{}, recent: map[incidentKey]recentIncident{}}
}

func (m *AlertManager) IsOpen(t SignalType, service, template string) bool {
	_, ok := m.open[incidentKey{t, service, template}]
	return ok
}

// HighestOpen is the most severe open incident's peak (SevNone if none).
func (m *AlertManager) HighestOpen() Severity {
	var s Severity
	for _, inc := range m.open {
		s = max(s, inc.peak)
	}
	return s
}

// notification is what Process returns; the engine turns it into an Alert
// with window context.
type notification struct {
	inc    *incident
	status Status
	reason string
	now    int64
}

// Process feeds one signal at tick now and returns any notification.
func (m *AlertManager) Process(sig Signal, now int64) *notification {
	key := incidentKey{sig.Type, sig.Service, sig.Template}
	inc := m.open[key]
	if inc == nil {
		if sig.Severity == SevNone {
			return nil
		}
		inc = m.openIncident(key, sig, now)
	}
	inc.last = sig
	if sig.Severity > inc.peak {
		inc.peak = sig.Severity
	}
	switch sig.Clear {
	case 1:
		inc.clearCount++
	case -1:
		inc.clearCount = 0
	}
	if sig.Resolve || inc.clearCount >= m.cfg.ClearTicks {
		return m.resolve(inc, now)
	}
	if inc.emittedPeak != SevNone && inc.peak <= inc.emittedPeak {
		return nil
	}
	status := StatusOpen
	if inc.emittedPeak != SevNone {
		status = StatusEscalated
		inc.escalated = true
	}
	inc.emittedPeak = inc.peak
	return &notification{inc: inc, status: status, reason: sig.Reason, now: now}
}

func (m *AlertManager) openIncident(key incidentKey, sig Signal, now int64) *incident {
	var inc *incident
	if r, ok := m.recent[key]; ok && now-r.resolvedAt <= int64(m.cfg.CooldownS) {
		inc = &incident{id: r.inc.id, key: key, peak: sig.Severity, createdAt: r.inc.createdAt, last: sig}
	} else {
		inc = &incident{id: incidentID(key, now), key: key, peak: sig.Severity, createdAt: now, last: sig}
	}
	delete(m.recent, key)
	m.open[key] = inc
	return inc
}

func (m *AlertManager) resolve(inc *incident, now int64) *notification {
	delete(m.open, inc.key)
	m.recent[inc.key] = recentIncident{inc: inc, resolvedAt: now}
	reason := "resolved"
	if inc.last.Reason != "" {
		reason = "resolved: " + inc.last.Reason
	}
	return &notification{inc: inc, status: StatusResolved, reason: reason, now: now}
}

// incidentID is deterministic: the same incident opened at the same tick
// always gets the same id. Replaying the same events after a crash then
// yields the same ids, so downstream dedup by id works.
func incidentID(k incidentKey, now int64) string {
	return shortHash("inc", string(k.t), k.service, k.template, strconv.FormatInt(now, 10))
}

func alertID(incidentID string, status Status, now int64) string {
	return shortHash("alert", incidentID, string(status), strconv.FormatInt(now, 10))
}

func shortHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:%s|", len(p), p)
	}
	return hex.EncodeToString(h.Sum(nil)[:10])
}
