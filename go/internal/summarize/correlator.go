// Package summarize turns alerts into incidents and incidents into
// notifications: a correlator groups related alerts, an LLM writes a
// plain-English summary, and sinks (webhook, Slack) deliver it.
//
// The LLM never decides. Detection is deterministic code; the correlator
// decides what an incident is and when it opens and closes; the summary is
// text attached to a notification and has no other effect. Every notification
// can be sent with a deterministic template summary, so the system works the
// same with the LLM down, rate-limited or disabled.
package summarize

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"

	"github.com/mokshad/tremor/internal/detect"
)

// Kind separates operational anomalies from security detections; they are
// correlated by different rules.
type Kind string

const (
	KindAnomaly  Kind = "anomaly"
	KindSecurity Kind = "security"
)

func kindOf(t detect.SignalType) Kind {
	switch t {
	case detect.SignalBruteForce, detect.SignalCredentialStuffing, detect.SignalPrivilegeChange, detect.SignalUnusualAccess:
		return KindSecurity
	}
	return KindAnomaly
}

var sevRank = map[string]int{"INFO": 1, "WARNING": 2, "HIGH": 3, "CRITICAL": 4}

// SeverityAtLeast reports whether sev is at least min.
func SeverityAtLeast(sev, min string) bool { return sevRank[sev] >= sevRank[min] }

// Incident is a group of related alerts.
type Incident struct {
	ID         string
	Kind       Kind
	OpenedAt   int64 // unix seconds (detection clock)
	UpdatedAt  int64
	ClosedAt   int64 // 0 while open
	Severity   string
	Services   []string // sorted
	Alerts     []detect.Alert
	Deploys    []detect.Alert // deploy notices shortly before or during
	Truncated  int            // alerts dropped beyond MaxAlerts
	users      map[string]bool
	sources    map[string]bool
	detectIncs map[string]bool // detection-level incident ids, for RESOLVED notices
}

// AlertIDs returns the IDs of the incident's alerts.
func (in *Incident) AlertIDs() []string {
	out := make([]string, len(in.Alerts))
	for i, a := range in.Alerts {
		out[i] = a.ID
	}
	return out
}

// Snapshot returns a copy safe to hand to another goroutine.
func (in *Incident) Snapshot() Incident {
	c := *in
	c.Services = slices.Clone(in.Services)
	c.Alerts = slices.Clone(in.Alerts)
	c.Deploys = slices.Clone(in.Deploys)
	c.users, c.sources, c.detectIncs = nil, nil, nil
	return c
}

// Event is something the correlator reports.
type Event struct {
	Type     string // "opened" | "updated" | "escalated" | "closed"
	Incident Incident
}

// CorrelatorConfig controls grouping.
type CorrelatorConfig struct {
	WindowS         int `yaml:"window_s"`          // alerts this close (and related) join one incident; idle this long closes it
	MaxAlerts       int `yaml:"max_alerts"`        // per incident; more are counted, not kept
	DeployLookbackS int `yaml:"deploy_lookback_s"` // deploys this long before an incident are attached
}

func DefaultCorrelatorConfig() CorrelatorConfig {
	return CorrelatorConfig{WindowS: 300, MaxAlerts: 200, DeployLookbackS: 1800}
}

// Correlator groups alerts into incidents. Time is the alerts' own
// detection time, so a replay produces the same incidents. Not safe for
// concurrent use: one goroutine owns it.
//
// Grouping rules:
//   - Anomalies (error rate, silence, ...) within the window join the open
//     anomaly incident, across services: a database outage that makes three
//     services error is one incident, not three pages.
//   - Security alerts join an open security incident that shares a user or
//     a source with them (the same attacker hitting sshd and the app), or
//     the same service and rule.
//   - RESOLVED notices update the incident their alert belongs to.
//   - An alert ID seen before is dropped (at-least-once delivery and crash
//     replay can produce duplicates).
type Correlator struct {
	cfg     CorrelatorConfig
	open    []*Incident
	seen    map[string]int64 // alert id -> when seen
	deploys []detect.Alert   // recent deploy notices
}

func NewCorrelator(cfg CorrelatorConfig) *Correlator {
	return &Correlator{cfg: cfg, seen: map[string]int64{}}
}

func incidentID(first detect.Alert) string {
	h := sha256.Sum256([]byte("incident|" + first.ID))
	return "inc-" + hex.EncodeToString(h[:6])
}

// Notice records context (deploys) for incidents.
func (c *Correlator) Notice(n detect.Alert) {
	c.deploys = append(c.deploys, n)
	if len(c.deploys) > 200 {
		c.deploys = c.deploys[len(c.deploys)-200:]
	}
}

// Add feeds one alert and returns what happened (nothing for duplicates).
func (c *Correlator) Add(a detect.Alert) []Event {
	if _, dup := c.seen[a.ID]; dup {
		return nil
	}
	c.seen[a.ID] = a.UpdatedAt
	now := a.UpdatedAt
	out := c.Expire(now)

	if a.Status == detect.StatusResolved {
		for _, in := range c.open {
			if in.detectIncs[a.IncidentID] {
				c.append(in, a)
				out = append(out, Event{"updated", in.Snapshot()})
				return out
			}
		}
		return out // resolution of something already closed: nothing to say
	}

	if in := c.match(a); in != nil {
		before := in.Severity
		c.append(in, a)
		kind := "updated"
		if sevRank[in.Severity] > sevRank[before] {
			kind = "escalated"
		}
		return append(out, Event{kind, in.Snapshot()})
	}
	in := &Incident{ID: incidentID(a), Kind: kindOf(a.Type), OpenedAt: now,
		users: map[string]bool{}, sources: map[string]bool{}, detectIncs: map[string]bool{}}
	c.append(in, a)
	c.open = append(c.open, in)
	return append(out, Event{"opened", in.Snapshot()})
}

func (c *Correlator) match(a detect.Alert) *Incident {
	window := int64(c.cfg.WindowS)
	k := kindOf(a.Type)
	for _, in := range c.open {
		if in.Kind != k || a.UpdatedAt-in.UpdatedAt > window {
			continue
		}
		if k == KindAnomaly {
			return in
		}
		if (a.User != "" && in.users[a.User]) || (a.Source != "" && in.sources[a.Source]) {
			return in
		}
		for _, b := range in.Alerts {
			if b.Service == a.Service && b.Type == a.Type {
				return in
			}
		}
	}
	return nil
}

func (c *Correlator) append(in *Incident, a detect.Alert) {
	in.UpdatedAt = max(in.UpdatedAt, a.UpdatedAt)
	if len(in.Alerts) < c.cfg.MaxAlerts {
		in.Alerts = append(in.Alerts, a)
	} else {
		in.Truncated++
	}
	if a.Status != detect.StatusResolved && sevRank[a.Severity] > sevRank[in.Severity] {
		in.Severity = a.Severity
	}
	if !slices.Contains(in.Services, a.Service) {
		in.Services = append(in.Services, a.Service)
		slices.Sort(in.Services)
		// Attach deploys of this service from shortly before the incident.
		for _, d := range c.deploys {
			if d.Service == a.Service && d.UpdatedAt >= in.OpenedAt-int64(c.cfg.DeployLookbackS) && d.UpdatedAt <= a.UpdatedAt {
				in.Deploys = append(in.Deploys, d)
			}
		}
	}
	if a.User != "" {
		in.users[a.User] = true
	}
	if a.Source != "" {
		in.sources[a.Source] = true
	}
	if a.IncidentID != "" {
		in.detectIncs[a.IncidentID] = true
	}
}

// Expire closes incidents with no alert for a whole window before now and
// forgets old alert IDs.
func (c *Correlator) Expire(now int64) []Event {
	var out []Event
	window := int64(c.cfg.WindowS)
	kept := c.open[:0]
	for _, in := range c.open {
		if now-in.UpdatedAt > window {
			in.ClosedAt = in.UpdatedAt + window
			out = append(out, Event{"closed", in.Snapshot()})
			continue
		}
		kept = append(kept, in)
	}
	c.open = kept
	for id, t := range c.seen {
		if now-t > 4*window {
			delete(c.seen, id)
		}
	}
	return out
}

// CloseAll closes every open incident (shutdown, end of a replay).
func (c *Correlator) CloseAll() []Event {
	var out []Event
	for _, in := range c.open {
		in.ClosedAt = in.UpdatedAt
		out = append(out, Event{"closed", in.Snapshot()})
	}
	c.open = nil
	return out
}

// Open returns the number of open incidents.
func (c *Correlator) Open() int { return len(c.open) }

// unixTime formats detection time for humans.
func unixTime(s int64) string { return time.Unix(s, 0).UTC().Format(time.RFC3339) }
