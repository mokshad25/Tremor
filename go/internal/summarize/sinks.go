package summarize

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Notification is what sinks receive. Everything in it comes from redacted
// data.
type Notification struct {
	Kind         string        `json:"kind"` // incident.opened | incident.escalated | incident.summary | incident.closed
	IncidentID   string        `json:"incident_id"`
	IncidentKind string        `json:"incident_kind"`
	Severity     string        `json:"severity"`
	Services     []string      `json:"services"`
	OpenedAt     string        `json:"opened_at"`
	ClosedAt     string        `json:"closed_at,omitempty"`
	AlertCount   int           `json:"alert_count"`
	Alerts       []NotifyAlert `json:"alerts"`
	Summary      Summary       `json:"summary"`
	SentAt       string        `json:"sent_at"`
}

// NotifyAlert is the per-alert part of a notification.
type NotifyAlert struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Status      string   `json:"status"`
	Severity    string   `json:"severity"`
	Service     string   `json:"service"`
	At          string   `json:"at"`
	Reason      string   `json:"reason"`
	MitreAttack []string `json:"mitre_attack,omitempty"`
	User        string   `json:"user,omitempty"`
	Source      string   `json:"source,omitempty"`
}

const maxNotifyAlerts = 20

// NewNotification builds a notification for an incident.
func NewNotification(kind string, in Incident, s Summary, now time.Time) Notification {
	n := Notification{Kind: kind, IncidentID: in.ID, IncidentKind: string(in.Kind), Severity: in.Severity,
		Services: in.Services, OpenedAt: unixTime(in.OpenedAt), AlertCount: len(in.Alerts) + in.Truncated,
		Summary: s, SentAt: now.UTC().Format(time.RFC3339)}
	if in.ClosedAt != 0 {
		n.ClosedAt = unixTime(in.ClosedAt)
	}
	for i, a := range in.Alerts {
		if i >= maxNotifyAlerts {
			break
		}
		n.Alerts = append(n.Alerts, NotifyAlert{ID: a.ID, Type: string(a.Type), Status: string(a.Status), Severity: a.Severity,
			Service: a.Service, At: unixTime(a.UpdatedAt), Reason: a.Reason, MitreAttack: a.Techniques, User: a.User, Source: a.Source})
	}
	return n
}

// Sink delivers notifications somewhere.
type Sink interface {
	Name() string
	Send(ctx context.Context, n Notification) error
}

// retryable marks a delivery error worth retrying (network, 429, 5xx).
type deliveryError struct {
	status    int
	retryable bool
	msg       string
}

func (e *deliveryError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.status, e.msg) }

func post(ctx context.Context, client *http.Client, url string, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return &deliveryError{msg: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return &deliveryError{retryable: true, msg: err.Error()}
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode/100 == 2 {
		return nil
	}
	return &deliveryError{status: resp.StatusCode, retryable: resp.StatusCode == 429 || resp.StatusCode >= 500, msg: strings.TrimSpace(string(msg))}
}

// Webhook POSTs the notification as JSON. With a secret, the body is signed:
// X-Tremor-Signature: sha256=<hex HMAC-SHA256(secret, body)>, so the
// receiver can verify it came from TREMOR and was not altered.
type Webhook struct {
	URL    string
	Secret []byte
	HTTP   *http.Client
}

func (w *Webhook) Name() string { return "webhook" }

func (w *Webhook) Send(ctx context.Context, n Notification) error {
	body, _ := json.Marshal(n)
	h := map[string]string{"X-Tremor-Event": n.Kind}
	if len(w.Secret) > 0 {
		m := hmac.New(sha256.New, w.Secret)
		m.Write(body)
		h["X-Tremor-Signature"] = "sha256=" + hex.EncodeToString(m.Sum(nil))
	}
	return post(ctx, w.HTTP, w.URL, body, h)
}

// Slack posts to an incoming webhook.
type Slack struct {
	URL  string
	HTTP *http.Client
}

func (s *Slack) Name() string { return "slack" }

// slackEscape escapes the three characters Slack's mrkdwn treats specially.
func slackEscape(v string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(v)
}

var kindTitle = map[string]string{
	"incident.opened": "Incident opened", "incident.escalated": "Incident escalated",
	"incident.summary": "Incident summary", "incident.closed": "Incident closed",
}

func (s *Slack) Send(ctx context.Context, n Notification) error {
	icon := map[string]string{"CRITICAL": ":red_circle:", "HIGH": ":large_orange_circle:", "WARNING": ":large_yellow_circle:"}[n.Severity]
	title := fmt.Sprintf("%s %s: %s %s on %s", icon, kindTitle[n.Kind], n.Severity, n.IncidentKind, strings.Join(n.Services, ", "))
	src := "template"
	if n.Summary.Source == "llm" {
		src = "LLM (" + n.Summary.Model + ")"
	}
	text := fmt.Sprintf("*%s*\n%s\n*Likely trigger:* %s\n*Next check:* %s\n_%s · incident %s · %d alerts · summary by %s_",
		slackEscape(title), slackEscape(n.Summary.Summary), slackEscape(n.Summary.LikelyTrigger),
		slackEscape(n.Summary.SuggestedNextCheck), n.OpenedAt, n.IncidentID, n.AlertCount, src)
	body, _ := json.Marshal(map[string]any{
		"text":   title, // notification fallback
		"blocks": []map[string]any{{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": text}}},
	})
	return post(ctx, s.HTTP, s.URL, body, nil)
}

// SinkStats counts deliveries per sink.
type SinkStats struct {
	Sent, Failed, Dropped atomic.Int64
}

// Dispatcher delivers to every sink through a bounded queue per sink with
// retries. Enqueue never blocks: a full queue drops the notification and
// counts it, so a dead Slack can never back up detection.
type Dispatcher struct {
	sinks   []Sink
	queues  []chan Notification
	Stats   map[string]*SinkStats
	log     *slog.Logger
	backoff []time.Duration
	wg      sync.WaitGroup
}

func NewDispatcher(sinks []Sink, queueLen int, log *slog.Logger) *Dispatcher {
	d := &Dispatcher{sinks: sinks, Stats: map[string]*SinkStats{}, log: log,
		backoff: []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}}
	for _, s := range sinks {
		q := make(chan Notification, queueLen)
		d.queues = append(d.queues, q)
		st := &SinkStats{}
		d.Stats[s.Name()] = st
		d.wg.Go(func() { d.worker(s, q, st) })
	}
	return d
}

func (d *Dispatcher) worker(s Sink, q chan Notification, st *SinkStats) {
	for n := range q {
		var err error
		for attempt := 0; ; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err = s.Send(ctx, n)
			cancel()
			de, ok := err.(*deliveryError)
			if err == nil || !ok || !de.retryable || attempt >= len(d.backoff) {
				break
			}
			time.Sleep(d.backoff[attempt])
		}
		if err != nil {
			st.Failed.Add(1)
			d.log.Warn("notification not delivered", "sink", s.Name(), "incident", n.IncidentID, "kind", n.Kind, "err", err)
			continue
		}
		st.Sent.Add(1)
	}
}

// Enqueue hands n to every sink without blocking.
func (d *Dispatcher) Enqueue(n Notification) {
	for i, q := range d.queues {
		select {
		case q <- n:
		default:
			d.Stats[d.sinks[i].Name()].Dropped.Add(1)
		}
	}
}

// Close drains the queues and waits for in-flight deliveries.
func (d *Dispatcher) Close() {
	for _, q := range d.queues {
		close(q)
	}
	d.wg.Wait()
}
