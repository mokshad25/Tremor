package summarize

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mokshad/tremor/internal/detect"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func f(v float64) *float64 { return &v }

func alert(id string, t detect.SignalType, svc, sev string, at int64) detect.Alert {
	return detect.Alert{ID: id, IncidentID: "d-" + id, Type: t, Status: detect.StatusOpen, Severity: sev, Service: svc,
		UpdatedAt: at, CreatedAt: at, WindowStart: at - 30, WindowEnd: at, Value: f(0.42), Baseline: f(0.02), Z: f(9.1),
		Reason: "error rate 42.0% vs baseline 2.0% over the last 30 s", TopErrorTemplateText: "DB timeout posting <ID> after <NUM>", TopErrorTemplateCount: 120}
}

func TestCorrelatorGroupsAnomaliesAcrossServices(t *testing.T) {
	c := NewCorrelator(DefaultCorrelatorConfig())
	ev := c.Add(alert("a1", detect.SignalErrorRate, "ledger", "HIGH", 1000))
	if len(ev) != 1 || ev[0].Type != "opened" {
		t.Fatalf("%+v", ev)
	}
	id := ev[0].Incident.ID
	ev = c.Add(alert("a2", detect.SignalErrorRate, "payments", "CRITICAL", 1060)) // cascade: joins
	if len(ev) != 1 || ev[0].Type != "escalated" || ev[0].Incident.ID != id || len(ev[0].Incident.Services) != 2 {
		t.Fatalf("cascade: %+v", ev)
	}
	if c.Add(alert("a2", detect.SignalErrorRate, "payments", "CRITICAL", 1061)) != nil {
		t.Fatal("duplicate alert ID not dropped")
	}
	ev = c.Add(alert("a3", detect.SignalErrorRate, "auth", "WARNING", 1060+301)) // after the window: closes + new
	if len(ev) != 2 || ev[0].Type != "closed" || ev[0].Incident.ID != id || ev[1].Type != "opened" || ev[1].Incident.ID == id {
		t.Fatalf("window: %+v", ev)
	}
	// Deterministic: the same first alert gives the same incident ID.
	if NewCorrelator(DefaultCorrelatorConfig()).Add(alert("a1", detect.SignalErrorRate, "ledger", "HIGH", 5))[0].Incident.ID != id {
		t.Fatal("incident ID not deterministic")
	}
}

func TestCorrelatorSecurityByIdentity(t *testing.T) {
	c := NewCorrelator(DefaultCorrelatorConfig())
	bf := detect.Alert{ID: "s1", Type: detect.SignalBruteForce, Status: detect.StatusOpen, Severity: "HIGH", Service: "sshd", Source: "ip_aaa", User: "root", UpdatedAt: 100}
	stuff := detect.Alert{ID: "s2", Type: detect.SignalCredentialStuffing, Status: detect.StatusOpen, Severity: "HIGH", Service: "auth-service", Source: "ip_aaa", UpdatedAt: 160}
	other := detect.Alert{ID: "s3", Type: detect.SignalPrivilegeChange, Status: detect.StatusOpen, Severity: "HIGH", Service: "bastion", User: "usr_b", UpdatedAt: 170}
	a := c.Add(bf)[0].Incident.ID
	if ev := c.Add(stuff); ev[0].Incident.ID != a || len(ev[0].Incident.Services) != 2 {
		t.Fatal("same source across services should join")
	}
	if ev := c.Add(other); ev[0].Type != "opened" || ev[0].Incident.ID == a {
		t.Fatal("unrelated security alert joined")
	}
	if ev := c.Add(alert("x", detect.SignalErrorRate, "sshd", "HIGH", 175)); ev[0].Type != "opened" {
		t.Fatal("anomaly joined a security incident")
	}
	res := bf
	res.ID, res.Status, res.UpdatedAt = "s1r", detect.StatusResolved, 200
	res.IncidentID = "" // security alerts have no detection-level incident; nothing to update
	if c.Open() != 3 {
		t.Fatalf("open %d", c.Open())
	}
	if n := len(c.CloseAll()); n != 3 {
		t.Fatalf("closed %d", n)
	}
}

func TestCorrelatorAttachesDeploys(t *testing.T) {
	c := NewCorrelator(DefaultCorrelatorConfig())
	c.Notice(detect.Alert{Type: detect.SignalDeploy, Status: detect.StatusNotice, Service: "ledger", Reason: "Deployed ledger v2.3.1", UpdatedAt: 900})
	c.Notice(detect.Alert{Type: detect.SignalDeploy, Status: detect.StatusNotice, Service: "auth", Reason: "Deployed auth v9", UpdatedAt: 950})
	in := c.Add(alert("a1", detect.SignalErrorRate, "ledger", "HIGH", 1000))[0].Incident
	if len(in.Deploys) != 1 || in.Deploys[0].Service != "ledger" {
		t.Fatalf("deploys %+v", in.Deploys)
	}
	if x := BuildInput(in); len(x.Deploys) != 1 || !strings.Contains(x.Deploys[0], "v2.3.1") {
		t.Fatalf("input deploys %v", x.Deploys)
	}
}

func incident() Incident {
	c := NewCorrelator(DefaultCorrelatorConfig())
	c.Add(alert("a1", detect.SignalErrorRate, "ledger", "HIGH", 1000))
	return c.Add(alert("a2", detect.SignalSilence, "payments", "HIGH", 1010))[0].Incident
}

func goodSummary() Summary {
	return Summary{Summary: "Ledger errors spiked.", LikelyTrigger: "DB timeouts.", AffectedServices: []string{"ledger"},
		SuggestedNextCheck: "Check the database.", CitedAlertIDs: []string{"a1"}}
}

func TestValidate(t *testing.T) {
	in := incident()
	if err := Validate(goodSummary(), in); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*Summary){
		"fabricated citation": func(s *Summary) { s.CitedAlertIDs = []string{"a1", "zzz"} },
		"no citation":         func(s *Summary) { s.CitedAlertIDs = nil },
		"unknown service":     func(s *Summary) { s.AffectedServices = []string{"billing"} },
		"empty summary":       func(s *Summary) { s.Summary = "  " },
		"overlong next check": func(s *Summary) { s.SuggestedNextCheck = strings.Repeat("x", 900) },
	}
	for name, mut := range bad {
		s := goodSummary()
		mut(&s)
		if err := Validate(s, in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseSummary(`{"summary":"x","likely_trigger":"y","affected_services":["ledger"],"suggested_next_check":"z","cited_alert_ids":["a1"],"severity":"LOW"}`); err == nil {
		t.Error("unknown field (an attempt to set severity) accepted")
	}
}

// TestFallbackWithLLMDisabled is the Phase 6 acceptance check: with no LLM
// at all, every incident still gets a complete, valid summary.
func TestFallbackWithLLMDisabled(t *testing.T) {
	g := NewGuarded(nil, DefaultLLMConfig(), nil, nil)
	for _, in := range []Incident{incident(), securityIncident()} {
		s, err := g.Summarize(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if s.Source != "template" || s.FallbackReason != "llm_disabled" {
			t.Fatalf("source %q reason %q", s.Source, s.FallbackReason)
		}
		if err := Validate(s, in); err != nil {
			t.Fatalf("template summary invalid: %v\n%+v", err, s)
		}
	}
	if g.Stats.Fallbacks.Load() != 2 || g.Stats.Requests.Load() != 0 {
		t.Fatalf("stats %+v", g.Stats)
	}
}

func securityIncident() Incident {
	c := NewCorrelator(DefaultCorrelatorConfig())
	return c.Add(detect.Alert{ID: "b1", Type: detect.SignalBruteForce, Status: detect.StatusOpen, Severity: "CRITICAL",
		Service: "sshd", User: "root", Source: "ip_0123456789ab", UpdatedAt: 500, Techniques: []string{"T1110.001", "T1078"},
		Reason: "successful login after 25 failures for the same user and source"})[0].Incident
}

// fakeLLM is an OpenAI-compatible endpoint that returns `reply` as the
// assistant message, and records what it was sent.
type fakeLLM struct {
	srv     *httptest.Server
	calls   atomic.Int64
	mu      sync.Mutex
	prompts []string
}

func newFakeLLM(t *testing.T, status int, reply string, delay time.Duration) *fakeLLM {
	f := &fakeLLM{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer test-key" || r.URL.Path != "/v1/chat/completions" {
			w.WriteHeader(401)
			return
		}
		var req chatRequest
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.prompts = append(f.prompts, req.Messages[1].Content)
		f.mu.Unlock()
		if req.ResponseFormat.Type != "json_object" {
			t.Error("JSON mode not requested")
		}
		time.Sleep(delay)
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": reply}, "finish_reason": "stop"}},
			"usage":   map[string]int{"prompt_tokens": 321, "completion_tokens": 87},
		})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLLM) client() *OpenAICompatible {
	return &OpenAICompatible{Endpoint: f.srv.URL + "/v1", Model: "test-model", APIKey: "test-key", HTTP: f.srv.Client()}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestGuardedLLMPaths(t *testing.T) {
	good := mustJSON(map[string]any{"summary": "Ledger and payments failed together.", "likely_trigger": "Ledger DB timeouts.",
		"affected_services": []string{"ledger", "payments"}, "suggested_next_check": "Check ledger-db.", "cited_alert_ids": []string{"a1", "a2"}})
	cases := []struct {
		name, reply, wantSource, wantReason string
		status                              int
		delay                               time.Duration
	}{
		{"valid", good, "llm", "", 200, 0},
		{"fabricated citation", strings.Replace(good, `"a2"`, `"a9"`, 1), "template", "invalid_output", 200, 0},
		{"not json", "Sure! Here is the summary.", "template", "invalid_output", 200, 0},
		{"server error", good, "template", "llm_error", 500, 0},
		{"too slow", good, "template", "timeout", 200, 300 * time.Millisecond},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := newFakeLLM(t, c.status, c.reply, c.delay)
			cfg := DefaultLLMConfig()
			g := NewGuarded(fake.client(), cfg, nil, nil)
			g.Timeout = 100 * time.Millisecond
			in := incident()
			s, err := g.Summarize(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if s.Source != c.wantSource || s.FallbackReason != c.wantReason {
				t.Fatalf("source %q reason %q", s.Source, s.FallbackReason)
			}
			if err := Validate(s, in); err != nil {
				t.Fatalf("returned summary does not validate: %v", err)
			}
			if c.wantSource == "llm" && (s.PromptTokens != 321 || s.Model != "test-model" || g.Stats.CompletionTokens.Load() != 87) {
				t.Fatalf("usage not recorded: %+v", s)
			}
		})
	}
}

func TestGuardedCacheRateLimitAndScrub(t *testing.T) {
	good := mustJSON(map[string]any{"summary": "x", "likely_trigger": "y", "affected_services": []string{"ledger"},
		"suggested_next_check": "z", "cited_alert_ids": []string{"a1"}})
	fake := newFakeLLM(t, 200, good, 0)
	cfg := DefaultLLMConfig()
	cfg.RatePerMinute = 1
	scrubbed := atomic.Bool{}
	g := NewGuarded(fake.client(), cfg, func(p string) string {
		scrubbed.Store(true)
		return strings.ReplaceAll(p, "DB timeout", "[scrubbed]")
	}, nil)
	in := incident()
	s1, _ := g.Summarize(context.Background(), in)
	s2, _ := g.Summarize(context.Background(), in)
	if fake.calls.Load() != 1 || s1.Source != "llm" || s2.Source != "llm" || g.Stats.CacheHits.Load() != 1 {
		t.Fatalf("cache: calls %d, %s/%s", fake.calls.Load(), s1.Source, s2.Source)
	}
	if !scrubbed.Load() || strings.Contains(fake.prompts[0], "DB timeout") {
		t.Fatal("prompt was not passed through the scrubber before leaving the process")
	}
	other := securityIncident()
	s3, _ := g.Summarize(context.Background(), other)
	if s3.FallbackReason != "rate_limited" || fake.calls.Load() != 1 {
		t.Fatalf("rate limit: %+v calls %d", s3, fake.calls.Load())
	}
}

func TestSinks(t *testing.T) {
	var mu sync.Mutex
	var got [][]byte
	var sigOK atomic.Bool
	fails := atomic.Int64{}
	fails.Store(2) // first two deliveries fail with 503: retried
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if fails.Add(-1) >= 0 {
			w.WriteHeader(503)
			return
		}
		m := hmac.New(sha256.New, []byte("s3cret"))
		m.Write(body)
		sigOK.Store(r.Header.Get("X-Tremor-Signature") == "sha256="+hex.EncodeToString(m.Sum(nil)))
		mu.Lock()
		got = append(got, body)
		mu.Unlock()
	}))
	defer hook.Close()
	var slackBody []byte
	slack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slackBody, _ = io.ReadAll(r.Body)
	}))
	defer slack.Close()
	d := NewDispatcher([]Sink{&Webhook{URL: hook.URL, Secret: []byte("s3cret"), HTTP: hook.Client()}, &Slack{URL: slack.URL, HTTP: slack.Client()}}, 8, quiet)
	d.backoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	in := securityIncident()
	s, _ := Template{}.Summarize(context.Background(), in)
	s.Summary += " <script>"
	d.Enqueue(NewNotification("incident.opened", in, s, time.Unix(0, 0)))
	d.Close()
	if len(got) != 1 || !sigOK.Load() || d.Stats["webhook"].Sent.Load() != 1 {
		t.Fatalf("webhook: %d deliveries, signature ok %v", len(got), sigOK.Load())
	}
	var n Notification
	json.Unmarshal(got[0], &n)
	if n.IncidentID != in.ID || n.Alerts[0].MitreAttack[0] != "T1110.001" || n.Summary.Source != "template" {
		t.Fatalf("payload %+v", n)
	}
	var sp struct {
		Blocks []struct {
			Text struct{ Text string } `json:"text"`
		} `json:"blocks"`
	}
	json.Unmarshal(slackBody, &sp)
	if txt := sp.Blocks[0].Text.Text; !strings.Contains(txt, "&lt;script&gt;") || strings.Contains(txt, "<script>") {
		t.Fatalf("slack text not escaped: %s", txt)
	}
}

func TestDispatcherNeverBlocks(t *testing.T) {
	block := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer slow.Close()
	d := NewDispatcher([]Sink{&Webhook{URL: slow.URL, HTTP: slow.Client()}}, 2, quiet)
	n := NewNotification("incident.opened", incident(), goodSummary(), time.Now())
	start := time.Now()
	for range 10 {
		d.Enqueue(n)
	}
	if time.Since(start) > 100*time.Millisecond || d.Stats["webhook"].Dropped.Load() < 7 {
		t.Fatalf("enqueue blocked or did not drop: dropped %d", d.Stats["webhook"].Dropped.Load())
	}
	close(block)
	d.Close()
}

func TestNotifierPagesFirstThenSummarizes(t *testing.T) {
	good := mustJSON(map[string]any{"summary": "Ledger failed.", "likely_trigger": "DB.", "affected_services": []string{"ledger"},
		"suggested_next_check": "Check DB.", "cited_alert_ids": []string{"a1"}})
	fake := newFakeLLM(t, 200, good, 0)
	g := NewGuarded(fake.client(), DefaultLLMConfig(), nil, nil)
	var mu sync.Mutex
	var notes []Notification
	n := NewNotifier(NotifierConfig{MinSeverity: "WARNING", Delay: 50 * time.Millisecond}, NewCorrelator(DefaultCorrelatorConfig()), g, nil, quiet)
	n.OnNotify = func(x Notification) { mu.Lock(); notes = append(notes, x); mu.Unlock() }
	go n.Run()
	now := time.Now().Unix()
	n.Alerts() <- alert("a1", detect.SignalErrorRate, "ledger", "HIGH", now)
	info := alert("i1", detect.SignalUnusualAccess, "auth", "INFO", now)
	info.User = "usr_x"
	n.Alerts() <- info // INFO: recorded, never sent
	time.Sleep(1500 * time.Millisecond)
	close(n.Alerts())
	n.Wait()
	mu.Lock()
	defer mu.Unlock()
	kinds := []string{}
	for _, x := range notes {
		kinds = append(kinds, x.Kind+"/"+x.Summary.Source)
	}
	want := []string{"incident.opened/template", "incident.summary/llm", "incident.closed/llm"}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("notifications %v, want %v", kinds, want)
	}
	if fake.calls.Load() != 1 || n.Stats.Opened.Load() != 2 || n.Stats.Paged.Load() != 1 {
		t.Fatalf("calls %d opened %d paged %d", fake.calls.Load(), n.Stats.Opened.Load(), n.Stats.Paged.Load())
	}
}

func TestTransientFailuresAreNotCached(t *testing.T) {
	fake := newFakeLLM(t, 500, "", 0)
	g := NewGuarded(fake.client(), DefaultLLMConfig(), nil, nil)
	in := incident()
	g.Summarize(context.Background(), in)
	g.Summarize(context.Background(), in)
	if fake.calls.Load() != 2 {
		t.Fatalf("a provider error was cached: %d calls", fake.calls.Load())
	}
}
