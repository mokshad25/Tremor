package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	"github.com/mokshad/tremor/internal/config"
	"github.com/mokshad/tremor/internal/detect"
	"github.com/mokshad/tremor/internal/redact"
	"github.com/mokshad/tremor/internal/shard"
)

type running struct {
	srv    *Server
	url    string
	cancel context.CancelFunc
	errc   chan error
}

func testConfig(dir string) config.Config {
	cfg := config.Default()
	cfg.Server.ListenAddr = "127.0.0.1:0"
	cfg.Server.DebugAddr, cfg.Server.MetricsAddr = "", ""
	cfg.OTLP.HTTPAddr, cfg.OTLP.GRPCAddr = "", "" // tests that need OTLP turn it on with port 0
	cfg.Ingest.QueueCapacity = 16
	cfg.WAL.Dir = filepath.Join(dir, "wal")
	cfg.WAL.SegmentBytes = 64 << 10 // small, to exercise rotation and cleanup
	cfg.WAL.SyncInterval = 2 * time.Millisecond
	cfg.Checkpoint.Interval = 20 * time.Millisecond
	cfg.Shards.Count = 4
	cfg.Testing.ProcessedLogDir = filepath.Join(dir, "processed")
	return cfg
}

func start(t *testing.T, cfg config.Config) *running {
	t.Helper()
	ready := make(chan string, 1)
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.Ready = ready
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx) }()
	select {
	case addr := <-ready:
		return &running{srv: s, url: "http://" + addr + "/ingest", cancel: cancel, errc: errc}
	case err := <-errc:
		cancel()
		t.Fatalf("server exited during startup: %v", err)
	}
	return nil
}

func (r *running) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	if err := <-r.errc; err != nil {
		t.Fatalf("run: %v", err)
	}
}

type ackRange struct{ first, last uint64 }

const perReq = 10

var batchBody = `{"events":[` + strings.TrimSuffix(strings.Repeat(`{"service":"svc-SVC","message":"hello world from a producer"},`, perReq), ",") + `]}`

// produce sends batches from n goroutines until stop is closed and returns
// the acked seq ranges.
func produce(t *testing.T, url string, n int, stop <-chan struct{}) []ackRange {
	var mu sync.Mutex
	var acked []ackRange
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 5 * time.Second}
	for i := range n {
		body := strings.ReplaceAll(batchBody, "SVC", string(rune('a'+i%26)))
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := client.Post(url, "application/json", strings.NewReader(body))
				if err != nil {
					continue
				}
				var ok struct{ FirstSeq, LastSeq uint64 }
				if resp.StatusCode == http.StatusOK {
					var raw struct {
						First uint64 `json:"first_seq"`
						Last  uint64 `json:"last_seq"`
					}
					json.NewDecoder(resp.Body).Decode(&raw)
					ok.FirstSeq, ok.LastSeq = raw.First, raw.Last
					if ok.LastSeq-ok.FirstSeq+1 != perReq {
						t.Errorf("ack range %d-%d is not %d events", ok.FirstSeq, ok.LastSeq, perReq)
					}
					mu.Lock()
					acked = append(acked, ackRange{ok.FirstSeq, ok.LastSeq})
					mu.Unlock()
				} else if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
					t.Errorf("unexpected status %d", resp.StatusCode)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		})
	}
	<-stop
	wg.Wait()
	return acked
}

func runLoad(t *testing.T, r *running, d time.Duration) []ackRange {
	stop := make(chan struct{})
	time.AfterFunc(d, func() { close(stop) })
	return produce(t, r.url, 16, stop)
}

func assertAllProcessed(t *testing.T, dir string, acked []ackRange) map[uint64]int {
	t.Helper()
	seen, err := shard.ReadProcessedLogs(filepath.Join(dir, "processed"))
	if err != nil {
		t.Fatal(err)
	}
	missing := 0
	for _, a := range acked {
		for s := a.first; s <= a.last; s++ {
			if seen[s] == 0 {
				missing++
			}
		}
	}
	if missing > 0 {
		t.Fatalf("%d acknowledged events were never processed", missing)
	}
	return seen
}

func TestGracefulShutdownProcessesEverythingAcked(t *testing.T) {
	dir := t.TempDir()
	r := start(t, testConfig(dir))
	// Cancel while producers are mid-flight.
	stop := make(chan struct{})
	var acked []ackRange
	done := make(chan struct{})
	go func() { acked = produce(t, r.url, 32, stop); close(done) }()
	time.Sleep(300 * time.Millisecond)
	r.stop(t)
	close(stop)
	<-done
	if len(acked) == 0 {
		t.Fatal("nothing was acked")
	}
	if got := r.srv.Gateway.EventsAccepted.Load(); got != int64(len(acked)*perReq) {
		t.Fatalf("server accepted %d, clients saw %d", got, len(acked)*perReq)
	}
	assertAllProcessed(t, dir, acked)
}

func TestCleanRestartReplaysNothing(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	r := start(t, cfg)
	acked := runLoad(t, r, 300*time.Millisecond)
	r.stop(t)

	r = start(t, cfg) // the final checkpoint at shutdown covers everything
	if n := r.srv.WAL.RecordsReplayed.Load(); n != 0 {
		t.Fatalf("clean restart replayed %d records", n)
	}
	acked = append(acked, runLoad(t, r, 100*time.Millisecond)...)
	r.stop(t)
	seen := assertAllProcessed(t, dir, acked)
	for s, n := range seen {
		if n != 1 {
			t.Fatalf("seq %d processed %d times across a clean restart", s, n)
		}
	}
	// Sequence numbers continue across restarts: no reuse.
	maxFirst := uint64(0)
	for _, a := range acked {
		maxFirst = max(maxFirst, a.first)
	}
	if maxFirst <= uint64(len(acked)) {
		t.Fatal("suspicious seq numbering")
	}
}

func TestLostCheckpointReplaysEverything(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.WAL.SegmentBytes = 64 << 20 // keep all records so replay can cover them
	r := start(t, cfg)
	acked := runLoad(t, r, 200*time.Millisecond)
	r.stop(t)
	// Simulate a crash before any checkpoint was written.
	if err := os.Remove(filepath.Join(cfg.WAL.Dir, "checkpoint.json")); err != nil {
		t.Fatal(err)
	}
	r = start(t, cfg)
	replayed := r.srv.WAL.RecordsReplayed.Load()
	r.stop(t)
	if replayed != int64(len(acked)*perReq) {
		t.Fatalf("replayed %d, want %d", replayed, len(acked)*perReq)
	}
	seen := assertAllProcessed(t, dir, acked)
	for _, a := range acked {
		if seen[a.first] != 2 { // once live, once on replay: at-least-once
			t.Fatalf("seq %d seen %d times", a.first, seen[a.first])
		}
	}
}

func TestShardCountChangeDoesNotSkip(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.WAL.SegmentBytes = 64 << 20
	r := start(t, cfg)
	acked := runLoad(t, r, 200*time.Millisecond)
	r.stop(t)
	cfg.Shards.Count = 3 // routing changes: per-shard checkpoints are void
	r = start(t, cfg)
	acked = append(acked, runLoad(t, r, 100*time.Millisecond)...)
	r.stop(t)
	assertAllProcessed(t, dir, acked)
}

// TestErrorBurstRaisesCriticalAlert goes producer -> gateway -> WAL ->
// ring -> shard (Drain + detection) -> alert. The CRITICAL rule (error rate
// above 50% with enough lines) fires even before baselines are learned, so
// one burst is enough.
func TestErrorBurstRaisesCriticalAlert(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Testing.ProcessedLogDir = ""
	cfg.Shards.TickInterval = 100 * time.Millisecond
	got := make(chan detectAlert, 16)
	ready := make(chan string, 1)
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.Ready = ready
	s.AlertHook = func(a detectAlert) { got <- a }
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx) }()
	url := "http://" + <-ready + "/ingest"

	var b strings.Builder
	b.WriteString(`{"events":[`)
	for i := range 40 {
		if i > 0 {
			b.WriteByte(',')
		}
		if i%4 == 0 {
			fmt.Fprintf(&b, `{"service":"payments","level":"info","message":"Payment authorized txn_%04x amount=%d.00"}`, i, i)
		} else {
			fmt.Fprintf(&b, `{"service":"payments","level":"error","message":"Acquirer timeout txn_%04x after %dms upstream=10.0.0.%d"}`, i, 100+i, i)
		}
	}
	b.WriteString(`]}`)
	resp, err := http.Post(url, "application/json", strings.NewReader(b.String()))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("post: %v %v", err, resp)
	}
	var ack struct {
		First uint64 `json:"first_seq"`
		Last  uint64 `json:"last_seq"`
	}
	json.NewDecoder(resp.Body).Decode(&ack)
	resp.Body.Close()

	select {
	case a := <-got:
		if a.Type != "ERROR_RATE" || a.Severity != "CRITICAL" || a.Service != "payments" || a.Status != "OPEN" {
			t.Fatalf("unexpected alert %+v", a)
		}
		if a.Lines != 40 || a.Errors != 30 || a.Value == nil || *a.Value != 0.75 {
			t.Fatalf("observed values wrong: lines %d errors %d value %v", a.Lines, a.Errors, a.Value)
		}
		if a.SourceSeqs.First != ack.First || a.SourceSeqs.Last != ack.Last || len(a.SourceSeqs.ErrorSeqs) == 0 {
			t.Fatalf("source seqs %+v, acked %d-%d", a.SourceSeqs, ack.First, ack.Last)
		}
		if a.TopErrorTemplateText != "Acquirer timeout <ID> after <NUM> upstream=<IP>" {
			t.Fatalf("top error template %q", a.TopErrorTemplateText)
		}
		if a.WindowEnd-a.WindowStart != 30 || a.ID == "" || a.IncidentID == "" {
			t.Fatalf("window/id: %+v", a)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no alert within 10s")
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if s.Detect.Critical.Load() != 1 {
		t.Fatalf("critical counter %d", s.Detect.Critical.Load())
	}
}

type detectAlert = detect.Alert

// TestRawPIINeverReachesDisk sends PII through all three receivers, stops
// the server, then scans every byte of every file it wrote (WAL segments,
// checkpoint, processed logs) for the raw values.
func TestRawPIINeverReachesDisk(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.OTLP.HTTPAddr, cfg.OTLP.GRPCAddr = "127.0.0.1:0", "127.0.0.1:0"
	cfg.Redact.HMACKey = []byte("disk-test-key-0123456789abcdef!!")
	r := start(t, cfg)

	secrets := []string{
		"priya.sharma@example.com", "4111111111111111", "9876543210", "234567890124",
		"ABCPE1234F", "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc", "203.0.113.77", "alice_admin", "hunter2hunter2",
	}
	msg := "Login failed user=alice_admin from 203.0.113.77 email priya.sharma@example.com card 4111111111111111 " +
		"phone 9876543210 aadhaar 2345 6789 0124 pan ABCPE1234F key=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc password=hunter2hunter2"
	// The Aadhaar test value must really be Verhoeff-valid for this to mean anything.
	if !strings.Contains(redact.New(cfg.Redact.HMACKey).String(msg), "<AADHAAR>") {
		t.Fatal("test fixture: aadhaar value is not valid")
	}

	// 1. Native JSON.
	body := fmt.Sprintf(`{"events":[{"service":"auth","level":"error","message":%q,"attributes":{"user":"alice_admin","client_ip":"203.0.113.77"}}]}`, msg)
	if resp, err := http.Post(r.url, "application/json", strings.NewReader(body)); err != nil || resp.StatusCode != 200 {
		t.Fatalf("ingest: %v %v", err, resp)
	}
	// 2. OTLP/HTTP protobuf.
	req := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{Key: "service.name", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "auth"}}}}},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
			Body:       &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: msg}},
			Attributes: []*commonpb.KeyValue{{Key: "enduser.id", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "alice_admin"}}}},
		}}}},
	}}}
	pb, _ := proto.Marshal(req)
	if resp, err := http.Post("http://"+r.srv.OTLPHTTPAddr+"/v1/logs", "application/x-protobuf", bytes.NewReader(pb)); err != nil || resp.StatusCode != 200 {
		t.Fatalf("otlp http: %v %v", err, resp)
	}
	// 3. OTLP/gRPC.
	conn, err := grpc.NewClient(r.srv.OTLPGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := collogspb.NewLogsServiceClient(conn).Export(ctx, req); err != nil {
		t.Fatalf("otlp grpc: %v", err)
	}
	conn.Close()
	r.stop(t)

	files, scanned := 0, 0
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, _ := os.ReadFile(path)
		files++
		scanned += len(data)
		for _, s := range secrets {
			if bytes.Contains(data, []byte(s)) {
				t.Errorf("raw PII %q found on disk in %s", s, path)
			}
		}
		return nil
	})
	if files < 2 || scanned < 500 {
		t.Fatalf("scanned only %d files / %d bytes: test is not looking at the WAL", files, scanned)
	}
	if r.srv.Gateway.EventsAccepted.Load() != 3 {
		t.Fatalf("accepted %d of 3 events", r.srv.Gateway.EventsAccepted.Load())
	}
}

// TestPrometheusMetrics scrapes /metrics after real traffic and checks the
// families every Grafana panel depends on.
func TestPrometheusMetrics(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Server.MetricsAddr = "127.0.0.1:0"
	cfg.Redact.HMACKey = []byte("metrics-test-key-0123456789abcdef")
	r := start(t, cfg)
	body := `{"events":[{"service":"auth","level":"error","message":"Login failed user=alice ip=10.0.0.1 card 4111111111111111"}]}`
	if resp, err := http.Post(r.url, "application/json", strings.NewReader(body)); err != nil || resp.StatusCode != 200 {
		t.Fatalf("ingest %v %v", err, resp)
	}
	time.Sleep(100 * time.Millisecond) // let the shard process and the checkpointer run
	resp, err := http.Get("http://" + r.srv.MetricsAddr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	text, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	r.stop(t)
	for _, want := range []string{
		`tremor_ingest_requests_total{result="accepted"} 1`,
		"tremor_events_accepted_total 1",
		"tremor_events_processed_total 1",
		`tremor_redactions_total{type="card"} 1`,
		`tremor_redactions_total{type="username"} 1`,
		`tremor_redactions_total{type="ip"} 1`,
		"tremor_wal_fsync_seconds_count",
		"tremor_wal_write_seconds_count",
		"tremor_checkpoint_lag_records",
		`tremor_shard_queue_depth{shard="0"}`,
		`tremor_queue_depth{stage="ingest"}`,
		"process_resident_memory_bytes",
	} {
		if !strings.Contains(string(text), want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
	if strings.Contains(string(text), "alice") || strings.Contains(string(text), "4111111111111111") {
		t.Fatal("raw PII in /metrics")
	}
}

// TestIncidentReachesWebhookWithLLMSummary: error burst -> CRITICAL alert ->
// incident -> immediate page (template) -> LLM summary follow-up, through a
// real webhook sink and a fake OpenAI-compatible LLM. The prompt the LLM
// receives must contain no raw PII.
func TestIncidentReachesWebhookWithLLMSummary(t *testing.T) {
	var mu sync.Mutex
	var prompts []string
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		prompt := req.Messages[1].Content
		mu.Lock()
		prompts = append(prompts, prompt)
		mu.Unlock()
		// Cite the first alert ID present in the prompt, as a model would.
		id := prompt[strings.Index(prompt, `"id": "`)+7:]
		id = id[:strings.Index(id, `"`)]
		content, _ := json.Marshal(map[string]any{"summary": "Payments errors spiked to 75%.", "likely_trigger": "Acquirer timeouts.",
			"affected_services": []string{"payments"}, "suggested_next_check": "Check the acquirer.", "cited_alert_ids": []string{id}})
		json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": string(content)}}},
			"usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 50}})
	}))
	defer llm.Close()
	var notes []map[string]any
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n map[string]any
		json.NewDecoder(r.Body).Decode(&n)
		mu.Lock()
		notes = append(notes, n)
		mu.Unlock()
	}))
	defer hook.Close()

	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Testing.ProcessedLogDir = ""
	cfg.Shards.TickInterval = 100 * time.Millisecond
	cfg.Redact.HMACKey = []byte("notify-test-key-0123456789abcdef")
	cfg.LLM.Endpoint, cfg.LLMAPIKey, cfg.LLM.DelayS = llm.URL, "test-key", 0
	cfg.Notify.WebhookURL = hook.URL
	r := start(t, cfg)
	var b strings.Builder
	b.WriteString(`{"events":[`)
	for i := range 40 {
		if i > 0 {
			b.WriteByte(',')
		}
		lvl := "error"
		if i%4 == 0 {
			lvl = "info"
		}
		fmt.Fprintf(&b, `{"service":"payments","level":%q,"message":"Payment failed for priya%d@example.com from 203.0.113.%d"}`, lvl, i, i)
	}
	b.WriteString(`]}`)
	if resp, err := http.Post(r.url, "application/json", strings.NewReader(b.String())); err != nil || resp.StatusCode != 200 {
		t.Fatalf("post %v %v", err, resp)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(notes)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	r.stop(t) // closes the incident: a third notification
	mu.Lock()
	defer mu.Unlock()
	var kinds []string
	for _, n := range notes {
		kinds = append(kinds, fmt.Sprint(n["kind"], "/", n["summary"].(map[string]any)["source"]))
	}
	if len(kinds) < 2 || kinds[0] != "incident.opened/template" || kinds[1] != "incident.summary/llm" {
		t.Fatalf("notifications: %v", kinds)
	}
	if len(prompts) != 1 {
		t.Fatalf("LLM called %d times, want 1 (cached per incident)", len(prompts))
	}
	for _, raw := range []string{"priya", "example.com", "203.0.113."} {
		if strings.Contains(prompts[0], raw) {
			t.Fatalf("raw PII %q reached the LLM prompt", raw)
		}
	}
	if r.srv.LLM.OK.Load() != 1 || r.srv.LLM.PromptTokens.Load() != 100 {
		t.Fatalf("llm stats ok=%d tokens=%d", r.srv.LLM.OK.Load(), r.srv.LLM.PromptTokens.Load())
	}
}
