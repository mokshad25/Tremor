package main

import (
	"encoding/json"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 5, 14, 0, 0, 0, time.UTC)

func TestGeneratorDeterministicPerSeed(t *testing.T) {
	cfg := GenConfig{Services: 5, Seed: 7}
	a := NewGenerator(cfg, 1).Batch(0, t0, 200)
	b := NewGenerator(cfg, 1).Batch(0, t0, 200)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same seed and stream produced different events")
	}
	cfg.Seed = 8
	if reflect.DeepEqual(a, NewGenerator(cfg, 1).Batch(0, t0, 200)) {
		t.Fatal("different seed produced identical events")
	}
}

func TestGeneratorServicesAndLevels(t *testing.T) {
	g := NewGenerator(GenConfig{Services: 5, Seed: 1}, 0)
	want := []string{"payment-gateway", "auth-service", "ledger", "svc-04", "svc-05"}
	if !reflect.DeepEqual(g.ServiceNames(), want) {
		t.Fatalf("services %v", g.ServiceNames())
	}
	seen := map[string]int{}
	levels := map[string]int{}
	const n = 50_000
	for _, e := range g.Batch(0, t0, n) {
		seen[e.Service]++
		levels[e.Level]++
		if strings.ContainsAny(e.Message, "{}") {
			t.Fatalf("unfilled placeholder: %q", e.Message)
		}
	}
	if len(seen) != 5 {
		t.Fatalf("not all services generated: %v", seen)
	}
	// Baseline error rate is 1.5-2% for every service.
	if r := float64(levels["ERROR"]) / n; r < 0.01 || r > 0.03 {
		t.Fatalf("baseline error rate %.4f outside [1%%, 3%%]", r)
	}
}

func TestSpikeWindowsRaiseErrorRate(t *testing.T) {
	cfg := GenConfig{Services: 3, Seed: 3, SpikeEvery: 60 * time.Second, SpikeLen: 10 * time.Second, SpikeErrorRate: 0.6}
	g := NewGenerator(cfg, 0)

	spikes := g.Spikes(200 * time.Second)
	wantSpikes := []Spike{
		{"payment-gateway", 60, 70}, {"auth-service", 120, 130}, {"ledger", 180, 190},
	}
	if !reflect.DeepEqual(spikes, wantSpikes) {
		t.Fatalf("spikes %+v", spikes)
	}

	errRate := func(elapsed time.Duration, svc string) float64 {
		var errs, total int
		for _, e := range g.Batch(elapsed, t0, 30_000) {
			if e.Service == svc {
				total++
				if e.Level == "ERROR" {
					errs++
				}
			}
		}
		return float64(errs) / float64(total)
	}
	if r := errRate(65*time.Second, "payment-gateway"); r < 0.5 {
		t.Fatalf("spiking service error rate %.3f", r)
	}
	if r := errRate(65*time.Second, "ledger"); r > 0.05 {
		t.Fatalf("non-spiking service error rate %.3f during another's spike", r)
	}
	if r := errRate(75*time.Second, "payment-gateway"); r > 0.05 {
		t.Fatalf("error rate %.3f after spike ended", r)
	}
	if r := errRate(30*time.Second, "payment-gateway"); r > 0.05 {
		t.Fatalf("error rate %.3f in clean first period", r)
	}
}

func TestRenderReusesRepeatedPlaceholder(t *testing.T) {
	tm := compile("a={ip} b={ip} c={ms}")
	var sb strings.Builder
	out := tm.render(rand.New(rand.NewPCG(1, 1)), &sb)
	parts := strings.Fields(out)
	if strings.TrimPrefix(parts[0], "a=") != strings.TrimPrefix(parts[1], "b=") {
		t.Fatalf("repeated placeholder got different values: %q", out)
	}
}

func TestPercentiles(t *testing.T) {
	var ds []time.Duration
	for i := 1; i <= 100; i++ {
		ds = append(ds, time.Duration(i)*time.Millisecond)
	}
	p := percentiles(ds)
	if p.N != 100 || p.P50 != 50 || p.P99 != 99 || p.Max != 100 {
		t.Fatalf("%+v", p)
	}
	if (percentiles(nil) != Percentiles{}) {
		t.Fatal("empty input")
	}
}

func TestBackoffHonoursRetryAfterWithJitter(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 100 {
		d := backoff("2", 0, r)
		if d < time.Second || d >= 3*time.Second {
			t.Fatalf("backoff %v outside [1s, 3s)", d)
		}
	}
}

// fakeServer answers in a fixed rotation of status codes.
func fakeServer(t *testing.T, codes ...int) (*httptest.Server, *atomic.Int64) {
	var n, events atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Events []wireEvent }
		data, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(data, &body); err != nil {
			t.Errorf("bad body: %v", err)
		}
		code := codes[int(n.Add(1)-1)%len(codes)]
		if code == http.StatusOK {
			events.Add(int64(len(body.Events)))
		}
		if code == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "1")
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return srv, &events
}

func testOptions(url string) options {
	return options{
		url: url, rate: 2000, duration: 500 * time.Millisecond, batch: 10,
		concurrency: 8, timeout: 5 * time.Second, gen: GenConfig{Services: 3, Seed: 1},
	}
}

func TestRunLoadPacesAndCounts(t *testing.T) {
	srv, serverEvents := fakeServer(t, http.StatusOK, http.StatusTooManyRequests)
	s := runLoad(testOptions(srv.URL), io.Discard)

	// 2000 ev/s / 10 per batch * 0.5 s = 100 scheduled requests.
	if got := s.Requests + s.ClientDropped; got != 100 {
		t.Fatalf("scheduled %d requests, want 100", got)
	}
	if s.OK+s.R429 != s.Requests || s.R429 == 0 || s.OK == 0 {
		t.Fatalf("bad split %+v", s)
	}
	if s.EventsAccepted != serverEvents.Load() {
		t.Fatalf("client counted %d accepted events, server %d", s.EventsAccepted, serverEvents.Load())
	}
	if !s.AllRejections429 {
		t.Fatal("429-only rejections should pass the acceptance check")
	}
	if s.ElapsedS > 2 {
		t.Fatalf("run took %.2fs, pacing is off", s.ElapsedS)
	}
}

func TestRunLoadFlagsUnexpectedStatus(t *testing.T) {
	srv, _ := fakeServer(t, http.StatusOK, http.StatusInternalServerError)
	s := runLoad(testOptions(srv.URL), io.Discard)
	if s.AllRejections429 || s.OtherStatus == 0 || s.OtherStatusCodes[500] != s.OtherStatus {
		t.Fatalf("500s not reported: %+v", s)
	}
}

func TestRunLoadRetriesOn429(t *testing.T) {
	srv, _ := fakeServer(t, http.StatusTooManyRequests, http.StatusOK)
	o := testOptions(srv.URL)
	o.retry, o.maxRetries = true, 3
	o.rate, o.duration, o.concurrency = 100, 100*time.Millisecond, 2 // 1 batch
	s := runLoad(o, io.Discard)
	if s.Retries != 1 || s.OK != 1 || s.R429 != 1 || s.EventsSent != 10 {
		t.Fatalf("%+v", s)
	}
}

func TestRunLoadPregenSendsValidBodies(t *testing.T) {
	srv, serverEvents := fakeServer(t, http.StatusOK)
	o := testOptions(srv.URL)
	o.pregen = 4
	s := runLoad(o, io.Discard)
	if s.OK == 0 || s.EventsAccepted != serverEvents.Load() || s.Spikes != nil {
		t.Fatalf("%+v", s)
	}
}

func TestWriteFile(t *testing.T) {
	path := t.TempDir() + "/out.jsonl"
	o := testOptions("")
	o.toFile, o.count, o.rate = path, 50, 1000
	if err := writeFile(o); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 50 {
		t.Fatalf("%d lines", len(lines))
	}
	var e wireEvent
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil || e.Service == "" || e.Message == "" {
		t.Fatalf("bad line %q: %v", lines[0], err)
	}
}
