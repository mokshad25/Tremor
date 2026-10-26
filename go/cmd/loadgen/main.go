// Command loadgen drives TREMOR with realistic log traffic.
//
// It is open-loop: requests are scheduled at a fixed rate regardless of how
// fast the server answers. If every worker is busy when a request is due, the
// request is counted as client_dropped instead of being sent late. A closed-
// loop generator (send the next request when the last returns) slows down when
// the server slows down and hides overload ("coordinated omission"); open
// loop keeps the offered load honest.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type options struct {
	url         string
	rate        float64 // events per second
	duration    time.Duration
	batch       int
	concurrency int
	timeout     time.Duration
	retry       bool
	maxRetries  int
	progress    time.Duration
	out         string
	pregen      int    // >0: cycle this many pre-built bodies (throughput tests)
	body        string // "events": {"events":[...]} (TREMOR); "array": [...] (Fluent Bit, Vector)
	toFile      string
	count       int
	attack      string
	attackAt    time.Duration
	attackGap   time.Duration
	replaySSH   string
	speed       float64
	year        int
	gen         GenConfig
}

func main() {
	var o options
	flag.StringVar(&o.url, "url", "http://localhost:8080/ingest", "ingest endpoint")
	flag.Float64Var(&o.rate, "rate", 10000, "offered load in events/sec")
	flag.DurationVar(&o.duration, "duration", 30*time.Second, "run length")
	flag.IntVar(&o.batch, "batch", 100, "events per request")
	flag.IntVar(&o.concurrency, "concurrency", 64, "max in-flight requests (connections)")
	flag.DurationVar(&o.timeout, "timeout", 30*time.Second, "per-request timeout")
	flag.BoolVar(&o.retry, "retry", false, "retry 429/503 after Retry-After with jitter (realistic producer); off = pure open-loop overload")
	flag.IntVar(&o.maxRetries, "max-retries", 5, "retries per batch when -retry is set")
	flag.DurationVar(&o.progress, "progress", 5*time.Second, "progress line interval (0 disables)")
	flag.StringVar(&o.out, "out", "", "write JSON summary to this file")
	flag.StringVar(&o.attack, "attack", "", "inject attacks into the run: brute_force, credential_stuffing, privilege_change, unusual_access (comma-separated) or all")
	flag.DurationVar(&o.attackAt, "attack-at", 20*time.Second, "when the first attack starts")
	flag.DurationVar(&o.attackGap, "attack-gap", 90*time.Second, "time between attacks")
	flag.StringVar(&o.replaySSH, "replay-ssh", "", "send a Loghub OpenSSH log (e.g. bench/data/OpenSSH_2k.log) instead of synthetic traffic")
	flag.Float64Var(&o.speed, "speed", 60, "-replay-ssh pacing: log time / speed (0 = as fast as possible)")
	flag.IntVar(&o.year, "year", 2017, "year for syslog timestamps in -replay-ssh")
	flag.StringVar(&o.toFile, "to-file", "", "instead of sending, write -count events as JSON lines to this file (input for collectors and other pipelines)")
	flag.IntVar(&o.count, "count", 100000, "events to write with -to-file")
	flag.IntVar(&o.pregen, "pregen", 0, "pre-build this many batch bodies and cycle them, so generation cost does not compete with the server for CPU (timestamps and spikes are fixed; throughput tests only)")
	flag.StringVar(&o.body, "body", "events", `request body: "events" sends {"events":[...]} (TREMOR's /ingest); "array" sends a bare JSON array of the same events (other collectors' HTTP inputs, for benchmarks)`)
	flag.IntVar(&o.gen.Services, "services", 3, "number of services")
	flag.Uint64Var(&o.gen.Seed, "seed", 42, "RNG seed")
	flag.DurationVar(&o.gen.SpikeEvery, "spike-every", 0, "start an error spike every this often (0 = none)")
	flag.DurationVar(&o.gen.SpikeLen, "spike-len", 30*time.Second, "length of each error spike")
	flag.Float64Var(&o.gen.SpikeErrorRate, "spike-error-rate", 0.5, "ERROR probability during a spike")
	flag.Parse()

	if o.replaySSH != "" {
		if o.batch > 500 {
			o.batch = 500
		}
		if err := replaySSH(o); err != nil {
			fmt.Fprintln(os.Stderr, "loadgen:", err)
			os.Exit(1)
		}
		return
	}
	if o.toFile != "" {
		if err := writeFile(o); err != nil {
			fmt.Fprintln(os.Stderr, "loadgen:", err)
			os.Exit(1)
		}
		return
	}
	if o.rate <= 0 || o.batch < 1 || o.concurrency < 1 || o.duration <= 0 {
		fmt.Fprintln(os.Stderr, "loadgen: rate, batch, concurrency and duration must be positive")
		os.Exit(2)
	}
	if o.body != "events" && o.body != "array" {
		fmt.Fprintln(os.Stderr, `loadgen: -body must be "events" or "array"`)
		os.Exit(2)
	}

	var attacks chan []AttackLabel
	if o.attack != "" {
		attacks = make(chan []AttackLabel, 1)
		start := time.Now()
		go func() {
			labels, err := runAttacks(o, start)
			if err != nil {
				fmt.Fprintln(os.Stderr, "loadgen: attack:", err)
			}
			attacks <- labels
		}()
	}
	sum := runLoad(o, os.Stderr)
	if attacks != nil {
		sum.Attacks = <-attacks
	}
	enc, _ := json.MarshalIndent(sum, "", "  ")
	fmt.Println(string(enc))
	if o.out != "" {
		if err := os.WriteFile(o.out, append(enc, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "loadgen:", err)
			os.Exit(1)
		}
	}
}

// counters are shared by all workers.
type counters struct {
	requests, ok, r429, r503, other, transport atomic.Int64
	dropped, retries, gaveUp                   atomic.Int64
	eventsSent, eventsAccepted                 atomic.Int64

	mu          sync.Mutex
	otherStatus map[int]int64
}

// workerStats are per-worker so latency recording needs no locks.
type workerStats struct {
	okLat, rejLat []time.Duration
	okSeen        int // for reservoir sampling
	rng           *rand.Rand
}

const maxLatencySamples = 50_000 // per worker; reservoir sampled beyond that

func (w *workerStats) recordOK(d time.Duration) {
	w.okSeen++
	if len(w.okLat) < maxLatencySamples {
		w.okLat = append(w.okLat, d)
	} else if j := w.rng.IntN(w.okSeen); j < maxLatencySamples {
		w.okLat[j] = d
	}
}

// job is one scheduled batch. due is when the open-loop schedule wanted it
// sent; latency is measured from due, so time spent waiting for a free worker
// counts against the server instead of being hidden.
type job struct {
	elapsed time.Duration
	due     time.Time
}

func runLoad(o options, progressOut io.Writer) Summary {
	tr := &http.Transport{
		MaxIdleConns:        o.concurrency,
		MaxIdleConnsPerHost: o.concurrency,
		MaxConnsPerHost:     o.concurrency,
		DisableCompression:  true,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: o.timeout}
	defer tr.CloseIdleConnections()

	c := &counters{otherStatus: map[int]int64{}}
	pool := pregenerate(o)
	// A small buffer absorbs scheduling jitter; once it is full, a due request
	// is dropped (and counted) rather than delayed.
	jobs := make(chan job, o.concurrency)
	stats := make([]*workerStats, o.concurrency)
	var wg sync.WaitGroup
	for i := range o.concurrency {
		ws := &workerStats{rng: rand.New(rand.NewPCG(o.gen.Seed, uint64(i)+1<<32))}
		stats[i] = ws
		gen := NewGenerator(o.gen, uint64(i))
		wg.Go(func() { worker(o, client, gen, pool, jobs, c, ws) })
	}

	interval := time.Duration(float64(time.Second) * float64(o.batch) / o.rate)
	start := time.Now()
	stopProgress := startProgress(o.progress, progressOut, c, start)

	for i := int64(0); ; i++ {
		due := time.Duration(i) * interval
		if due >= o.duration {
			break
		}
		if d := time.Until(start.Add(due)); d > 0 {
			time.Sleep(d)
		}
		select {
		case jobs <- job{elapsed: due, due: start.Add(due)}:
		default:
			c.dropped.Add(1)
		}
	}
	close(jobs)
	wg.Wait()
	stopProgress()
	elapsed := time.Since(start)

	var okLat, rejLat []time.Duration
	for _, ws := range stats {
		okLat = append(okLat, ws.okLat...)
		rejLat = append(rejLat, ws.rejLat...)
	}
	var spikes []Spike
	if pool == nil { // pre-built bodies never spike
		spikes = NewGenerator(o.gen, 0).Spikes(o.duration)
	}
	return Summary{
		URL: o.url, TargetEPS: o.rate, DurationS: o.duration.Seconds(), ElapsedS: elapsed.Seconds(),
		Batch: o.batch, Concurrency: o.concurrency, Services: NewGenerator(o.gen, 0).ServiceNames(), Retry: o.retry,
		Requests: c.requests.Load(), OK: c.ok.Load(), R429: c.r429.Load(), R503: c.r503.Load(),
		OtherStatus: c.other.Load(), OtherStatusCodes: c.otherStatus, TransportErrors: c.transport.Load(),
		ClientDropped: c.dropped.Load(), Retries: c.retries.Load(), GaveUp: c.gaveUp.Load(),
		EventsSent: c.eventsSent.Load(), EventsAccepted: c.eventsAccepted.Load(),
		AcceptedEPS:      float64(c.eventsAccepted.Load()) / elapsed.Seconds(),
		OfferedEPS:       float64(c.eventsSent.Load()+c.dropped.Load()*int64(o.batch)) / elapsed.Seconds(),
		OKLatencyMS:      percentiles(okLat),
		RejectLatencyMS:  percentiles(rejLat),
		Spikes:           spikes,
		Pregen:           o.pregen,
		AllRejections429: c.other.Load() == 0 && c.transport.Load() == 0,
	}
}

// pregenerate builds o.pregen request bodies up front, or returns nil.
func pregenerate(o options) [][]byte {
	if o.pregen <= 0 {
		return nil
	}
	gen := NewGenerator(o.gen, 1<<40)
	pool := make([][]byte, o.pregen)
	var buf bytes.Buffer
	for i := range pool {
		buf.Reset()
		encodeBatch(&buf, o.body, gen.Batch(0, time.Now(), o.batch))
		pool[i] = bytes.Clone(buf.Bytes())
	}
	return pool
}

func encodeBatch(buf *bytes.Buffer, format string, events []wireEvent) {
	var v any = struct {
		Events []wireEvent `json:"events"`
	}{events}
	if format == "array" {
		v = events
	}
	if err := json.NewEncoder(buf).Encode(v); err != nil {
		panic(err) // only possible on a programming error
	}
}

func worker(o options, client *http.Client, gen *Generator, pool [][]byte, jobs <-chan job, c *counters, ws *workerStats) {
	var buf bytes.Buffer
	next := ws.rng.IntN(max(len(pool), 1)) // workers start at different pool offsets
	for j := range jobs {
		var body []byte
		if pool != nil {
			body = pool[next%len(pool)]
			next++
		} else {
			buf.Reset()
			encodeBatch(&buf, o.body, gen.Batch(j.elapsed, time.Now(), o.batch))
			body = buf.Bytes()
		}
		c.eventsSent.Add(int64(o.batch)) // once per batch, not per retry

		for attempt := 0; ; attempt++ {
			c.requests.Add(1)
			resp, err := client.Post(o.url, "application/json", bytes.NewReader(body))
			if err != nil {
				c.transport.Add(1)
				break
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			lat := time.Since(j.due)

			switch resp.StatusCode {
			case http.StatusOK:
				c.ok.Add(1)
				c.eventsAccepted.Add(int64(o.batch))
				ws.recordOK(lat)
			case http.StatusTooManyRequests, http.StatusServiceUnavailable:
				if resp.StatusCode == http.StatusTooManyRequests {
					c.r429.Add(1)
				} else {
					c.r503.Add(1)
				}
				if len(ws.rejLat) < maxLatencySamples {
					ws.rejLat = append(ws.rejLat, lat)
				}
				if o.retry {
					if attempt < o.maxRetries {
						c.retries.Add(1)
						time.Sleep(backoff(resp.Header.Get("Retry-After"), attempt, ws.rng))
						continue
					}
					c.gaveUp.Add(1)
				}
			default:
				c.other.Add(1)
				c.mu.Lock()
				c.otherStatus[resp.StatusCode]++
				c.mu.Unlock()
			}
			break
		}
	}
}

// backoff honours Retry-After and adds full jitter so a crowd of rejected
// producers does not come back in lock-step (thundering herd).
func backoff(retryAfter string, attempt int, r *rand.Rand) time.Duration {
	base := time.Second
	if n, err := strconv.Atoi(retryAfter); err == nil && n > 0 {
		base = time.Duration(n) * time.Second
	}
	base <<= min(attempt, 4)
	return base/2 + time.Duration(r.Int64N(int64(base)))
}

func startProgress(every time.Duration, out io.Writer, c *counters, start time.Time) (stop func()) {
	if every <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		t := time.NewTicker(every)
		defer t.Stop()
		var lastAcc int64
		last := start
		for {
			select {
			case <-done:
				return
			case now := <-t.C:
				acc := c.eventsAccepted.Load()
				fmt.Fprintf(out, "t=%5.0fs accepted=%8.0f ev/s  ok=%d 429=%d 503=%d other=%d transport=%d dropped=%d\n",
					now.Sub(start).Seconds(), float64(acc-lastAcc)/now.Sub(last).Seconds(),
					c.ok.Load(), c.r429.Load(), c.r503.Load(), c.other.Load(), c.transport.Load(), c.dropped.Load())
				lastAcc, last = acc, now
			}
		}
	})
	return func() { close(done); wg.Wait() }
}

// Summary is the machine-readable result of a run.
type Summary struct {
	URL              string        `json:"url"`
	TargetEPS        float64       `json:"target_eps"`
	DurationS        float64       `json:"duration_s"`
	ElapsedS         float64       `json:"elapsed_s"`
	Batch            int           `json:"batch"`
	Concurrency      int           `json:"concurrency"`
	Services         []string      `json:"services"`
	Retry            bool          `json:"retry"`
	Requests         int64         `json:"requests"`
	OK               int64         `json:"ok"`
	R429             int64         `json:"rejected_429"`
	R503             int64         `json:"rejected_503"`
	OtherStatus      int64         `json:"other_status"`
	OtherStatusCodes map[int]int64 `json:"other_status_codes"`
	TransportErrors  int64         `json:"transport_errors"`
	ClientDropped    int64         `json:"client_dropped"`
	Retries          int64         `json:"retries"`
	GaveUp           int64         `json:"gave_up"`
	EventsSent       int64         `json:"events_sent"`
	EventsAccepted   int64         `json:"events_accepted"`
	OfferedEPS       float64       `json:"offered_eps"`
	AcceptedEPS      float64       `json:"accepted_eps"`
	OKLatencyMS      Percentiles   `json:"ok_latency_ms"`
	RejectLatencyMS  Percentiles   `json:"reject_latency_ms"`
	Spikes           []Spike       `json:"spikes,omitempty"`
	Pregen           int           `json:"pregen"`
	Attacks          []AttackLabel `json:"attacks,omitempty"` // ground truth for injected attacks
	// AllRejections429 is the Phase 1 acceptance check: every request the
	// server did not accept got an explicit 429/503 (no timeouts, resets or
	// 5xx surprises).
	AllRejections429 bool `json:"all_rejections_explicit"`
}

type Percentiles struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50"`
	P90 float64 `json:"p90"`
	P99 float64 `json:"p99"`
	Max float64 `json:"max"`
}

func percentiles(ds []time.Duration) Percentiles {
	if len(ds) == 0 {
		return Percentiles{}
	}
	slices.Sort(ds)
	at := func(q float64) float64 {
		i := int(q * float64(len(ds)-1))
		return float64(ds[i]) / float64(time.Millisecond)
	}
	return Percentiles{N: len(ds), P50: at(0.50), P90: at(0.90), P99: at(0.99), Max: at(1)}
}

// writeFile writes o.count events as JSON lines (one wireEvent per line),
// timestamps spaced to match -rate, spikes included. The same file can be
// tailed by an OpenTelemetry Collector, Vector or Fluent Bit.
func writeFile(o options) error {
	f, err := os.Create(o.toFile)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	enc := json.NewEncoder(w)
	gen := NewGenerator(o.gen, 0)
	start := time.Now().UTC()
	step := time.Duration(float64(time.Second) / o.rate)
	for i := range o.count {
		elapsed := time.Duration(i) * step
		if err := enc.Encode(gen.Event(elapsed, start.Add(elapsed))); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return f.Close()
}
