// Package server wires TREMOR's stages together and owns startup recovery
// and graceful shutdown.
//
//	gateway ─▶ ingest queue ─▶ WAL committer ─▶ dispatcher ─▶ shards ─────────────────▶ alerts
//	   (429)     (bounded)      (fsync, ack)   (consistent    (Drain + detection,
//	                                            hash ring)     checkpoint)
package server

import (
	"context"
	"crypto/rand"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"

	"github.com/mokshad/tremor/internal/config"
	"github.com/mokshad/tremor/internal/detect"
	"github.com/mokshad/tremor/internal/drain"
	"github.com/mokshad/tremor/internal/event"
	"github.com/mokshad/tremor/internal/ingest"
	"github.com/mokshad/tremor/internal/metrics"
	"github.com/mokshad/tremor/internal/pipeline"
	"github.com/mokshad/tremor/internal/redact"
	"github.com/mokshad/tremor/internal/router"
	"github.com/mokshad/tremor/internal/shard"
	"github.com/mokshad/tremor/internal/summarize"
	"github.com/mokshad/tremor/internal/wal"
)

// Server is one TREMOR process.
type Server struct {
	cfg config.Config
	log *slog.Logger

	Gateway metrics.Gateway
	Hist    *metrics.Histograms
	WAL     metrics.WAL
	Detect  metrics.Detect

	// AlertHook, if set, receives every alert notification (after it is
	// logged). Phase 6 replaces this with the correlator; tests use it now.
	AlertHook func(detect.Alert)
	// NoticeHook receives non-alert context (deploy notices).
	NoticeHook func(detect.Alert)
	// NotifyHook sees every incident notification (tests).
	NotifyHook func(summarize.Notification)

	LLM        summarize.LLMStats
	notifier   *summarize.Notifier
	dispatcher *summarize.Dispatcher

	// Ready, if set, receives the gateway's listen address once recovery is
	// complete and producers can connect.
	Ready chan<- string
	// OTLPHTTPAddr and OTLPGRPCAddr are the bound receiver addresses (set
	// before Ready fires; useful when the config asks for port 0).
	OTLPHTTPAddr, OTLPGRPCAddr string
	MetricsAddr                string // bound Prometheus listener

	// extraFamilies lets later stages (correlator, LLM, sinks) add metrics.
	extraFamilies []metrics.Family

	// PublishExpvar registers metrics in the global expvar registry. Only
	// one Server per process may do this, so tests leave it off.
	PublishExpvar bool
}

func New(cfg config.Config, log *slog.Logger) *Server {
	return &Server{cfg: cfg, log: log, Hist: metrics.NewHistograms()}
}

func (s *Server) checkpointPath() string { return filepath.Join(s.cfg.WAL.Dir, "checkpoint.json") }

// Run recovers from the WAL, serves until ctx is cancelled, then shuts down
// gracefully. The order of both sequences is what the delivery guarantee
// rests on; see docs/phase2-wal.md.
func (s *Server) Run(ctx context.Context) error {
	cfg := s.cfg

	// ── Recovery ────────────────────────────────────────────────────────
	// 1. Open the WAL: validate the last segment, truncate a torn tail.
	start := time.Now()
	wlog, rec, err := wal.Open(wal.Options{Dir: cfg.WAL.Dir, SegmentBytes: cfg.WAL.SegmentBytes, Fsync: cfg.WAL.Fsync}, s.log)
	if err != nil {
		return fmt.Errorf("open wal: %w", err)
	}
	defer wlog.Close()

	// 2. Load per-shard checkpoints for the current routing.
	nShards := cfg.Shards.Count
	if nShards == 0 {
		nShards = runtime.NumCPU()
	}
	rt := router.NewRing(nShards, router.DefaultVNodes)
	cp, found, err := wal.LoadCheckpoint(s.checkpointPath())
	if err != nil {
		return err
	}
	restored, reset := wal.RestoreShards(cp, found, nShards, rt.ID())
	if reset {
		s.log.Warn("routing changed since the last checkpoint; all shards replay from the minimum",
			"was", cp.Router, "now", rt.ID())
	}

	// 3. Start the alert stream and the shards.
	alerts := make(chan detect.Alert, 1024)
	alertsDone := make(chan struct{})
	runID := strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	// Redaction is built before the shards so allowlisted sources can be
	// tokenized with the same key.
	var redactor *redact.Redactor
	if cfg.Redact.Enabled {
		key := cfg.Redact.HMACKey
		if key == nil {
			key = make([]byte, 32)
			_, _ = rand.Read(key)
			s.log.Warn("TREMOR_HMAC_KEY not set: using a random key; ip_/usr_ tokens will change on restart")
		}
		redactor = redact.New(key)
	} else {
		s.log.Warn("PII redaction is DISABLED (redact.enabled=false): raw values will reach the WAL")
	}
	notifier, dispatcher := s.newNotifier(redactor)
	go notifier.Run()
	go func() { s.consumeAlerts(alerts, notifier); close(alertsDone) }()
	stopNotifier := func() { // after the alert stream is closed
		close(notifier.Alerts())
		notifier.Wait() // closes open incidents, finishes queued summaries
		dispatcher.Close()
	}
	allowed := map[string]bool{}
	for _, ip := range cfg.Detect.Security.AllowedSources {
		if redactor != nil {
			ip = redactor.Pseudonym(redact.KindIP, ip)
		}
		allowed[ip] = true
	}
	procs, err := s.newProcessors(nShards, runID, alerts, allowed)
	if err != nil {
		close(alerts)
		<-alertsDone
		stopNotifier()
		return err
	}
	shards := shard.NewSet(rt, restored, cfg.Shards.QueueCapacity, func(i int) shard.Processor { return procs[i] })
	shards.TickEvery = cfg.Shards.TickInterval
	shards.Start()
	shardsClosed := false
	defer func() {
		if !shardsClosed { // startup failed after the shards started
			shards.Close()
			shards.CloseProcessors()
			close(alerts)
			<-alertsDone
			stopNotifier()
		}
	}()

	// 4. Replay everything after the lowest checkpoint. Shards skip what
	//    they had already checkpointed, so only the overlap is redone.
	from := shards.MinRestored() + 1
	replayed, err := s.replay(wlog, shards, from)
	if err != nil {
		return fmt.Errorf("replay: %w", err)
	}
	s.WAL.RecordsReplayed.Add(int64(replayed))
	s.log.Info("recovery complete",
		"segments", rec.Segments, "last_seq", rec.LastSeq, "truncated_bytes", rec.TruncatedBytes,
		"replay_from", from, "replayed", replayed, "shards", nShards, "router", rt.ID(),
		"took", time.Since(start).String())

	// ── Steady state ────────────────────────────────────────────────────
	q := pipeline.NewQueue(cfg.Ingest.QueueCapacity)
	committer := &wal.Committer{
		Log:      wlog,
		Policy:   wal.SyncPolicy{EveryRecords: cfg.WAL.SyncEveryRecords, Interval: cfg.WAL.SyncInterval},
		Dispatch: shards,
		Metrics:  &s.WAL,
		Hist:     s.Hist,
		Logger:   s.log,
	}
	committerDone := make(chan struct{})
	go func() { committer.Run(q.Batches()); close(committerDone) }()

	ckpt := &checkpointer{s: s, shards: shards, wal: wlog, router: rt.ID()}
	ckptStop := make(chan struct{})
	var ckptWG sync.WaitGroup
	ckptWG.Go(func() { ckpt.loop(cfg.Checkpoint.Interval, ckptStop) })

	var red ingest.Redactor
	if redactor != nil {
		red = redactor
	}
	gw := ingest.NewGateway(q, &s.Gateway, ingest.Options{
		MaxBodyBytes:      cfg.Ingest.MaxBodyBytes,
		MaxEventsPerBatch: cfg.Ingest.MaxEventsPerBatch,
		RetryAfter:        cfg.Ingest.RetryAfter,
		AckTimeout:        cfg.Ingest.AckTimeout,
	}, red, s.log)
	srv := &http.Server{
		Handler:           gw.Routes(),
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		MaxHeaderBytes:    16 << 10,
	}
	ln, err := net.Listen("tcp", cfg.Server.ListenAddr)
	if err != nil {
		q.Close()
		<-committerDone
		close(ckptStop)
		ckptWG.Wait()
		return err
	}
	otlpHTTP, otlpGRPC, err := s.startOTLP(gw)
	if err != nil {
		_ = ln.Close()
		q.Close()
		<-committerDone
		close(ckptStop)
		ckptWG.Wait()
		return err
	}
	stats := func() map[string]int64 {
		m := shards.Stats()
		m["queue_depth"] = int64(q.Depth())
		m["queue_inflight"] = int64(q.InFlight())
		m["queue_capacity"] = int64(q.Capacity())
		m["wal_last_seq"] = int64(wlog.LastSeq())
		m["wal_segments"] = int64(wlog.Segments())
		if redactor != nil {
			for k, v := range redactor.Counts() {
				m["redactions_"+k+"_total"] = v
			}
		}
		return m
	}
	debugSrv := s.startDebug(stats)
	metricsSrv := s.startMetrics(s.families(q, wlog, shards, redactor))

	s.log.Info("tremor listening", "addr", ln.Addr().String(),
		"queue_capacity", cfg.Ingest.QueueCapacity, "max_buffered_bytes", cfg.MaxBufferedBytes(),
		"wal_dir", cfg.WAL.Dir, "fsync", cfg.WAL.Fsync,
		"sync_every_records", cfg.WAL.SyncEveryRecords, "sync_interval", cfg.WAL.SyncInterval.String())
	if s.Ready != nil {
		s.Ready <- ln.Addr().String()
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	var runErr error
	select {
	case err := <-serveErr:
		runErr = fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	// ── Shutdown ────────────────────────────────────────────────────────
	// Stop intake, let in-flight producers get their acks, then drain each
	// stage in pipeline order so nothing admitted is dropped.
	sdStart := time.Now()
	s.log.Info("shutdown: draining")
	gw.SetDraining()
	sctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	var sdWG sync.WaitGroup
	if otlpHTTP != nil {
		sdWG.Go(func() {
			if err := otlpHTTP.Shutdown(sctx); err != nil {
				_ = otlpHTTP.Close()
			}
		})
	}
	if otlpGRPC != nil {
		sdWG.Go(func() {
			done := make(chan struct{})
			go func() { otlpGRPC.GracefulStop(); close(done) }()
			select {
			case <-done:
			case <-sctx.Done():
				otlpGRPC.Stop()
			}
		})
	}
	if err := srv.Shutdown(sctx); errors.Is(err, context.DeadlineExceeded) {
		s.log.Warn("shutdown: handlers still running at timeout; closing connections")
		_ = srv.Close()
		runErr = errors.Join(runErr, err)
	}
	sdWG.Wait()
	q.Close()       // committer drains the queue, does a final fsync and acks
	<-committerDone //
	shards.Close()  // shards drain what was dispatched
	shardsClosed = true
	close(alerts) // no more producers: shards are done
	<-alertsDone
	stopNotifier()
	close(ckptStop)
	ckptWG.Wait()
	if err := ckpt.save(); err != nil { // final checkpoint: a clean restart replays nothing
		runErr = errors.Join(runErr, err)
	}
	if err := shards.CloseProcessors(); err != nil {
		runErr = errors.Join(runErr, err)
	}
	if err := wlog.Close(); err != nil {
		runErr = errors.Join(runErr, err)
	}
	if metricsSrv != nil {
		_ = metricsSrv.Close()
	}
	if debugSrv != nil {
		_ = debugSrv.Close()
	}
	g, w, st := s.Gateway.Snapshot(), s.WAL.Snapshot(), shards.Stats()
	s.log.Info("shutdown: complete", "took", time.Since(sdStart).String(),
		"events_accepted", g["events_accepted_total"],
		"wal_records_appended", w["wal_records_appended_total"],
		"events_processed", st["shard_events_processed_total"],
		"checkpoint_min", st["shard_checkpoint_min"], "wal_last_seq", wlog.LastSeq())
	return runErr
}

// newProcessors builds each shard's chain: detection (Drain + engines),
// plus the test-only processed log when configured.
func (s *Server) newProcessors(n int, runID string, alerts chan<- detect.Alert, allowed map[string]bool) ([]shard.Processor, error) {
	procs := make([]shard.Processor, n)
	for i := range procs {
		dp := detect.NewProcessor(s.cfg.Detect, drain.TremorConfig(), func(a detect.Alert) { alerts <- a })
		dp.SetAllowedSources(allowed)
		chain := shard.Chain{dp}
		if dir := s.cfg.Testing.ProcessedLogDir; dir != "" {
			p, err := shard.OpenProcessedLog(dir, runID, i)
			if err != nil {
				return nil, err
			}
			chain = append(chain, p)
		}
		procs[i] = chain
	}
	if s.cfg.Testing.ProcessedLogDir != "" {
		s.log.Warn("testing.processed_log_dir is set: every processed seq is written to disk (test harness only)")
	}
	return procs, nil
}

// consumeAlerts counts and logs every alert, then hands alerts and notices
// to the notifier (correlator -> summaries -> sinks).
func (s *Server) consumeAlerts(alerts <-chan detect.Alert, n *summarize.Notifier) {
	for a := range alerts {
		if a.Status == detect.StatusNotice {
			if s.NoticeHook != nil {
				s.NoticeHook(a)
			}
			n.Alerts() <- a
			continue // context for summaries, not an alert
		}
		switch a.Type {
		case detect.SignalErrorRate:
			s.Detect.ErrorRate.Add(1)
		case detect.SignalSilence:
			s.Detect.Silence.Add(1)
		case detect.SignalNewPattern:
			s.Detect.NewPattern.Add(1)
		case detect.SignalLatency:
			s.Detect.Latency.Add(1)
		case detect.SignalBruteForce:
			s.Detect.BruteForce.Add(1)
		case detect.SignalCredentialStuffing:
			s.Detect.CredentialStuffing.Add(1)
		case detect.SignalPrivilegeChange:
			s.Detect.PrivilegeChange.Add(1)
		case detect.SignalUnusualAccess:
			s.Detect.UnusualAccess.Add(1)
		}
		sev := a.Severity
		if a.Status == detect.StatusResolved {
			sev = "RESOLVED"
		}
		s.Detect.Count(string(a.Type), sev)
		switch {
		case a.Status == detect.StatusResolved:
			s.Detect.Resolved.Add(1)
		case a.Severity == "INFO":
			s.Detect.Info.Add(1)
		case a.Severity == "WARNING":
			s.Detect.Warning.Add(1)
		case a.Severity == "HIGH":
			s.Detect.High.Add(1)
		case a.Severity == "CRITICAL":
			s.Detect.Critical.Add(1)
		}
		s.log.Info("alert", "id", a.ID, "incident", a.IncidentID, "type", a.Type, "status", a.Status,
			"severity", a.Severity, "service", a.Service, "reason", a.Reason,
			"window_start", a.WindowStart, "window_end", a.WindowEnd,
			"seq_first", a.SourceSeqs.First, "seq_last", a.SourceSeqs.Last,
			"top_error_template", a.TopErrorTemplateText,
			"mitre_attack", a.Techniques, "user", a.User, "source", a.Source)
		if s.AlertHook != nil {
			s.AlertHook(a)
		}
		n.Alerts() <- a
	}
}

// newNotifier builds correlator -> guarded LLM -> sinks. Without an API key
// (or with llm.enabled false) summaries come from the template.
func (s *Server) newNotifier(red *redact.Redactor) (*summarize.Notifier, *summarize.Dispatcher) {
	cfg := s.cfg
	var llm summarize.Summarizer
	switch {
	case !cfg.LLM.Enabled:
		s.log.Info("llm summaries disabled (llm.enabled=false): template summaries only")
	case cfg.LLMAPIKey == "":
		s.log.Warn("TREMOR_LLM_API_KEY not set: template summaries only")
	default:
		llm = &summarize.OpenAICompatible{Endpoint: cfg.LLM.Endpoint, Model: cfg.LLM.Model, APIKey: cfg.LLMAPIKey,
			MaxTokens: cfg.LLM.MaxTokens, Temperature: cfg.LLM.Temperature,
			HTTP: &http.Client{Timeout: time.Duration(cfg.LLM.TimeoutS+5) * time.Second}}
		s.log.Info("llm summaries enabled", "provider", cfg.LLM.Provider, "model", cfg.LLM.Model, "rate_per_minute", cfg.LLM.RatePerMinute)
	}
	var scrub func(string) string
	if red != nil {
		scrub = red.String // second redaction pass on exactly what leaves the process
	}
	guarded := summarize.NewGuarded(llm, cfg.LLM, scrub, &s.LLM)
	guarded.Observe = s.Hist.ObserveLLM
	var sinks []summarize.Sink
	client := &http.Client{Timeout: 10 * time.Second}
	if cfg.Notify.WebhookURL != "" {
		sinks = append(sinks, &summarize.Webhook{URL: cfg.Notify.WebhookURL, Secret: cfg.Notify.WebhookSecret, HTTP: client})
	}
	if cfg.Notify.SlackURL != "" {
		sinks = append(sinks, &summarize.Slack{URL: cfg.Notify.SlackURL, HTTP: client})
	}
	if len(sinks) == 0 {
		s.log.Info("no notification sinks configured (notify.webhook_url, TREMOR_SLACK_WEBHOOK_URL): incidents are logged and exported as metrics only")
	}
	disp := summarize.NewDispatcher(sinks, cfg.Notify.QueueLength, s.log)
	n := summarize.NewNotifier(summarize.NotifierConfig{MinSeverity: cfg.Notify.MinSeverity, Delay: time.Duration(cfg.LLM.DelayS) * time.Second},
		summarize.NewCorrelator(cfg.Correlator), guarded, disp, s.log)
	n.OnNotify = func(note summarize.Notification) {
		s.log.Info("incident", "kind", note.Kind, "incident", note.IncidentID, "severity", note.Severity, "services", note.Services,
			"alerts", note.AlertCount, "summary_source", note.Summary.Source, "fallback_reason", note.Summary.FallbackReason,
			"summary", note.Summary.Summary, "likely_trigger", note.Summary.LikelyTrigger)
		if s.NotifyHook != nil {
			s.NotifyHook(note)
		}
	}
	s.notifier, s.dispatcher = n, disp
	s.extraFamilies = append(s.extraFamilies, s.summaryFamilies()...)
	return n, disp
}

// summaryFamilies export incident, LLM and sink metrics.
func (s *Server) summaryFamilies() []metrics.Family {
	l := &s.LLM
	return []metrics.Family{
		{Name: "tremor_incidents_total", Help: "Incidents by lifecycle event.", Counter: true, LabelNames: []string{"event"},
			Read: func() []metrics.Sample {
				st := &s.notifier.Stats
				return []metrics.Sample{{Labels: []string{"opened"}, Value: float64(st.Opened.Load())},
					{Labels: []string{"paged"}, Value: float64(st.Paged.Load())}, {Labels: []string{"closed"}, Value: float64(st.Closed.Load())}}
			}},
		{Name: "tremor_incidents_open", Help: "Incidents currently open.", Read: func() []metrics.Sample { return metrics.One(float64(s.notifier.Stats.Open.Load())) }},
		{Name: "tremor_llm_requests_total", Help: "LLM summary requests by outcome.", Counter: true, LabelNames: []string{"result"},
			Read: func() []metrics.Sample {
				return []metrics.Sample{{Labels: []string{"ok"}, Value: float64(l.OK.Load())}, {Labels: []string{"error"}, Value: float64(l.Errors.Load())},
					{Labels: []string{"invalid_output"}, Value: float64(l.Invalid.Load())}, {Labels: []string{"rate_limited"}, Value: float64(l.RateLimited.Load())},
					{Labels: []string{"cache_hit"}, Value: float64(l.CacheHits.Load())}}
			}},
		{Name: "tremor_llm_tokens_total", Help: "LLM tokens used.", Counter: true, LabelNames: []string{"kind"},
			Read: func() []metrics.Sample {
				return []metrics.Sample{{Labels: []string{"prompt"}, Value: float64(l.PromptTokens.Load())}, {Labels: []string{"completion"}, Value: float64(l.CompletionTokens.Load())}}
			}},
		{Name: "tremor_summary_fallbacks_total", Help: "Template summaries served instead of the LLM.", Counter: true, Read: func() []metrics.Sample { return metrics.One(float64(l.Fallbacks.Load())) }},
		{Name: "tremor_notifications_total", Help: "Notification deliveries by sink and result.", Counter: true, LabelNames: []string{"sink", "result"},
			Read: func() []metrics.Sample {
				var out []metrics.Sample
				for name, st := range s.dispatcher.Stats {
					out = append(out, metrics.Sample{Labels: []string{name, "sent"}, Value: float64(st.Sent.Load())},
						metrics.Sample{Labels: []string{name, "failed"}, Value: float64(st.Failed.Load())},
						metrics.Sample{Labels: []string{name, "dropped"}, Value: float64(st.Dropped.Load())})
				}
				return out
			}},
	}
}

// replay streams WAL records from `from` to the shards in chunks, each
// with a watermark, exactly as live dispatch would.
func (s *Server) replay(l *wal.Log, shards *shard.Set, from uint64) (int, error) {
	const chunk = 4096
	buf := make([]event.Event, 0, chunk)
	flush := func() {
		if len(buf) > 0 {
			shards.Dispatch([][]event.Event{buf}, buf[len(buf)-1].Seq)
			buf = make([]event.Event, 0, chunk) // shards own the dispatched slice
		}
	}
	n, err := l.Replay(from, func(ev *event.Event) error {
		buf = append(buf, *ev)
		if len(buf) == chunk {
			flush()
		}
		return nil
	})
	flush()
	return n, err
}

// checkpointer periodically persists shard checkpoints and then deletes WAL
// segments that every shard has moved past.
type checkpointer struct {
	s      *Server
	shards *shard.Set
	wal    *wal.Log
	router string
	last   []uint64
}

func (c *checkpointer) loop(every time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if err := c.save(); err != nil {
				c.s.log.Error("checkpoint failed", "err", err)
			}
		}
	}
}

func (c *checkpointer) save() error {
	cps, err := c.shards.Snapshot() // reads checkpoints, then flushes processors
	if err != nil {
		return err
	}
	if c.last != nil && equal(cps, c.last) {
		return nil
	}
	if err := wal.SaveCheckpoint(c.s.checkpointPath(), wal.Checkpoint{Router: c.router, Shards: cps}); err != nil {
		return err
	}
	c.last = cps
	c.s.WAL.CheckpointsSaved.Add(1)
	// Only now, with the checkpoint durable, is it safe to delete segments.
	low := cps[0]
	for _, v := range cps[1:] {
		low = min(low, v)
	}
	removed, err := c.wal.Cleanup(low)
	c.s.WAL.SegmentsRemoved.Add(int64(removed))
	return err
}

func equal(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// startDebug serves expvar and pprof on a separate (by default loopback-only)
// listener so profiling endpoints are never exposed on the ingest port.
func (s *Server) startDebug(stats metrics.Source) *http.Server {
	addr := s.cfg.Server.DebugAddr
	if addr == "" {
		return nil
	}
	if s.PublishExpvar {
		metrics.Publish(s.Gateway.Snapshot, s.WAL.Snapshot, s.Detect.Snapshot, stats)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /debug/vars", expvar.Handler())
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("debug server", "err", err)
		}
	}()
	return srv
}

// startOTLP starts the OTLP/HTTP and OTLP/gRPC receivers (if configured).
func (s *Server) startOTLP(gw *ingest.Gateway) (*http.Server, *grpc.Server, error) {
	var hs *http.Server
	var gs *grpc.Server
	if addr := s.cfg.OTLP.HTTPAddr; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("otlp http: %w", err)
		}
		hs = &http.Server{
			Handler:           gw.OTLPHTTP(),
			ReadHeaderTimeout: s.cfg.Server.ReadHeaderTimeout,
			ReadTimeout:       s.cfg.Server.ReadTimeout,
			WriteTimeout:      s.cfg.Server.WriteTimeout,
			IdleTimeout:       s.cfg.Server.IdleTimeout,
		}
		go func() { _ = hs.Serve(ln) }()
		s.OTLPHTTPAddr = ln.Addr().String()
		s.log.Info("otlp/http listening", "addr", s.OTLPHTTPAddr, "path", "/v1/logs")
	}
	if addr := s.cfg.OTLP.GRPCAddr; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			if hs != nil {
				_ = hs.Close()
			}
			return nil, nil, fmt.Errorf("otlp grpc: %w", err)
		}
		gs = gw.NewOTLPGRPCServer()
		go func() { _ = gs.Serve(ln) }()
		s.OTLPGRPCAddr = ln.Addr().String()
		s.log.Info("otlp/grpc listening", "addr", s.OTLPGRPCAddr)
	}
	return hs, gs, nil
}

// families are the metrics computed when Prometheus scrapes. Rates (events
// per second, 429s per second) are derived in PromQL with rate().
func (s *Server) families(q *pipeline.Queue, wlog *wal.Log, shards *shard.Set, red *redact.Redactor) []metrics.Family {
	g, w := &s.Gateway, &s.WAL
	c := func(v *atomic.Int64) func() []metrics.Sample {
		return func() []metrics.Sample { return metrics.One(float64(v.Load())) }
	}
	minCheckpoint := func() uint64 {
		ps := shards.PerShard()
		low := ps[0].Checkpoint
		for _, p := range ps[1:] {
			low = min(low, p.Checkpoint)
		}
		return low
	}
	return []metrics.Family{
		{Name: "tremor_ingest_requests_total", Help: "Ingest requests by outcome (all receivers).", Counter: true, LabelNames: []string{"result"},
			Read: func() []metrics.Sample {
				return []metrics.Sample{
					{Labels: []string{"accepted"}, Value: float64(g.RequestsAccepted.Load())},
					{Labels: []string{"rejected_429"}, Value: float64(g.Rejected429.Load())},
					{Labels: []string{"rejected_503"}, Value: float64(g.Rejected503.Load())},
					{Labels: []string{"bad_request"}, Value: float64(g.RejectedBad.Load())},
				}
			}},
		{Name: "tremor_events_accepted_total", Help: "Events acknowledged to producers (fsynced).", Counter: true, Read: c(&g.EventsAccepted)},
		{Name: "tremor_events_processed_total", Help: "Events processed by the shards.", Counter: true,
			Read: func() []metrics.Sample { return metrics.One(float64(shards.Stats()["shard_events_processed_total"])) }},
		{Name: "tremor_events_replayed_total", Help: "WAL records replayed at startup.", Counter: true, Read: c(&w.RecordsReplayed)},
		{Name: "tremor_queue_depth", Help: "Batches waiting in a stage's queue.", LabelNames: []string{"stage"},
			Read: func() []metrics.Sample {
				return []metrics.Sample{{Labels: []string{"ingest"}, Value: float64(q.Depth())}}
			}},
		{Name: "tremor_ingest_inflight_batches", Help: "Admission slots in use (decoding, queued, waiting for fsync).", Read: func() []metrics.Sample { return metrics.One(float64(q.InFlight())) }},
		{Name: "tremor_ingest_capacity_batches", Help: "Admission slots in total.", Read: func() []metrics.Sample { return metrics.One(float64(q.Capacity())) }},
		{Name: "tremor_shard_queue_depth", Help: "Dispatch messages waiting for each shard.", LabelNames: []string{"shard"},
			Read: func() []metrics.Sample {
				var out []metrics.Sample
				for i, p := range shards.PerShard() {
					out = append(out, metrics.Sample{Labels: []string{strconv.Itoa(i)}, Value: float64(p.Depth)})
				}
				return out
			}},
		{Name: "tremor_shard_events_processed_total", Help: "Events processed per shard.", Counter: true, LabelNames: []string{"shard"},
			Read: func() []metrics.Sample {
				var out []metrics.Sample
				for i, p := range shards.PerShard() {
					out = append(out, metrics.Sample{Labels: []string{strconv.Itoa(i)}, Value: float64(p.Processed)})
				}
				return out
			}},
		{Name: "tremor_wal_last_seq", Help: "Last sequence number appended to the WAL.", Read: func() []metrics.Sample { return metrics.One(float64(wlog.LastSeq())) }},
		{Name: "tremor_checkpoint_min_seq", Help: "Lowest shard checkpoint.", Read: func() []metrics.Sample { return metrics.One(float64(minCheckpoint())) }},
		{Name: "tremor_checkpoint_lag_records", Help: "WAL records not yet covered by every shard's checkpoint (replay size after a crash).",
			Read: func() []metrics.Sample {
				last, low := wlog.LastSeq(), minCheckpoint()
				return metrics.One(float64(last - min(low, last)))
			}},
		{Name: "tremor_wal_segments", Help: "WAL segment files on disk.", Read: func() []metrics.Sample { return metrics.One(float64(wlog.Segments())) }},
		{Name: "tremor_wal_records_total", Help: "Records appended to the WAL.", Counter: true, Read: c(&w.RecordsAppended)},
		{Name: "tremor_wal_bytes_total", Help: "Bytes appended to the WAL.", Counter: true, Read: c(&w.BytesAppended)},
		{Name: "tremor_wal_sync_errors_total", Help: "Failed fsyncs (the WAL then refuses all work).", Counter: true, Read: c(&w.SyncErrors)},
		{Name: "tremor_wal_segments_removed_total", Help: "Segments deleted after every shard checkpointed past them.", Counter: true, Read: c(&w.SegmentsRemoved)},
		{Name: "tremor_redactions_total", Help: "PII values redacted, by type (counts only, never values).", Counter: true, LabelNames: []string{"type"},
			Read: func() []metrics.Sample {
				if red == nil {
					return nil
				}
				var out []metrics.Sample
				for k, v := range red.Counts() {
					out = append(out, metrics.Sample{Labels: []string{k}, Value: float64(v)})
				}
				return out
			}},
		{Name: "tremor_alerts_total", Help: "Alert notifications by signal type and severity (RESOLVED for resolutions).", Counter: true, LabelNames: []string{"type", "severity"},
			Read: func() []metrics.Sample {
				var out []metrics.Sample
				for k, v := range s.Detect.Pairs() {
					out = append(out, metrics.Sample{Labels: []string{k[0], k[1]}, Value: float64(v)})
				}
				return out
			}},
	}
}

// startMetrics serves Prometheus /metrics on its own listener so it can be
// exposed to a scraper without exposing pprof.
func (s *Server) startMetrics(fams []metrics.Family) *http.Server {
	addr := s.cfg.Server.MetricsAddr
	if addr == "" {
		return nil
	}
	reg := metrics.NewRegistry(s.Hist, append(fams, s.extraFamilies...))
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.log.Error("metrics listener", "err", err)
		return nil
	}
	s.MetricsAddr = ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	return srv
}
