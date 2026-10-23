// Package config loads TREMOR's YAML configuration. Non-secret settings live
// in one YAML file; a few operational overrides and all secrets (from Phase 4
// on: HMAC key, LLM API key) come from TREMOR_* environment variables so they
// never sit in a file that might be committed.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mokshad/tremor/internal/detect"
	"github.com/mokshad/tremor/internal/summarize"
)

type Config struct {
	Server     Server                     `yaml:"server"`
	Ingest     Ingest                     `yaml:"ingest"`
	WAL        WAL                        `yaml:"wal"`
	Checkpoint Checkpoint                 `yaml:"checkpoint"`
	Shards     Shards                     `yaml:"shards"`
	Detect     detect.Config              `yaml:"detect"`
	OTLP       OTLP                       `yaml:"otlp"`
	Redact     Redact                     `yaml:"redact"`
	Correlator summarize.CorrelatorConfig `yaml:"correlator"`
	LLM        summarize.LLMConfig        `yaml:"llm"`
	Notify     Notify                     `yaml:"notify"`
	Testing    Testing                    `yaml:"testing"`

	// LLMAPIKey comes only from TREMOR_LLM_API_KEY, never from YAML.
	LLMAPIKey string `yaml:"-"`
}

// OTLP receivers. An empty address disables that receiver.
type OTLP struct {
	HTTPAddr string `yaml:"http_addr"` // OTLP/HTTP, POST /v1/logs
	GRPCAddr string `yaml:"grpc_addr"` // OTLP/gRPC LogsService
}

// Redact controls PII redaction, which runs before the WAL.
type Redact struct {
	// Enabled false is only for measuring redaction's cost (TREMOR_REDACT).
	Enabled bool `yaml:"enabled"`
	// HMACKey tokenizes IPs and usernames. It comes only from the
	// TREMOR_HMAC_KEY environment variable, never from the YAML file.
	HMACKey []byte `yaml:"-"`
}

type Server struct {
	ListenAddr        string        `yaml:"listen_addr"`
	DebugAddr         string        `yaml:"debug_addr"`   // expvar + pprof; "" disables
	MetricsAddr       string        `yaml:"metrics_addr"` // Prometheus /metrics; "" disables
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	ShutdownTimeout   time.Duration `yaml:"shutdown_timeout"`
}

type Ingest struct {
	MaxBodyBytes      int64         `yaml:"max_body_bytes"`
	MaxEventsPerBatch int           `yaml:"max_events_per_batch"`
	QueueCapacity     int           `yaml:"queue_capacity"` // batches admitted at once
	RetryAfter        time.Duration `yaml:"retry_after"`
	AckTimeout        time.Duration `yaml:"ack_timeout"`
}

type WAL struct {
	Dir              string        `yaml:"dir"`
	SegmentBytes     int64         `yaml:"segment_bytes"`
	SyncEveryRecords int           `yaml:"sync_every_records"`
	SyncInterval     time.Duration `yaml:"sync_interval"`
	// Fsync false makes acks mean "written to the page cache". Only for
	// measuring what durability costs; never in production.
	Fsync bool `yaml:"fsync"`
}

type Checkpoint struct {
	Interval time.Duration `yaml:"interval"` // stored at <wal.dir>/checkpoint.json
}

type Shards struct {
	Count         int           `yaml:"count"`          // 0 = number of CPUs
	QueueCapacity int           `yaml:"queue_capacity"` // messages buffered per shard
	TickInterval  time.Duration `yaml:"tick_interval"`  // wall-clock ticks when no events arrive
}

// Notify configures where incident notifications go. URLs that embed
// credentials (Slack webhooks) and the webhook signing secret come only from
// the environment: TREMOR_SLACK_WEBHOOK_URL, TREMOR_WEBHOOK_SECRET.
type Notify struct {
	MinSeverity   string `yaml:"min_severity"` // incidents below this are recorded, not sent
	WebhookURL    string `yaml:"webhook_url"`  // generic JSON webhook (or TREMOR_WEBHOOK_URL)
	QueueLength   int    `yaml:"queue_length"` // per sink; full queues drop (counted)
	WebhookSecret []byte `yaml:"-"`
	SlackURL      string `yaml:"-"`
}

// Testing holds settings that only test harnesses use.
type Testing struct {
	// ProcessedLogDir, if set, makes every shard record the seq of each
	// event it processes (cmd/chaos verifies these against acked seqs).
	ProcessedLogDir string `yaml:"processed_log_dir"`
}

// Default returns the configuration used when a field is not set.
func Default() Config {
	return Config{
		Server: Server{
			ListenAddr:        ":8080",
			DebugAddr:         "127.0.0.1:6060",
			MetricsAddr:       ":2112",
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
			ShutdownTimeout:   30 * time.Second,
		},
		Ingest: Ingest{
			MaxBodyBytes:      1 << 20,
			MaxEventsPerBatch: 5000,
			QueueCapacity:     256,
			RetryAfter:        time.Second,
			AckTimeout:        10 * time.Second,
		},
		WAL: WAL{
			Dir:              "./data/wal",
			SegmentBytes:     64 << 20,
			SyncEveryRecords: 10000,
			SyncInterval:     10 * time.Millisecond,
			Fsync:            true,
		},
		Checkpoint: Checkpoint{Interval: time.Second},
		Shards:     Shards{Count: 0, QueueCapacity: 16, TickInterval: time.Second},
		Detect:     detect.DefaultConfig(),
		OTLP:       OTLP{HTTPAddr: ":4318", GRPCAddr: ":4317"},
		Redact:     Redact{Enabled: true},
		Correlator: summarize.DefaultCorrelatorConfig(),
		LLM:        summarize.DefaultLLMConfig(),
		Notify:     Notify{MinSeverity: "WARNING", QueueLength: 256},
	}
}

// Load reads path (if non-empty) over the defaults, applies environment
// overrides and validates the result. Unknown YAML keys are an error so a
// typo cannot silently fall back to a default.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		// io.EOF: an empty file means "all defaults".
		if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
			return Config{}, fmt.Errorf("config %s: %w", path, err)
		}
	}
	if err := applyEnv(&cfg, os.LookupEnv); err != nil {
		return Config{}, err
	}
	return cfg, cfg.Validate()
}

func applyEnv(cfg *Config, lookup func(string) (string, bool)) error {
	if v, ok := lookup("TREMOR_LISTEN_ADDR"); ok {
		cfg.Server.ListenAddr = v
	}
	if v, ok := lookup("TREMOR_METRICS_ADDR"); ok {
		cfg.Server.MetricsAddr = v
	}
	if v, ok := lookup("TREMOR_DEBUG_ADDR"); ok {
		cfg.Server.DebugAddr = v
	}
	if v, ok := lookup("TREMOR_QUEUE_CAPACITY"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("TREMOR_QUEUE_CAPACITY: %w", err)
		}
		cfg.Ingest.QueueCapacity = n
	}
	if v, ok := lookup("TREMOR_WAL_DIR"); ok {
		cfg.WAL.Dir = v
	}
	if v, ok := lookup("TREMOR_WAL_SYNC_EVERY_RECORDS"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("TREMOR_WAL_SYNC_EVERY_RECORDS: %w", err)
		}
		cfg.WAL.SyncEveryRecords = n
	}
	if v, ok := lookup("TREMOR_WAL_SYNC_INTERVAL"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("TREMOR_WAL_SYNC_INTERVAL: %w", err)
		}
		cfg.WAL.SyncInterval = d
	}
	if v, ok := lookup("TREMOR_WAL_FSYNC"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("TREMOR_WAL_FSYNC: %w", err)
		}
		cfg.WAL.Fsync = b
	}
	if v, ok := lookup("TREMOR_SHARDS"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("TREMOR_SHARDS: %w", err)
		}
		cfg.Shards.Count = n
	}
	if v, ok := lookup("TREMOR_LLM_API_KEY"); ok {
		cfg.LLMAPIKey = v
	}
	if v, ok := lookup("TREMOR_LLM_ENABLED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("TREMOR_LLM_ENABLED: %w", err)
		}
		cfg.LLM.Enabled = b
	}
	if v, ok := lookup("TREMOR_WEBHOOK_URL"); ok {
		cfg.Notify.WebhookURL = v
	}
	if v, ok := lookup("TREMOR_WEBHOOK_SECRET"); ok {
		cfg.Notify.WebhookSecret = []byte(v)
	}
	if v, ok := lookup("TREMOR_SLACK_WEBHOOK_URL"); ok {
		cfg.Notify.SlackURL = v
	}
	if v, ok := lookup("TREMOR_HMAC_KEY"); ok {
		cfg.Redact.HMACKey = []byte(v)
	}
	if v, ok := lookup("TREMOR_REDACT"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("TREMOR_REDACT: %w", err)
		}
		cfg.Redact.Enabled = b
	}
	if v, ok := lookup("TREMOR_OTLP_HTTP_ADDR"); ok {
		cfg.OTLP.HTTPAddr = v
	}
	if v, ok := lookup("TREMOR_OTLP_GRPC_ADDR"); ok {
		cfg.OTLP.GRPCAddr = v
	}
	if v, ok := lookup("TREMOR_PROCESSED_LOG_DIR"); ok {
		cfg.Testing.ProcessedLogDir = v
	}
	return nil
}

// Validate rejects settings that would break the backpressure guarantees.
func (c Config) Validate() error {
	var errs []error
	if c.Server.ListenAddr == "" {
		errs = append(errs, errors.New("server.listen_addr is required"))
	}
	if c.Ingest.MaxBodyBytes < 1024 {
		errs = append(errs, errors.New("ingest.max_body_bytes must be >= 1024"))
	}
	if c.Ingest.MaxEventsPerBatch < 1 {
		errs = append(errs, errors.New("ingest.max_events_per_batch must be >= 1"))
	}
	if c.Ingest.QueueCapacity < 1 {
		errs = append(errs, errors.New("ingest.queue_capacity must be >= 1"))
	}
	if c.Ingest.RetryAfter < time.Second {
		errs = append(errs, errors.New("ingest.retry_after must be >= 1s (Retry-After has 1 s resolution)"))
	}
	if c.Ingest.AckTimeout <= 0 {
		errs = append(errs, errors.New("ingest.ack_timeout must be > 0"))
	}
	if c.WAL.Dir == "" {
		errs = append(errs, errors.New("wal.dir is required"))
	}
	if c.WAL.SegmentBytes < 4096 {
		errs = append(errs, errors.New("wal.segment_bytes must be >= 4096"))
	}
	if c.WAL.SyncEveryRecords < 1 {
		errs = append(errs, errors.New("wal.sync_every_records must be >= 1"))
	}
	if c.WAL.SyncInterval <= 0 {
		errs = append(errs, errors.New("wal.sync_interval must be > 0"))
	}
	if c.WAL.SyncInterval >= c.Ingest.AckTimeout {
		errs = append(errs, errors.New("wal.sync_interval must be shorter than ingest.ack_timeout"))
	}
	if c.Checkpoint.Interval <= 0 {
		errs = append(errs, errors.New("checkpoint.interval must be > 0"))
	}
	if c.Shards.Count < 0 || c.Shards.QueueCapacity < 1 {
		errs = append(errs, errors.New("shards.count must be >= 0 and shards.queue_capacity >= 1"))
	}
	if c.Shards.TickInterval <= 0 || c.Shards.TickInterval > time.Second {
		errs = append(errs, errors.New("shards.tick_interval must be in (0, 1s]: detection ticks once per second"))
	}
	if k := c.Redact.HMACKey; k != nil && len(k) < 16 {
		errs = append(errs, errors.New("TREMOR_HMAC_KEY must be at least 16 bytes"))
	}
	if _, ok := map[string]bool{"INFO": true, "WARNING": true, "HIGH": true, "CRITICAL": true}[c.Notify.MinSeverity]; !ok {
		errs = append(errs, errors.New("notify.min_severity must be INFO, WARNING, HIGH or CRITICAL"))
	}
	if c.Correlator.WindowS < 1 || c.Correlator.MaxAlerts < 1 {
		errs = append(errs, errors.New("correlator.window_s and correlator.max_alerts must be >= 1"))
	}
	if c.LLM.Enabled && (c.LLM.Endpoint == "" || c.LLM.Model == "" || c.LLM.TimeoutS < 1) {
		errs = append(errs, errors.New("llm: endpoint, model and timeout_s are required when enabled"))
	}
	if err := c.Detect.Validate(); err != nil {
		errs = append(errs, err)
	}
	if c.Server.ShutdownTimeout <= 0 {
		errs = append(errs, errors.New("server.shutdown_timeout must be > 0"))
	}
	return errors.Join(errs...)
}

// MaxBufferedBytes is the worst-case raw request bytes held in memory by the
// ingest queue: every admission slot holding a maximum-size body.
func (c Config) MaxBufferedBytes() int64 {
	return int64(c.Ingest.QueueCapacity) * c.Ingest.MaxBodyBytes
}
