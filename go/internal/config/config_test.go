package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAreValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Ingest.QueueCapacity != 256 || cfg.MaxBufferedBytes() != 256<<20 {
		t.Fatalf("unexpected defaults %+v", cfg.Ingest)
	}
}

func TestLoadOverridesDefaults(t *testing.T) {
	p := writeFile(t, `
server:
  listen_addr: ":9999"
ingest:
  queue_capacity: 32
  retry_after: 2s
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ListenAddr != ":9999" || cfg.Ingest.QueueCapacity != 32 || cfg.Ingest.RetryAfter != 2*time.Second {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if cfg.Ingest.MaxBodyBytes != 1<<20 {
		t.Fatal("unset field lost its default")
	}
}

func TestEmptyFileMeansDefaults(t *testing.T) {
	cfg, err := Load(writeFile(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ListenAddr != ":8080" {
		t.Fatal("defaults not kept")
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	_, err := Load(writeFile(t, "ingest:\n  queue_capacty: 10\n"))
	if err == nil || !strings.Contains(err.Error(), "queue_capacty") {
		t.Fatalf("typo not rejected: %v", err)
	}
}

func TestEnvOverrides(t *testing.T) {
	cfg := Default()
	env := map[string]string{"TREMOR_LISTEN_ADDR": ":1", "TREMOR_QUEUE_CAPACITY": "8", "TREMOR_SHARDS": "3",
		"TREMOR_WAL_SYNC_INTERVAL": "2ms", "TREMOR_WAL_FSYNC": "false", "TREMOR_WAL_DIR": "/x"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if err := applyEnv(&cfg, lookup); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ListenAddr != ":1" || cfg.Ingest.QueueCapacity != 8 || cfg.Shards.Count != 3 ||
		cfg.WAL.SyncInterval != 2*time.Millisecond || cfg.WAL.Fsync || cfg.WAL.Dir != "/x" {
		t.Fatalf("env not applied: %+v", cfg)
	}
	env["TREMOR_QUEUE_CAPACITY"] = "lots"
	if err := applyEnv(&cfg, lookup); err == nil {
		t.Fatal("bad int accepted")
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	cfg := Default()
	cfg.Ingest.QueueCapacity = 0
	cfg.Ingest.RetryAfter = 100 * time.Millisecond
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "queue_capacity") || !strings.Contains(err.Error(), "retry_after") {
		t.Fatalf("expected both errors, got %v", err)
	}
}

func TestValidateWAL(t *testing.T) {
	cfg := Default()
	cfg.WAL.SyncInterval = cfg.Ingest.AckTimeout
	cfg.WAL.SegmentBytes = 10
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "sync_interval") || !strings.Contains(err.Error(), "segment_bytes") {
		t.Fatalf("got %v", err)
	}
}

func TestRedactAndOTLPEnv(t *testing.T) {
	cfg := Default()
	if !cfg.Redact.Enabled || cfg.OTLP.HTTPAddr != ":4318" || cfg.OTLP.GRPCAddr != ":4317" {
		t.Fatalf("defaults %+v %+v", cfg.Redact, cfg.OTLP)
	}
	env := map[string]string{"TREMOR_HMAC_KEY": "short", "TREMOR_REDACT": "false", "TREMOR_OTLP_GRPC_ADDR": ""}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if err := applyEnv(&cfg, lookup); err != nil {
		t.Fatal(err)
	}
	if cfg.Redact.Enabled || cfg.OTLP.GRPCAddr != "" || string(cfg.Redact.HMACKey) != "short" {
		t.Fatalf("env not applied: %+v", cfg)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "TREMOR_HMAC_KEY") {
		t.Fatalf("short key accepted: %v", err)
	}
	// The key can never come from YAML.
	if _, err := Load(writeFile(t, "redact:\n  hmac_key: abc\n")); err == nil {
		t.Fatal("hmac_key accepted from YAML")
	}
}
