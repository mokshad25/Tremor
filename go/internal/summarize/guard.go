package summarize

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// LLMStats counts summary outcomes for metrics.
type LLMStats struct {
	Requests         atomic.Int64 // calls sent to the provider
	OK               atomic.Int64
	Errors           atomic.Int64 // transport / HTTP errors and timeouts
	Invalid          atomic.Int64 // output failed parsing or validation
	RateLimited      atomic.Int64 // skipped by our own limiter
	CacheHits        atomic.Int64
	Fallbacks        atomic.Int64 // template summaries served instead of the LLM
	PromptTokens     atomic.Int64
	CompletionTokens atomic.Int64
}

// Guarded wraps a provider with everything that keeps it from hurting the
// pipeline:
//
//   - a cache per incident ID (one model call per incident);
//   - a token-bucket rate limit (a burst of incidents cannot run up a bill
//     or hit the provider's limits);
//   - a timeout per call;
//   - a scrub pass over the prompt (defence in depth: redaction already ran
//     at the gateway; this re-runs it on exactly what leaves the process);
//   - strict validation, including citations;
//   - the deterministic template whenever any of that fails.
//
// Summarize therefore never returns an error for a non-empty incident.
type Guarded struct {
	LLM      Summarizer // nil when disabled
	Fallback Summarizer
	Timeout  time.Duration
	Scrub    func(string) string // re-redacts the prompt; nil = identity
	Stats    *LLMStats
	Observe  func(seconds float64) // latency hook (Prometheus histogram)

	mu      sync.Mutex
	cache   map[string]Summary
	order   []string
	maxSize int
	limiter *limiter
}

// NewGuarded builds a guarded summarizer. llm may be nil (disabled).
func NewGuarded(llm Summarizer, cfg LLMConfig, scrub func(string) string, stats *LLMStats) *Guarded {
	if stats == nil {
		stats = &LLMStats{}
	}
	return &Guarded{LLM: llm, Fallback: Template{}, Timeout: time.Duration(cfg.TimeoutS) * time.Second,
		Scrub: scrub, Stats: stats, cache: map[string]Summary{}, maxSize: max(cfg.CacheSize, 1),
		limiter: newLimiter(cfg.RatePerMinute)}
}

// Summarize returns the LLM summary for the incident if it can get a valid
// one, else the template. Results are cached by incident ID.
func (g *Guarded) Summarize(ctx context.Context, in Incident) (Summary, error) {
	g.mu.Lock()
	if s, ok := g.cache[in.ID]; ok {
		g.mu.Unlock()
		g.Stats.CacheHits.Add(1)
		return s, nil
	}
	g.mu.Unlock()

	s, reason := g.tryLLM(ctx, in)
	if reason != "" {
		fb, err := g.Fallback.Summarize(ctx, in)
		if err != nil {
			return Summary{}, err
		}
		fb.FallbackReason = reason
		g.Stats.Fallbacks.Add(1)
		s = fb
	}
	// Cache final answers only. A timeout, provider error or our own rate
	// limit is transient: the next request for this incident may succeed.
	if reason == "" || reason == "llm_disabled" || reason == "invalid_output" {
		g.put(in.ID, s)
	}
	return s, nil
}

// tryLLM returns a validated LLM summary, or why it could not.
func (g *Guarded) tryLLM(ctx context.Context, in Incident) (Summary, string) {
	if g.LLM == nil {
		return Summary{}, "llm_disabled"
	}
	if !g.limiter.allow(time.Now()) {
		g.Stats.RateLimited.Add(1)
		return Summary{}, "rate_limited"
	}
	if g.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.Timeout)
		defer cancel()
	}
	g.Stats.Requests.Add(1)
	start := time.Now()
	var s Summary
	var err error
	if oc, ok := g.LLM.(*OpenAICompatible); ok && g.Scrub != nil {
		prompt, perr := Prompt(in)
		if perr != nil {
			return Summary{}, "prompt_error"
		}
		s, err = oc.complete(ctx, g.Scrub(prompt))
	} else {
		s, err = g.LLM.Summarize(ctx, in)
	}
	if g.Observe != nil {
		g.Observe(time.Since(start).Seconds())
	}
	g.Stats.PromptTokens.Add(int64(s.PromptTokens))
	g.Stats.CompletionTokens.Add(int64(s.CompletionTokens))
	switch {
	case errors.Is(err, ErrInvalidSummary):
		g.Stats.Invalid.Add(1)
		return Summary{}, "invalid_output"
	case errors.Is(err, context.DeadlineExceeded):
		g.Stats.Errors.Add(1)
		return Summary{}, "timeout"
	case err != nil:
		g.Stats.Errors.Add(1)
		return Summary{}, "llm_error"
	}
	if err := Validate(s, in); err != nil {
		g.Stats.Invalid.Add(1)
		return Summary{}, "invalid_output"
	}
	g.Stats.OK.Add(1)
	return s, ""
}

func (g *Guarded) put(id string, s Summary) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.cache[id]; !ok {
		g.order = append(g.order, id)
	}
	g.cache[id] = s
	for len(g.order) > g.maxSize {
		delete(g.cache, g.order[0])
		g.order = g.order[1:]
	}
}

// limiter is a token bucket: ratePerMinute tokens per minute, burst of the
// same size. 0 means unlimited.
type limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

func newLimiter(perMinute int) *limiter {
	if perMinute <= 0 {
		return nil
	}
	b := float64(perMinute)
	return &limiter{rate: b / 60, burst: b, tokens: b}
}

func (l *limiter) allow(now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() {
		l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
