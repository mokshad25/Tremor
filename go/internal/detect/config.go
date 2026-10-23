package detect

import "errors"

// Config holds the detection thresholds. Defaults are TREMOR's Python
// settings (app/config.py); the reasoning for each is there and in
// docs/phase3-detection.md.
type Config struct {
	WindowS       int     `yaml:"window_s"`          // arrival-time window for the error rate
	WarmupTicks   int     `yaml:"warmup_ticks"`      // ticks with n >= MinEvents used to seed a baseline
	Alpha         float64 `yaml:"alpha"`             // EWMA smoothing
	SigmaMin      float64 `yaml:"sigma_min"`         // absolute floor on sigma_eff
	MaxUpdateZ    float64 `yaml:"max_update_z"`      // baseline learns only from ticks below this z
	MinEvents     int     `yaml:"min_events"`        // fewer lines in the window: no verdict
	ZInfo         float64 `yaml:"z_info"`            // severity thresholds on z
	ZWarn         float64 `yaml:"z_warn"`            //
	ZHigh         float64 `yaml:"z_high"`            //
	RateCeiling   float64 `yaml:"rate_ceiling"`      // error rate above this is CRITICAL regardless of z
	ClearZ        float64 `yaml:"clear_z"`           // a tick below this z counts toward resolution
	ClearTicks    int     `yaml:"clear_ticks"`       // consecutive clear ticks to resolve
	SilenceS      int     `yaml:"silence_s"`         // no lines for this long after warm-up: SILENCE
	CooldownS     int     `yaml:"cooldown_s"`        // re-open within this reuses the incident id
	MaxCatchUpS   int     `yaml:"max_catch_up_s"`    // larger clock jumps skip ticks instead of replaying them
	SampleErrSeqs int     `yaml:"sample_error_seqs"` // error seqs kept per service for alert context

	Security SecurityConfig `yaml:"security"`
}

func DefaultConfig() Config {
	return Config{
		WindowS: 30, WarmupTicks: 30, Alpha: 0.01, SigmaMin: 0.01, MaxUpdateZ: 2.0, MinEvents: 20,
		ZInfo: 3, ZWarn: 5, ZHigh: 8, RateCeiling: 0.5, ClearZ: 2.0, ClearTicks: 10,
		SilenceS: 10, CooldownS: 60, MaxCatchUpS: 3600, SampleErrSeqs: 16,
		Security: DefaultSecurityConfig(),
	}
}

// Validate rejects settings that would make detection meaningless.
func (c Config) Validate() error {
	var errs []error
	if c.WindowS < 1 || c.WarmupTicks < 1 || c.MinEvents < 1 || c.ClearTicks < 1 {
		errs = append(errs, errors.New("detect: window_s, warmup_ticks, min_events and clear_ticks must be >= 1"))
	}
	if c.Alpha <= 0 || c.Alpha >= 1 {
		errs = append(errs, errors.New("detect: alpha must be in (0, 1)"))
	}
	if !(c.ZInfo <= c.ZWarn && c.ZWarn <= c.ZHigh) {
		errs = append(errs, errors.New("detect: need z_info <= z_warn <= z_high"))
	}
	if c.RateCeiling <= 0 || c.RateCeiling > 1 {
		errs = append(errs, errors.New("detect: rate_ceiling must be in (0, 1]"))
	}
	if c.SilenceS < 1 || c.MaxCatchUpS < 1 {
		errs = append(errs, errors.New("detect: silence_s and max_catch_up_s must be >= 1"))
	}
	return errors.Join(errs...)
}
