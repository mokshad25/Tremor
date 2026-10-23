package detect

import "fmt"

// score maps a tick to a severity (Python severity.py). rate/n are only
// passed for signals with a CRITICAL rule.
func score(cfg Config, z *float64, rate *float64, n int) Severity {
	if rate != nil && n >= cfg.MinEvents && *rate > cfg.RateCeiling {
		return SevCritical
	}
	if z == nil {
		return SevNone
	}
	switch {
	case *z >= cfg.ZHigh:
		return SevHigh
	case *z >= cfg.ZWarn:
		return SevWarning
	case *z >= cfg.ZInfo:
		return SevInfo
	}
	return SevNone
}

// ErrorRateReading is one tick's full numbers (Python ErrorRateReading).
type ErrorRateReading struct {
	N, Errors int
	Rate      *float64 // nil when the window is empty
	Mu        *float64 // baseline the tick was judged against
	SigmaEff  *float64
	Z         *float64
	State     string // "learning" | "insufficient" | "active"
	Severity  Severity
	Clear     int8
}

// ErrorRateDetector: per tick, r = errors / n over the arrival window.
//   - n < MinEvents: "insufficient": no z, no update, neutral for resolution.
//   - learning: record r for WarmupTicks ticks, then seed. Ticks that hit
//     the CRITICAL rule or have an incident open are not recorded.
//   - active: z against the previous tick's baseline, then the gated update.
//   - CRITICAL (r > RateCeiling with n >= MinEvents) works even while learning.
type ErrorRateDetector struct {
	cfg      Config
	Baseline Baseline
}

func NewErrorRateDetector(cfg Config) *ErrorRateDetector {
	return &ErrorRateDetector{cfg: cfg, Baseline: Baseline{
		Alpha: cfg.Alpha, WarmupTicks: cfg.WarmupTicks, SigmaMin: cfg.SigmaMin,
		MaxUpdateZ: cfg.MaxUpdateZ, NoiseFloor: BinomialFloor,
	}}
}

func f64(v float64) *float64 { return &v }

func (d *ErrorRateDetector) Measure(n, errors int, incidentOpen bool) ErrorRateReading {
	cfg := d.cfg
	r := ErrorRateReading{N: n, Errors: errors}
	if n > 0 {
		r.Rate = f64(float64(errors) / float64(n))
	}
	if mu, ok := d.Baseline.Mu(); ok {
		r.Mu = f64(mu)
	}
	if r.Rate == nil || n < cfg.MinEvents {
		r.State = "insufficient"
		return r
	}
	rate := *r.Rate
	critical := rate > cfg.RateCeiling
	if !d.Baseline.Seeded() {
		if !critical && !incidentOpen {
			d.Baseline.AddWarmup(rate)
		}
		r.State, r.Mu = "learning", nil
		r.Clear = 1
		if critical {
			r.Severity, r.Clear = SevCritical, -1
		}
		return r
	}
	sigma := d.Baseline.SigmaEff(n)
	z := d.Baseline.Z(rate, n)
	r.SigmaEff, r.Z, r.State = f64(sigma), f64(z), "active"
	r.Severity = score(cfg, r.Z, r.Rate, n)
	if !critical {
		d.Baseline.Update(rate, z, incidentOpen)
	}
	r.Clear = -1
	if z < cfg.ClearZ && !critical {
		r.Clear = 1
	}
	return r
}

func (r ErrorRateReading) reason(windowS int) string {
	if r.Rate == nil {
		return fmt.Sprintf("no lines over the last %d s", windowS)
	}
	base := "baseline still learning"
	if r.Mu != nil {
		base = "baseline " + pct(*r.Mu)
	}
	return fmt.Sprintf("error rate %s vs %s over the last %d s", pct(*r.Rate), base, windowS)
}

// pct formats like Python's f"{x:.1%}".
func pct(x float64) string { return fmt.Sprintf("%.1f%%", x*100) }

func (r ErrorRateReading) signal(service string, windowS int) Signal {
	return Signal{
		Type: SignalErrorRate, Service: service, Severity: r.Severity, Clear: r.Clear,
		Value: r.Rate, Baseline: r.Mu, Z: r.Z, Lines: r.N, Errors: r.Errors, Reason: r.reason(windowS),
	}
}

// silenceSignal (Python silence.py): after warm-up, a gap of at least
// SilenceS since the last arrival is HIGH; the first tick after lines
// return resolves the incident.
//
// One deliberate difference from Python: the gap only counts as silence if
// the service was busy just before it (busyBefore: at least MinEvents lines
// in the window ending at the last line, i.e. >= 0.67 lines/s by default,
// where a 10 s gap has under a 0.2% chance under normal traffic). Python
// pages on any 10 s gap once a service has ever warmed up, so a low-volume
// or diurnal service (quiet at night) pages all night: the attack simulator
// produced 498 such incidents in 21 days. Every Python scenario runs at
// 1.5-8 lines/s, so parity with Python is unaffected (checked by the eval).
func silenceSignal(cfg Config, service string, warmedUp bool, lastArrivalNs, nowNs int64, seen bool, busyBefore func() bool) Signal {
	if !warmedUp || !seen {
		return Signal{Type: SignalSilence, Service: service}
	}
	gap := float64(nowNs-lastArrivalNs) / 1e9
	if gap >= float64(cfg.SilenceS) && !busyBefore() {
		return Signal{Type: SignalSilence, Service: service} // quiet, but quiet is normal for it
	}
	if gap >= float64(cfg.SilenceS) {
		return Signal{Type: SignalSilence, Service: service, Severity: SevHigh, Value: f64(gap),
			Reason: fmt.Sprintf("log stream silent: no lines for %.0f s", gap)}
	}
	return Signal{Type: SignalSilence, Service: service, Resolve: true, Value: f64(gap), Reason: "log stream resumed"}
}
