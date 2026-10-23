// Package detect is TREMOR's deterministic anomaly detection, ported from
// the Python version (app/core/baseline.py, detectors/, severity.py,
// alerts.py, engine.py) with the same arithmetic, thresholds and alert
// lifecycle. Nothing here reads a clock: time is always passed in, so the
// live server, crash replay and the evaluation harness run identical code.
package detect

import "math"

// Baseline is a warm-up-seeded EWMA mean and variance of one signal.
//
//   - Warm-up: collect WarmupTicks values, then seed mu = mean and
//     var = population variance.
//   - Deviation: sigma_eff = max(sigma, noiseFloor(mu, n), SigmaMin);
//     z = (x - mu) / sigma_eff.
//   - Gated update, only when no incident is open and z < MaxUpdateZ:
//     var = (1-a)(var + a(x-mu)^2); mu = a*x + (1-a)*mu.
//
// The gate means an ongoing incident is never absorbed into "normal".
type Baseline struct {
	Alpha       float64
	WarmupTicks int
	SigmaMin    float64
	MaxUpdateZ  float64
	NoiseFloor  func(mu float64, n int) float64

	warmup []float64
	seeded bool
	mu     float64
	vr     float64
}

// BinomialFloor is the sampling noise of a proportion estimated from n
// lines: sqrt(mu(1-mu)/n). It stops a quiet service with a near-zero
// learned spread from paging on one unlucky error.
func BinomialFloor(mu float64, n int) float64 {
	if n <= 0 {
		return 0
	}
	return math.Sqrt(max(mu*(1-mu), 0) / float64(n))
}

func (b *Baseline) Seeded() bool { return b.seeded }

// Mu is the current mean; ok is false while learning.
func (b *Baseline) Mu() (mu float64, ok bool) { return b.mu, b.seeded }

func (b *Baseline) Sigma() float64 { return math.Sqrt(b.vr) }

func (b *Baseline) WarmupCount() int { return len(b.warmup) }

// AddWarmup records one warm-up value and seeds on the last one.
func (b *Baseline) AddWarmup(v float64) {
	if b.seeded {
		return
	}
	b.warmup = append(b.warmup, v)
	if len(b.warmup) < b.WarmupTicks {
		return
	}
	// Python's sum() (3.12+) uses compensated summation; PySum reproduces it
	// so the seeded baseline is the same as the Python version's.
	k := float64(len(b.warmup))
	mu := PySum(b.warmup, func(x float64) float64 { return x }) / k
	ss := PySum(b.warmup, func(x float64) float64 { return (x - mu) * (x - mu) })
	b.vr = ss / k
	b.mu = mu
	b.seeded = true
	b.warmup = nil
}

// SigmaEff is the spread used for z: never below the noise floor or SigmaMin.
func (b *Baseline) SigmaEff(n int) float64 {
	return max(math.Sqrt(b.vr), b.NoiseFloor(b.mu, n), b.SigmaMin)
}

func (b *Baseline) Z(v float64, n int) float64 { return (v - b.mu) / b.SigmaEff(n) }

// Update applies the gated EWMA update and reports whether it moved.
func (b *Baseline) Update(v, z float64, incidentOpen bool) bool {
	if incidentOpen || z >= b.MaxUpdateZ {
		return false
	}
	a, prev := b.Alpha, b.mu
	d := v - prev
	b.vr = (1 - a) * (b.vr + a*(d*d)) // Python: a * (x - mu)**2, square first
	b.mu = a*v + (1-a)*prev
	return true
}

// PySum is CPython's float sum() since 3.12 (Python/bltinmodule.c): Neumaier
// compensated summation, with the compensation added once at the end.
func PySum(xs []float64, f func(float64) float64) float64 {
	sum, c := 0.0, 0.0
	for _, x := range xs {
		v := f(x)
		t := sum + v
		if math.Abs(sum) >= math.Abs(v) {
			c += (sum - t) + v
		} else {
			c += (v - t) + sum
		}
		sum = t
	}
	if c != 0 && !math.IsInf(c, 0) && !math.IsNaN(c) {
		sum += c
	}
	return sum
}
