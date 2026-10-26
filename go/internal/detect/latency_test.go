package detect

import (
	"fmt"
	"testing"
	"time"

	"github.com/mokshad/tremor/internal/drain"
	"github.com/mokshad/tremor/internal/event"
)

// TestEvidenceReceivedAt: every OPEN/ESCALATED alert, whether emitted at a
// tick (error rate) or right after a line (security rules), carries the
// gateway receive time of its newest line, SourceSeqs.Last.
func TestEvidenceReceivedAt(t *testing.T) {
	cfg := cfgFast()
	cfg.Security = DefaultSecurityConfig()
	cfg.Security.Enabled = true
	var alerts []Alert
	p := NewProcessor(cfg, drain.TremorConfig(), func(a Alert) { alerts = append(alerts, a) })
	recv := map[uint64]int64{}
	seq := uint64(0)
	process := func(e *event.Event) {
		seq++
		e.Seq = seq
		recv[seq] = e.ReceivedAt
		p.Process(e)
	}
	const s0 = int64(1_000_000)
	sec := int64(time.Second)
	p.SetOrigin(s0)
	for k := s0; k < s0+20; k++ {
		for i := range 20 {
			level := event.LevelInfo
			if k >= s0+12 && i%5 != 0 {
				level = event.LevelError // 80% errors from second 12
			}
			process(ev("api", k*sec+int64(i)*sec/20+7, level, 0))
		}
	}
	u, ip := tok("usr_", 1), tok("ip_", 2)
	for i := range 12 {
		e := secEv("Login failed user="+u+" ip="+ip, 0, 0)
		e.ReceivedAt = (s0+20)*sec + int64(i)*sec/10
		process(e)
	}
	p.Advance((s0 + 25) * sec)

	byType := map[SignalType]int{}
	for _, a := range alerts {
		if a.Status != StatusOpen && a.Status != StatusEscalated {
			continue
		}
		want, ok := recv[a.SourceSeqs.Last]
		if !ok || a.EvidenceReceivedAt != want {
			t.Errorf("%s %s seqs %+v: evidence received at %d, want %d", a.Type, a.Status, a.SourceSeqs, a.EvidenceReceivedAt, want)
		}
		byType[a.Type]++
	}
	if byType[SignalErrorRate] == 0 || byType[SignalBruteForce] == 0 {
		t.Fatalf("expected error-rate and brute-force alerts, got %v", fmt.Sprint(byType))
	}
}
