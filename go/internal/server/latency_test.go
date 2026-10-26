package server

import (
	"testing"
	"time"

	"github.com/mokshad/tremor/internal/detect"
	"github.com/mokshad/tremor/internal/metrics"
)

func TestStampIngestToAlert(t *testing.T) {
	s := &Server{Hist: metrics.NewHistograms()}
	const start = int64(1_000) * int64(time.Second)
	now := start + 10*int64(time.Second)
	recv := now - 250*int64(time.Millisecond)
	cases := []struct {
		name string
		a    detect.Alert
		want time.Duration
	}{
		{"open", detect.Alert{Type: detect.SignalErrorRate, Status: detect.StatusOpen, EvidenceReceivedAt: recv}, 250 * time.Millisecond},
		{"escalated", detect.Alert{Type: detect.SignalBruteForce, Status: detect.StatusEscalated, EvidenceReceivedAt: recv}, 250 * time.Millisecond},
		{"resolved", detect.Alert{Type: detect.SignalErrorRate, Status: detect.StatusResolved, EvidenceReceivedAt: recv}, 0},
		{"silence", detect.Alert{Type: detect.SignalSilence, Status: detect.StatusOpen, EvidenceReceivedAt: recv}, 0},
		{"unknown evidence", detect.Alert{Type: detect.SignalErrorRate, Status: detect.StatusOpen}, 0},
		{"replayed line", detect.Alert{Type: detect.SignalErrorRate, Status: detect.StatusOpen, EvidenceReceivedAt: start - 1}, 0},
	}
	for _, c := range cases {
		a := c.a
		s.stampIngestToAlert(&a, now, start)
		if a.IngestToAlert != c.want {
			t.Errorf("%s: IngestToAlert %v, want %v", c.name, a.IngestToAlert, c.want)
		}
	}
}
