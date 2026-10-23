package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mokshad/tremor/internal/sim"
)

// AttackLabel is a ground-truth record written to the summary.
type AttackLabel struct {
	Type    string    `json:"type"`
	Variant string    `json:"variant"`
	Service string    `json:"service"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	User    string    `json:"user,omitempty"`
	Source  string    `json:"source,omitempty"`
}

// sendLines posts lines one per request, at their timestamps relative to
// `at` (prelude lines, which carry past timestamps, go immediately). 429/503
// are retried, as a real producer would.
func sendLines(client *http.Client, url string, lines []sim.Line, paced bool) error {
	for _, l := range lines {
		if paced {
			if d := time.Until(l.TS); d > 0 {
				time.Sleep(d)
			}
		}
		body, _ := json.Marshal(map[string]any{"events": []wireEvent{{
			Service: l.Service, Timestamp: l.TS.UTC().Format("2006-01-02T15:04:05.000Z07:00"), Level: l.Level, Message: l.Message,
		}}})
		for attempt := 0; ; attempt++ {
			resp, err := client.Post(url, "application/json", bytes.NewReader(body))
			if err != nil {
				return err
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
			if (resp.StatusCode == 429 || resp.StatusCode == 503) && attempt < 10 {
				time.Sleep(time.Second)
				continue
			}
			return fmt.Errorf("attack line rejected: %d", resp.StatusCode)
		}
	}
	return nil
}

// runAttacks injects the requested attacks (comma-separated, or "all")
// `after` into the run and returns their labels.
func runAttacks(o options, start time.Time) ([]AttackLabel, error) {
	kinds := strings.Split(o.attack, ",")
	if o.attack == "all" {
		kinds = []string{"brute_force", "credential_stuffing", "privilege_change", "unusual_access"}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	var labels []AttackLabel
	for i, k := range kinds {
		at := start.Add(o.attackAt + time.Duration(i)*o.attackGap)
		pre, atk, lbl, err := sim.LiveAttack(strings.TrimSpace(k), start, at, o.gen.Seed+uint64(i))
		if err != nil {
			return labels, err
		}
		if err := sendLines(client, o.url, pre, false); err != nil {
			return labels, err
		}
		if err := sendLines(client, o.url, atk, true); err != nil {
			return labels, err
		}
		labels = append(labels, AttackLabel{lbl.Type, lbl.Variant, lbl.Service, lbl.Start, lbl.End, lbl.User, lbl.Source})
		fmt.Fprintf(os.Stderr, "attack %s/%s injected at %s (user=%q source=%q)\n", lbl.Type, lbl.Variant, lbl.Start.Format(time.TimeOnly), lbl.User, lbl.Source)
	}
	return labels, nil
}

// replaySSH sends a Loghub OpenSSH log, paced by its own timestamps divided
// by speed (speed <= 0: as fast as possible), in batches.
func replaySSH(o options) error {
	f, err := os.Open(o.replaySSH)
	if err != nil {
		return err
	}
	defer f.Close()
	lines, skipped, err := sim.ReadSyslog(f, o.year)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return fmt.Errorf("no lines parsed")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	start, first := time.Now(), lines[0].TS
	sent := 0
	for i := 0; i < len(lines); i += o.batch {
		chunk := lines[i:min(i+o.batch, len(lines))]
		if o.speed > 0 {
			due := start.Add(time.Duration(float64(chunk[0].TS.Sub(first)) / o.speed))
			if d := time.Until(due); d > 0 {
				time.Sleep(d)
			}
		}
		evs := make([]wireEvent, len(chunk))
		for j, l := range chunk {
			evs[j] = wireEvent{Service: l.Service, Timestamp: l.TS.UTC().Format("2006-01-02T15:04:05.000Z07:00"), Level: l.Level, Message: l.Message}
		}
		body, _ := json.Marshal(map[string]any{"events": evs})
		for attempt := 0; ; attempt++ {
			resp, err := client.Post(o.url, "application/json", bytes.NewReader(body))
			if err != nil {
				return err
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
			if attempt >= 10 {
				return fmt.Errorf("batch rejected: %d", resp.StatusCode)
			}
			time.Sleep(time.Second)
		}
		sent += len(chunk)
	}
	fmt.Fprintf(os.Stderr, "replayed %d lines (%d unparseable) in %s\n", sent, skipped, time.Since(start).Round(time.Millisecond))
	return nil
}
