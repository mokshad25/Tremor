package drain

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// The fixtures were produced by bench/drain3/export_drain3.py: the real
// drain3 0.9.11 with TREMOR's configuration, run over sample/app.log after
// TREMOR's own parser (and PII redaction). Each line records the cluster id
// drain3 assigned to one message; the last line holds the final templates.
//
//	drain3_tremor.jsonl.gz  TREMOR's config (depth 4, sim 0.4, 100 children,
//	                        1000 clusters), 100,473 messages
//	drain3_stress.jsonl.gz  max_clusters 8, max_children 4, 30,000 messages:
//	                        constant LRU eviction and child-overflow paths
func TestMatchesDrain3(t *testing.T) {
	for _, name := range []string{"drain3_tremor.jsonl.gz", "drain3_stress.jsonl.gz"} {
		t.Run(name, func(t *testing.T) { compareFixture(t, "testdata/"+name) })
	}
}

func compareFixture(t *testing.T, path string) {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	var d *Drain
	masker := TremorMasker()
	n, mismatches := 0, 0
	for sc.Scan() {
		var line struct {
			Config *struct {
				SimTh       float64 `json:"sim_th"`
				Depth       int     `json:"depth"`
				MaxClusters int     `json:"max_clusters"`
				MaxChildren int     `json:"max_children"`
			} `json:"config"`
			M     *string           `json:"m"`
			ID    int               `json:"id"`
			Final map[string]string `json:"final"`
		}
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		switch {
		case line.Config != nil:
			cfg := TremorConfig()
			cfg.SimTh, cfg.Depth = line.Config.SimTh, line.Config.Depth
			cfg.MaxClusters, cfg.MaxChildren = line.Config.MaxClusters, line.Config.MaxChildren
			d = New(cfg)
		case line.M != nil:
			c, _ := d.Add(masker.Mask(*line.M))
			n++
			if c.ID != line.ID {
				mismatches++
				if mismatches <= 5 {
					t.Errorf("message %d: go cluster %d, drain3 %d\n  message: %q\n  masked:  %q",
						n, c.ID, line.ID, *line.M, masker.Mask(*line.M))
				}
			}
		case line.Final != nil:
			if d.Len() != len(line.Final) {
				t.Errorf("live clusters: go %d, drain3 %d", d.Len(), len(line.Final))
			}
			for idStr, tmpl := range line.Final {
				id, _ := strconv.Atoi(idStr)
				c := d.Get(id)
				if c == nil {
					t.Errorf("cluster %d live in drain3 but not in go", id)
					continue
				}
				if c.Template() != tmpl {
					t.Errorf("cluster %d template\n  go:     %q\n  drain3: %q", id, c.Template(), tmpl)
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if mismatches > 0 {
		t.Fatalf("%d of %d messages got a different cluster than drain3", mismatches, n)
	}
	t.Logf("%d messages: identical cluster ids; %d live / %d created clusters", n, d.Len(), d.Created())
}
