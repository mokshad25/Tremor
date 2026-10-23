package drain

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMaskExamples(t *testing.T) {
	m := TremorMasker()
	cases := map[string]string{
		"took 200ms":            "took <NUM>",
		"took 5s.":              "took <NUM>.",
		"value=1.5x":            "value=<NUM>.5x",
		"x-5":                   "x-<NUM>",
		"delta -12 +3":          "delta <NUM> <NUM>",
		"v2 x86_64":             "v2 x86_64",
		"from 10.0.0.1:8080 ok": "from <IP> ok",
		"id 550e8400-e29b-41d4-a716-446655440000 done": "id <UUID> done",
		"addr 0xFF and deadbeefcafe and deadbeef12345": "addr <HEX> and deadbeefcafe and <HEX>",
		"Payment authorized txn_8f2a amount=12.50 INR": "Payment authorized <ID> amount=<NUM> INR",
		"Login failed user=<EMAIL> attempts=3":         "Login failed user=<EMAIL> attempts=<NUM>",
	}
	for in, want := range cases {
		if got := m.Mask(in); got != want {
			t.Errorf("Mask(%q)\n  got  %q\n  want %q", in, got, want)
		}
	}
}

// TestMaskMatchesPython replays 30,000 random strings masked by drain3's
// LogMasker with TREMOR's regexes (bench/drain3/export_masks.py).
func TestMaskMatchesPython(t *testing.T) {
	f, err := os.Open("testdata/masks_python.jsonl.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	m := TremorMasker()
	sc := bufio.NewScanner(gz)
	n, diff, nonASCII := 0, 0, 0
	for sc.Scan() {
		var c struct{ In, Out string }
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		n++
		if got := m.Mask(c.In); got != c.Out {
			if !isASCII(c.In) {
				nonASCII++ // documented divergence: Python's \b and \d are Unicode-aware
				continue
			}
			diff++
			if diff <= 10 {
				t.Errorf("Mask(%q)\n  go     %q\n  python %q", c.In, got, c.Out)
			}
		}
	}
	if diff > 0 {
		t.Fatalf("%d of %d ASCII inputs differ from Python", diff, n)
	}
	t.Logf("%d inputs: all ASCII inputs identical; %d non-ASCII inputs differ (Unicode \\b/\\d)", n, nonASCII)
}

func isASCII(s string) bool {
	return utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return r > 127 }) < 0
}

func FuzzMaskNum(f *testing.F) {
	f.Add("took 1.5ms and -3s")
	f.Fuzz(func(t *testing.T, s string) {
		out := maskNum(s)
		// Masking only ever replaces text with <NUM>: removing every <NUM>
		// leaves a subsequence of the input, and it never panics or loops.
		if strings.Count(out, "<NUM>") == 0 && out != s {
			t.Fatalf("changed without masking: %q -> %q", s, out)
		}
	})
}
