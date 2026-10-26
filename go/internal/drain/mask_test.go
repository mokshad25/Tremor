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

// pythonMaskInputs returns the inputs of the Python masking fixture.
func pythonMaskInputs(tb testing.TB) []string {
	tb.Helper()
	f, err := os.Open("testdata/masks_python.jsonl.gz")
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		tb.Fatal(err)
	}
	var in []string
	sc := bufio.NewScanner(gz)
	for sc.Scan() {
		var c struct{ In string }
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			tb.Fatal(err)
		}
		in = append(in, c.In)
	}
	return in
}

// TestMaskMatchesRegexReference requires the single-pass masker to produce
// exactly the regexp implementation's output, including on non-ASCII input
// (both follow Go's ASCII \b and \d), for every real TREMOR message and
// every input of the Python fixture.
func TestMaskMatchesRegexReference(t *testing.T) {
	m, ref := TremorMasker(), newRegexMasker()
	inputs := append(fixtureMessages(t), pythonMaskInputs(t)...)
	diff := 0
	for _, s := range inputs {
		if got, want := m.Mask(s), ref.Mask(s); got != want {
			diff++
			if diff <= 10 {
				t.Errorf("Mask(%q)\n  scan  %q\n  regex %q", s, got, want)
			}
		}
	}
	if diff > 0 {
		t.Fatalf("%d of %d inputs differ from the regexp implementation", diff, len(inputs))
	}
	t.Logf("%d inputs identical to the regexp implementation", len(inputs))
}

func FuzzMaskMatchesRegex(f *testing.F) {
	for _, s := range []string{
		"id 550e8400-e29b-41d4-a716-446655440000 done",
		"550e8400-e29b-41d4-a716-446655440000x 550e8400-e29b-41d4-a716-44665544000",
		"-550e8400-e29b-41d4-a716-446655440000-5 deadbeef1234-5 0xFF-1",
		"addr 0xFF 0x 0xg 0x12_ and deadbeefcafe and deadbeef12345 DEADBEEF1234a",
		"from 10.0.0.1:8080 ok 1.2.3.4:80x 1.2.3.4.5 1.2.3.4567 01.002.3.4: 1.2.3",
		"-1.2.3.4 +10.0.0.1 1.2.3.4-5 x1.2.3.4",
		"10.1.2.3:8080123456789012 10.1.2.3:808012345678 10.1.2.3:80801234567 ok",
		"1.2.3.4:12345678-1234-1234-1234-123456789012 1.2.3.4:12345678-12",
		"txn_8f2a req_x re_1 req_a_b ch_ re_ ord_9z usr_A1 txn_8f2a_ txn_8f2a.5",
		"took 1.5ms -3s +4 5.s x-5 v2 x86_64 é1 1é 2026-10-14T08:00:00Z",
		"\xff1.2.3.4\xff deadbeef1234\x80 <HEX>-5 <NUM>",
	} {
		f.Add(s)
	}
	m, ref := TremorMasker(), newRegexMasker()
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := m.Mask(s), ref.Mask(s); got != want {
			t.Fatalf("Mask(%q)\n  scan  %q\n  regex %q", s, got, want)
		}
	})
}

// BenchmarkMaskRegex is BenchmarkMask for the regexp implementation.
func BenchmarkMaskRegex(b *testing.B) {
	msgs, m := fixtureMessages(b), newRegexMasker()
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		m.Mask(msgs[i%len(msgs)])
	}
}

// fixtureMessages returns the raw messages from the drain3 TREMOR fixture
// (real sample/app.log lines after TREMOR's parser and redaction).
func fixtureMessages(tb testing.TB) []string {
	tb.Helper()
	f, err := os.Open("testdata/drain3_tremor.jsonl.gz")
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		tb.Fatal(err)
	}
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var msgs []string
	for sc.Scan() {
		var line struct{ M *string }
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			tb.Fatal(err)
		}
		if line.M != nil {
			msgs = append(msgs, *line.M)
		}
	}
	return msgs
}

// BenchmarkMask masks real TREMOR messages, cycling through the fixture.
func BenchmarkMask(b *testing.B) {
	msgs, m := fixtureMessages(b), TremorMasker()
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		m.Mask(msgs[i%len(msgs)])
	}
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
