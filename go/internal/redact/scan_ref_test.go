package redact

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// refFind is Find before Phase 7: scanKeyValueSecrets and scanUsernames ran
// one strings.Index loop per keyword. It stays as the reference for the
// single-pass keywordHits.
func refFind(s string) []Finding {
	var fs []Finding
	ls := lowerASCII(s)
	fs = scanWords(s, fs)
	fs = scanBearer(s, ls, fs)
	fs = refScanKeyValueSecrets(s, ls, fs)
	fs = refScanUsernames(s, ls, fs)
	fs = scanEmails(s, fs)
	fs = scanDigits(s, fs)
	fs = scanIPs(s, fs)
	return resolve(fs)
}

func refScanKeyValueSecrets(s, ls string, fs []Finding) []Finding {
	if !strings.ContainsAny(s, "=:") {
		return fs
	}
	for _, key := range secretKeys {
		for i := 0; ; {
			k := indexFrom(ls, key, i)
			if k < 0 {
				break
			}
			i = k + len(key)
			if k > 0 && (isAlnum(s[k-1]) || s[k-1] == '_') {
				continue
			}
			v, ok := valueAfterKey(s, k+len(key))
			if !ok {
				continue
			}
			e := valueEnd(s, v)
			val := s[v:e]
			if strings.EqualFold(val, "bearer") || strings.EqualFold(val, "basic") {
				continue
			}
			if len(val) >= 4 && !isPlaceholder(val) {
				fs = append(fs, Finding{KindSecret, v, e})
			}
		}
	}
	return fs
}

func refScanUsernames(s, ls string, fs []Finding) []Finding {
	hasKV := strings.ContainsAny(s, "=:")
	for _, key := range userKeys {
		if !hasKV {
			break
		}
		for i := 0; ; {
			k := indexFrom(ls, key, i)
			if k < 0 {
				break
			}
			i = k + len(key)
			if k > 0 && (isAlnum(s[k-1]) || s[k-1] == '_' || s[k-1] == '.') {
				continue
			}
			v, ok := valueAfterKey(s, k+len(key))
			if !ok {
				continue
			}
			if e := userValueEnd(s, v); e > v && !isPlaceholder(s[v:e]) {
				fs = append(fs, Finding{KindUser, v, e})
			}
		}
	}
	for _, ph := range userPhrases {
		for i := 0; ; {
			k := indexFrom(ls, ph, i)
			if k < 0 {
				break
			}
			i = k + len(ph)
			if k > 0 && isAlnum(s[k-1]) {
				continue
			}
			v := k + len(ph)
			for v < len(s) && s[v] == ' ' {
				v++
			}
			if ph == "password for " && strings.HasPrefix(ls[v:], "invalid user ") {
				continue
			}
			if v < len(s) && (s[v] == '\'' || s[v] == '"') {
				v++
			}
			e := userValueEnd(s, v)
			if e > v && !isPlaceholder(s[v:e]) && !strings.EqualFold(s[v:e], "invalid") {
				fs = append(fs, Finding{KindUser, v, e})
			}
		}
	}
	return fs
}

// corpusTexts returns the text of every line of the labelled PII set.
func corpusTexts(tb testing.TB) []string {
	tb.Helper()
	f, err := os.Open("testdata/pii_labelled.jsonl")
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l struct{ Text string }
		if err := json.Unmarshal([]byte(strings.ReplaceAll(sc.Text(), "{{fake}}", "")), &l); err != nil {
			tb.Fatal(err)
		}
		out = append(out, l.Text)
	}
	return out
}

var refSeeds = []string{
	"Failed password for invalid user admin from 10.0.0.1 port 22 ssh2",
	"/home/home/bob/.ssh /home//x password=password=x token: token=abc12345",
	"user=user=bob username: alice USER.NAME=carol enduser.id=7 login=root ruser= logname=x",
	"sudo:   bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls (to root) x (to y",
	`{"password":"hunter22","Access_Token":"abc.def","x-api-key": "k1234567"} Authorization: Bearer abcdefgh`,
	"session opened for user alice by user bob; granted to carol by admin dave; su: from eve",
	"xpassword=1 my_password_hint=2 tokens=3 tokentoken=4 user_user=5 .user=6",
	"sha256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 md5:x ip 10.1.2.3 +91 98765 43210",
	"p", "pa", "", "user", "for user ", "(to ",
}

// TestFindMatchesReference requires the single-pass keyword search to give
// exactly the old per-keyword search's findings on the labelled PII set,
// the benchmark lines and the edge cases above.
func TestFindMatchesReference(t *testing.T) {
	inputs := append(append(corpusTexts(t), benchLines...), refSeeds...)
	diff := 0
	for _, s := range inputs {
		if got, want := Find(s), refFind(s); !reflect.DeepEqual(got, want) {
			diff++
			if diff <= 10 {
				t.Errorf("Find(%q)\n  new %v\n  ref %v", s, got, want)
			}
		}
	}
	if diff > 0 {
		t.Fatalf("%d of %d inputs differ from the reference", diff, len(inputs))
	}
	t.Logf("%d inputs: findings identical to the reference", len(inputs))
}

func FuzzFindMatchesReference(f *testing.F) {
	for _, s := range refSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := Find(s), refFind(s); !reflect.DeepEqual(got, want) {
			t.Fatalf("Find(%q)\n  new %v\n  ref %v", s, got, want)
		}
	})
}

// BenchmarkRedactCorpus redacts the 5,000 lines of the labelled PII set.
func BenchmarkRedactCorpus(b *testing.B) {
	texts, r := corpusTexts(b), New(testKey)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		r.String(texts[i%len(texts)])
	}
}

// BenchmarkRedactCorpusRef is BenchmarkRedactCorpus with the reference Find.
func BenchmarkRedactCorpusRef(b *testing.B) {
	texts := corpusTexts(b)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		refFind(texts[i%len(texts)])
	}
}

// BenchmarkFindCorpus is Find alone, for comparison with the reference.
func BenchmarkFindCorpus(b *testing.B) {
	texts := corpusTexts(b)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		Find(texts[i%len(texts)])
	}
}

// BenchmarkFindShortAttr is the per-attribute cost: loadgen sends one short
// host attribute with every event.
func BenchmarkFindShortAttr(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Find("payment-gateway-2")
	}
}

func BenchmarkFindShortAttrRef(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		refFind("payment-gateway-2")
	}
}
