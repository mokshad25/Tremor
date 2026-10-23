package redact

import (
	"strings"
	"sync"
	"testing"

	"github.com/mokshad/tremor/internal/event"
)

var testKey = []byte("unit-test-key-0123456789abcdef!!")

func TestRedactCases(t *testing.T) {
	r := New(testKey)
	tok := func(domain, v string) string { return r.Token(domain, v) }
	cases := []struct{ in, want string }{
		{"Login failed user=alice ip=10.0.0.12 attempts=3", "Login failed user=usr_" + tok("user", "alice") + " ip=ip_" + tok("ip", "10.0.0.12") + " attempts=3"},
		{"Failed password for invalid user admin from 203.0.113.9 port 22 ssh2", "Failed password for invalid user admin from ip_" + tok("ip", "203.0.113.9") + " port 22 ssh2"},
		{"user=Alice@Example.com", "user=usr_" + tok("user", "alice@example.com")}, // email logins: case-insensitive identity
		{"contact rahul.k+test@mail.co.in now", "contact <EMAIL> now"},
		{"card 4111 1111 1111 1111 ok", "card <CARD> ok"},
		{"card 4111-1111-1111-1111", "card <CARD>"},
		{"amex 3782 822463 10005", "amex <CARD>"},
		{"not a card 4111 1111 1111 1112", "not a card 4111 1111 1111 1112"}, // fails Luhn
		{"call +91 98765 43210 or 09876543210", "call <PHONE> or <PHONE>"},
		{"mobile 98765-43210", "mobile <PHONE>"},
		{"order 9876543210 shipped", "order 9876543210 shipped"}, // id context
		{"pan ABCPE1234F", "pan <PAN>"},
		{"code ABCDE1234F", "code ABCDE1234F"}, // 4th letter D is not a PAN holder type
		{"Authorization: Bearer abc.def-ghi_jkl123", "Authorization: Bearer <TOKEN>"},
		{"key=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc", "key=<API_KEY>"},
		{`{"password":"hunter22"}`, `{"password":"<SECRET>"}`},
		{"commit da39a3ee5e6b4b0d3255bfef95601890afd80709 v1.2.3.4 2026-10-14", "commit da39a3ee5e6b4b0d3255bfef95601890afd80709 v1.2.3.4 2026-10-14"},
		{"ssh2: RSA SHA256:aMmhyDngcWo0OR1q2qzvmMHU32ZOcVGcoGX4gFkdXIZ", "ssh2: RSA SHA256:aMmhyDngcWo0OR1q2qzvmMHU32ZOcVGcoGX4gFkdXIZ"},
		{"from [2001:db8::1]:443", "from [ip_" + tok("ip", "2001:db8::1") + "]:443"},
		{"listening on 10.0.0.1:8080", "listening on ip_" + tok("ip", "10.0.0.1") + ":8080"},
		{"at 14:00:00 mac aa:bb:cc:dd:ee:ff", "at 14:00:00 mac aa:bb:cc:dd:ee:ff"},
		{"sudo:   bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash", "sudo:   usr_" + tok("user", "bob") + " : TTY=pts/0 ; PWD=/home/usr_" + tok("user", "bob") + " ; USER=root ; COMMAND=/bin/bash"},
		{"su: (to root) carol on pts/1", "su: (to root) usr_" + tok("user", "carol") + " on pts/1"},
		{"Role admin granted to dave by admin erin", "Role admin granted to usr_" + tok("user", "dave") + " by admin usr_" + tok("user", "erin")},
		{"Failed password for root from 203.0.113.9 port 22 ssh2", "Failed password for root from ip_" + tok("ip", "203.0.113.9") + " port 22 ssh2"}, // role account kept
		{"", ""},
	}
	for _, c := range cases {
		if got := r.String(c.in); got != c.want {
			t.Errorf("Redact(%q)\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}

func TestVerhoeffCatchesEverySingleDigitError(t *testing.T) {
	base := []byte("23456789012")
	full := append(base, verhoeffCheckDigit(base))
	if !verhoeff(full) || !aadhaar(full) {
		t.Fatalf("%s should be valid", full)
	}
	for i := range full {
		for d := byte('0'); d <= '9'; d++ {
			if d == full[i] {
				continue
			}
			bad := append([]byte(nil), full...)
			bad[i] = d
			if verhoeff(bad) {
				t.Fatalf("single-digit error at %d not caught: %s", i, bad)
			}
		}
	}
	for i := 0; i+1 < len(full); i++ { // adjacent transpositions
		if full[i] == full[i+1] {
			continue
		}
		bad := append([]byte(nil), full...)
		bad[i], bad[i+1] = bad[i+1], bad[i]
		if verhoeff(bad) {
			t.Fatalf("transposition at %d not caught", i)
		}
	}
	if aadhaar([]byte("123456789012")) {
		t.Fatal("Aadhaar cannot start with 1")
	}
}

func TestLuhn(t *testing.T) {
	for _, ok := range []string{"4111111111111111", "5555555555554444", "378282246310005", "6011111111111117"} {
		if !card([]byte(ok)) {
			t.Errorf("%s should be a card", ok)
		}
	}
	for _, bad := range []string{"4111111111111112", "1234567812345670", "9999999999999995"} {
		if card([]byte(bad)) {
			t.Errorf("%s should not be a card", bad)
		}
	}
}

func TestTokensAreStableAndKeyed(t *testing.T) {
	a, b := New(testKey), New([]byte("a-completely-different-key-xxxxx"))
	if a.String("ip=10.0.0.1") != a.String("ip=10.0.0.1") {
		t.Fatal("same value, same key: tokens differ")
	}
	if a.String("ip=10.0.0.1") == b.String("ip=10.0.0.1") {
		t.Fatal("different keys gave the same token")
	}
	if a.String("from ::ffff:10.0.0.1 x") != a.String("from 10.0.0.1 x") {
		t.Fatal("IPv4-mapped IPv6 should tokenize like the IPv4 address")
	}
	if a.Token("ip", "admin") == a.Token("user", "admin") {
		t.Fatal("domains not separated")
	}
	if strings.Contains(a.String("user=alice"), "alice") {
		t.Fatal("raw username leaked")
	}
}

func TestEventAttributes(t *testing.T) {
	r := New(testKey)
	ev := event.Event{Service: "auth", Message: "Login failed user=bob", Attrs: map[string]string{
		"http.request.header.authorization": "Bearer xyz",
		"db.password":                       "x",
		"enduser.id":                        "bob",
		"client.address":                    "192.0.2.7",
		"note":                              "mail me at bob@example.com",
		"status":                            "401",
	}}
	r.Event(&ev)
	want := map[string]string{
		"http.request.header.authorization": "<SECRET>",
		"db.password":                       "<SECRET>",
		"enduser.id":                        "usr_" + r.Token("user", "bob"),
		"client.address":                    "ip_" + r.Token("ip", "192.0.2.7"),
		"note":                              "mail me at <EMAIL>",
		"status":                            "401",
	}
	for k, v := range want {
		if ev.Attrs[k] != v {
			t.Errorf("attr %s = %q, want %q", k, ev.Attrs[k], v)
		}
	}
	if ev.Message != "Login failed user=usr_"+r.Token("user", "bob") || ev.Service != "auth" {
		t.Fatalf("message/service: %+v", ev)
	}
	// The username token is the same in the message and in the attribute,
	// so detection can join them.
	if !strings.Contains(ev.Message, ev.Attrs["enduser.id"]) {
		t.Fatal("message and attribute tokens differ")
	}
	c := r.Counts()
	if c["secret"] != 2 || c["username"] != 2 || c["ip"] != 1 || c["email"] != 1 {
		t.Fatalf("counts %v", c)
	}
}

func TestConcurrentUse(t *testing.T) {
	r := New(testKey)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 500 {
				r.String("user=alice ip=10.0.0.1 card 4111111111111111")
			}
		})
	}
	wg.Wait()
	if c := r.Counts(); c["card"] != 4000 || c["ip"] != 4000 {
		t.Fatalf("counts %v", c)
	}
}

func FuzzRedactNeverLeaksCards(f *testing.F) {
	f.Add("pay 4111111111111111 now", "x")
	f.Fuzz(func(t *testing.T, prefix, suffix string) {
		r := New(testKey)
		in := prefix + " 4111111111111111 " + suffix
		out := r.String(in)
		if strings.Contains(out, "4111111111111111") {
			t.Fatalf("card leaked: %q -> %q", in, out)
		}
	})
}

var benchLines = []string{
	"Payment authorized txn_8f2a0c1d9e7b amount=1250.00 INR merchant=acme_books card 4111 1111 1111 1111 in 182ms",
	"Login failed user=priya.sharma@gmail.com ip=10.24.7.91 attempts=3 request_id=9f86d081884c7d65",
	"Request 4f2a9c1b7e3d5a60 completed in 23ms status=200 trace=550e8400-e29b-41d4-a716-446655440000",
	"Ledger entry posted acct_7c1e2d3f4a amount=88.10 INR journal=0d5c1f8e-9b2a-4c3d-8e7f-6a5b4c3d2e1f",
}

func BenchmarkRedact(b *testing.B) {
	r := New(testKey)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		r.String(benchLines[i%len(benchLines)])
	}
}
