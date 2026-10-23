// Command gen writes the labelled synthetic PII test set used to measure
// redaction precision and recall (internal/redact/eval_test.go).
//
//	go run ./internal/redact/testdata/gen > internal/redact/testdata/pii_labelled.jsonl
//
// It shares no code with the redactor: checksums and formats are
// re-implemented here so the evaluation is not circular. Every line records
// the PII values it contains. Hard negatives (order ids, tracking numbers,
// timestamps, hashes, UUIDs, pod names...) are generated at random and NOT
// filtered, so some will pass a checksum by chance (about 1 in 10 for Luhn
// or Verhoeff), exactly as in real logs; those become honest false
// positives.
package main

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
)

type label struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type line struct {
	Source string  `json:"source"`
	Text   string  `json:"text"`
	PII    []label `json:"pii"`
}

var r = rand.New(rand.NewPCG(2026, 10))

func pick[T any](xs ...T) T { return xs[r.IntN(len(xs))] }

func digits(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('0' + r.IntN(10))
	}
	return string(b)
}

func alnum(n int, set string) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[r.IntN(len(set))]
	}
	return string(b)
}

const (
	lowerSet  = "abcdefghijklmnopqrstuvwxyz"
	upperSet  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitSet  = "0123456789"
	alnumSet  = lowerSet + upperSet + digitSet
	b64urlSet = alnumSet + "-_"
	hexSet    = "0123456789abcdef"
)

// ── checksums (independent implementations) ──────────────────────────

func luhnDigit(payload string) byte {
	sum := 0
	for i := 0; i < len(payload); i++ {
		d := int(payload[len(payload)-1-i] - '0')
		if i%2 == 0 { // these positions are doubled once the check digit is appended
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return byte('0' + (10-sum%10)%10)
}

var vd = [10][10]int{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5}, {2, 3, 4, 0, 1, 7, 8, 9, 5, 6}, {3, 4, 0, 1, 2, 8, 9, 5, 6, 7}, {4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1}, {6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3}, {8, 7, 6, 5, 9, 3, 2, 1, 0, 4}, {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}}
var vp = [8][10]int{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4}, {5, 8, 0, 3, 7, 9, 6, 1, 4, 2}, {8, 9, 1, 6, 0, 4, 3, 5, 2, 7}, {9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1}, {2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}}
var vinv = [10]int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}

func verhoeffDigit(payload string) byte {
	c := 0
	for i := 0; i < len(payload); i++ {
		c = vd[c][vp[(i+1)%8][int(payload[len(payload)-1-i]-'0')]]
	}
	return byte('0' + vinv[c])
}

// ── PII generators ────────────────────────────────────────────────────

var firsts = []string{"aarav", "priya", "rahul", "ananya", "vikram", "sneha", "arjun", "kavya", "rohan", "meera", "john", "maria", "wei", "fatima", "deepak"}
var lasts = []string{"sharma", "iyer", "patel", "reddy", "nair", "gupta", "khan", "singh", "das", "menon", "smith", "garcia", "chen"}

func email() string {
	f, l := pick(firsts...), pick(lasts...)
	local := pick(f+"."+l, f+l+digits(2), f+"_"+l, f[:1]+l, f+"+"+pick("alerts", "work", "test"), f+"."+l+digits(1))
	dom := pick("gmail.com", "yahoo.co.in", "outlook.com", "acme-corp.in", "mail.example.org", "corp.bank.co.in", "student.iitm.ac.in", "proton.me")
	return local + "@" + dom
}

func mobile10() string { return string(byte('6'+r.IntN(4))) + digits(9) }

func phone() string {
	m := mobile10()
	switch r.IntN(7) {
	case 0:
		return "+91 " + m[:5] + " " + m[5:]
	case 1:
		return "+91-" + m
	case 2:
		return "+91" + m
	case 3:
		return m[:5] + " " + m[5:]
	case 4:
		return "0" + m
	case 5:
		return m[:3] + "-" + m[3:6] + "-" + m[6:]
	}
	return m
}

func aadhaarNum() string {
	p := string(byte('2'+r.IntN(8))) + digits(10)
	n := p + string(verhoeffDigit(p))
	switch r.IntN(3) {
	case 0:
		return n[:4] + " " + n[4:8] + " " + n[8:]
	case 1:
		return n[:4] + "-" + n[4:8] + "-" + n[8:]
	}
	return n
}

func panNum() string {
	return alnum(3, upperSet) + string("PCHFATBLJG"[r.IntN(10)]) + alnum(1, upperSet) + digits(4) + alnum(1, upperSet)
}

func cardNum() string {
	var p string
	n := 16
	switch r.IntN(5) {
	case 0:
		p = "4" + digits(14) // Visa
	case 1:
		p = pick("51", "52", "53", "54", "55") + digits(13) // Mastercard
	case 2:
		p, n = pick("34", "37")+digits(12), 15 // Amex
	case 3:
		p = pick("60", "65", "81", "82") + digits(13) // RuPay
	default:
		p = "2" + pick("221", "345", "720") + digits(11) // Mastercard 2-series
	}
	num := p + string(luhnDigit(p))
	switch {
	case n == 15 && r.IntN(2) == 0:
		return num[:4] + " " + num[4:10] + " " + num[10:]
	case n == 16 && r.IntN(3) == 0:
		return num[:4] + " " + num[4:8] + " " + num[8:12] + " " + num[12:]
	case n == 16 && r.IntN(3) == 0:
		return num[:4] + "-" + num[4:8] + "-" + num[8:12] + "-" + num[12:]
	}
	return num
}

func apiKey() string {
	switch r.IntN(7) {
	case 0:
		return pick("sk_live_", "sk_test_") + alnum(24, alnumSet)
	case 1:
		return "AKIA" + alnum(16, upperSet+digitSet)
	case 2:
		return "ghp_" + alnum(36, alnumSet)
	case 3:
		return "xoxb-" + digits(12) + "-" + digits(13) + "-" + alnum(24, alnumSet)
	case 4:
		return "AIza" + alnum(35, b64urlSet)
	case 5:
		return "gsk_" + alnum(48, alnumSet)
	}
	return "glpat-" + alnum(20, b64urlSet)
}

func jwt() string {
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + alnum(40, b64urlSet) + "." + alnum(43, b64urlSet)
}

func secretValue() string {
	return pick(alnum(10, alnumSet)+"!", "S3cr3t-"+alnum(6, alnumSet), alnum(32, alnumSet), "hunter"+digits(2))
}

func ipv4() string {
	switch r.IntN(3) {
	case 0:
		return fmt.Sprintf("10.%d.%d.%d", r.IntN(256), r.IntN(256), 1+r.IntN(254))
	case 1:
		return fmt.Sprintf("192.168.%d.%d", r.IntN(256), 1+r.IntN(254))
	}
	return fmt.Sprintf("%d.%d.%d.%d", 1+r.IntN(223), r.IntN(256), r.IntN(256), 1+r.IntN(254))
}

func ipv6() string {
	return fmt.Sprintf("2001:db8:%x:%x::%x", r.IntN(65536), r.IntN(65536), 1+r.IntN(65535))
}

// username returns a personal or service-specific account name. Built-in
// role accounts (root, admin, ubuntu, ...) are not personal data and are
// kept readable by the redactor, so they are not generated as labelled PII.
func username() string {
	return pick(pick(firsts...), pick(firsts...)+"."+pick(lasts...), "deploy", "svc_"+pick("backup", "ci", "etl"), pick(firsts...)+digits(2), pick(firsts...)+"_"+pick(lasts...))
}

// ── hard negatives (random, not filtered) ─────────────────────────────

func orderID() string  { return digits(12) }
func tracking() string { return "4" + digits(15) }
func epochMs() string  { return "17" + digits(11) }
func sha1() string     { return alnum(40, hexSet) }
func uuid() string {
	h := alnum(32, hexSet)
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-" + h[16:20] + "-" + h[20:]
}
func podName() string {
	return pick("api", "worker", "ledger") + "-" + alnum(9, "bcdfghjklmnpqrstvwxz2456789") + "-" + alnum(5, "bcdfghjklmnpqrstvwxz2456789")
}
func amount() string  { return fmt.Sprintf("%d.%02d", r.IntN(100000), r.IntN(100)) }
func version() string { return fmt.Sprintf("v%d.%d.%d", r.IntN(5), r.IntN(30), r.IntN(100)) }
func timestamp() string {
	return fmt.Sprintf("2026-%02d-%02dT%02d:%02d:%02d.%03dZ", 1+r.IntN(12), 1+r.IntN(28), r.IntN(24), r.IntN(60), r.IntN(60), r.IntN(1000))
}
func reqID() string      { return alnum(16, hexSet) }
func latency() string    { return fmt.Sprintf("%dms", r.IntN(5000)) }
func port() string       { return fmt.Sprint(1024 + r.IntN(60000)) }
func invalidPAN() string { return alnum(5, upperSet) + digits(5) }
func errCode() string    { return pick("E", "ERR-", "0x") + digits(4) }

// ── line templates ────────────────────────────────────────────────────

type builder struct {
	sb  strings.Builder
	pii []label
}

func (b *builder) s(text string) *builder { b.sb.WriteString(text); return b }
func (b *builder) p(kind, value string) *builder {
	b.sb.WriteString(value)
	b.pii = append(b.pii, label{kind, value})
	return b
}

type tmpl struct {
	source string
	build  func(b *builder)
}

var positives = []tmpl{
	{"sshd", func(b *builder) {
		b.s("sshd["+digits(5)+"]: Failed password for ").p("username", username()).s(" from ").p("ip", ipv4()).s(" port " + port() + " ssh2")
	}},
	{"sshd", func(b *builder) {
		b.s("sshd["+digits(5)+"]: Failed password for invalid user ").p("username", username()).s(" from ").p("ip", ipv4()).s(" port " + port() + " ssh2")
	}},
	{"sshd", func(b *builder) {
		b.s("sshd["+digits(4)+"]: Accepted publickey for ").p("username", username()).s(" from ").p("ip", pick(ipv4(), ipv6())).s(" port " + port() + " ssh2: RSA SHA256:" + alnum(43, alnumSet[:62]))
	}},
	{"pam", func(b *builder) {
		b.s("pam_unix(sshd:session): session opened for user ").p("username", username()).s(" by (uid=0)")
	}},
	{"nginx", func(b *builder) {
		b.p("ip", ipv4()).s(" - - [" + timestamp() + "] \"GET /api/v1/orders/" + orderID() + " HTTP/1.1\" " + pick("200", "404", "500") + " " + digits(4) + " \"-\" \"Mozilla/5.0\" rt=0." + digits(3))
	}},
	{"auth", func(b *builder) {
		b.s("Login failed user=").p("username", pick(username(), email())).s(" ip=").p("ip", ipv4()).s(" attempts=" + fmt.Sprint(1+r.IntN(9)) + " request_id=" + reqID())
	}},
	{"auth", func(b *builder) {
		b.s("Login succeeded user=").p("username", username()).s(" ip=").p("ip", ipv4()).s(" session=sess_" + alnum(10, hexSet) + " at " + timestamp())
	}},
	{"support", func(b *builder) {
		b.s("Ticket #"+digits(6)+" opened by ").p("email", email()).s(" callback ").p("phone", phone()).s(" priority=" + pick("P1", "P2", "P3"))
	}},
	{"support", func(b *builder) {
		b.s("Customer updated contact: mobile ").p("phone", phone()).s(", email ").p("email", email())
	}},
	{"kyc", func(b *builder) {
		b.s("KYC submitted for customer "+digits(8)+" aadhaar=").p("aadhaar", aadhaarNum()).s(" pan=").p("pan", panNum()).s(" status=PENDING")
	}},
	{"kyc", func(b *builder) {
		b.s("Verification failed: Aadhaar ").p("aadhaar", aadhaarNum()).s(" does not match name on PAN ").p("pan", panNum())
	}},
	{"payments", func(b *builder) {
		b.s("Payment authorized txn_"+alnum(12, hexSet)+" amount="+amount()+" INR card ").p("card", cardNum()).s(" in " + latency())
	}},
	{"payments", func(b *builder) {
		b.s(`{"event":"charge.failed","card_number":"`).p("card", cardNum()).s(`","order_id":"`+orderID()+`","email":"`).p("email", email()).s(`"}`)
	}},
	{"payments", func(b *builder) {
		b.s("Refund to UPI handle failed for ").p("phone", phone()).s(" amount " + amount() + " ref " + orderID())
	}},
	{"app", func(b *builder) {
		b.s("Calling upstream with Authorization: Bearer ").p("token", pick(jwt(), alnum(32, b64urlSet))).s(" timeout=" + latency())
	}},
	{"app", func(b *builder) {
		b.s("Loaded config: region=ap-south-1 api_key=").p("api_key", apiKey()).s(" retries=3")
	}},
	{"app", func(b *builder) {
		b.s("Webhook signature check failed for endpoint "+uuid()+" secret=").p("secret", secretValue())
	}},
	{"app", func(b *builder) {
		b.s(`{"level":"error","msg":"db connect failed","dsn_user":"app","password":"`).p("secret", secretValue()).s(`","host":"`).p("ip", ipv4()).s(`"}`)
	}},
	{"ci", func(b *builder) {
		b.s("git clone using token ").p("api_key", apiKey()).s(" at commit " + sha1())
	}},
	{"k8s", func(b *builder) {
		b.s("pod "+podName()+" assigned IP ").p("ip", ipv4()).s(" node=ip-" + digits(2) + "-0-1-" + digits(2) + " image=" + version())
	}},
	{"mail", func(b *builder) {
		b.s("Delivered OTP to ").p("phone", phone()).s(" and receipt to ").p("email", email()).s(" in " + latency())
	}},
}

var negatives = []tmpl{
	{"payments", func(b *builder) {
		b.s("Order " + orderID() + " shipped, tracking " + tracking() + " amount=" + amount() + " INR at " + timestamp())
	}},
	{"app", func(b *builder) {
		b.s("Request " + reqID() + " completed in " + latency() + " status=200 trace=" + uuid())
	}},
	{"ci", func(b *builder) {
		b.s("Build " + digits(5) + " passed at commit " + sha1() + " image " + version() + " duration " + latency())
	}},
	{"k8s", func(b *builder) {
		b.s("Scaled deployment " + podName() + " replicas=" + fmt.Sprint(1+r.IntN(20)) + " revision=" + digits(3))
	}},
	{"db", func(b *builder) {
		b.s("Slow query took " + latency() + " rows=" + digits(6) + " ts=" + epochMs() + " plan_hash=" + digits(10))
	}},
	{"app", func(b *builder) {
		b.s("Invoice " + digits(10) + " generated for account acct_" + alnum(10, hexSet) + " total " + amount())
	}},
	{"app", func(b *builder) {
		b.s("Error code " + errCode() + " from upstream after " + latency() + " ref=" + invalidPAN())
	}},
	{"metrics", func(b *builder) {
		b.s("cpu=0." + digits(2) + " mem=" + digits(10) + " bytes gc_pause=" + latency() + " goroutines=" + digits(4))
	}},
	{"batch", func(b *builder) {
		b.s("Processed batch " + digits(12) + " with " + digits(5) + " records offset " + digits(16))
	}},
	{"app", func(b *builder) {
		b.s("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) build " + digits(8) + " session=sess_" + alnum(10, hexSet))
	}},
}

// fakeMarker is spliced into every synthetic key, token and secret value on
// disk (e.g. "sk_l{{fake}}ive_...") so the committed corpus never matches
// provider secret-scanner patterns (GitHub push protection, gitleaks). The
// eval test strips it before decoding, so the redactor sees the real format.
const fakeMarker = "{{fake}}"

func unscannable(js []byte, pii []label) []byte {
	out := string(js)
	for _, l := range pii {
		if (l.Kind != "api_key" && l.Kind != "token" && l.Kind != "secret") || len(l.Value) < 5 {
			continue
		}
		raw, _ := json.Marshal(l.Value)
		v := string(raw[1 : len(raw)-1])
		out = strings.ReplaceAll(out, v, v[:4]+fakeMarker+v[4:])
	}
	return []byte(out)
}

func main() {
	w := os.Stdout
	for i := range 5000 {
		set := positives
		if i%5 >= 3 { // 40% of lines carry no PII
			set = negatives
		}
		t := set[r.IntN(len(set))]
		var b builder
		t.build(&b)
		if b.pii == nil {
			b.pii = []label{}
		}
		js, err := json.Marshal(line{Source: t.source, Text: b.sb.String(), PII: b.pii})
		if err != nil {
			panic(err)
		}
		if _, err := w.Write(append(unscannable(js, b.pii), '\n')); err != nil {
			panic(err)
		}
	}
}
