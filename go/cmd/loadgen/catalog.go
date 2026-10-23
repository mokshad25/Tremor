package main

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
)

// The message catalogue is ported from TREMOR's Python simulator
// (simulator/gen_logs.py) so both implementations see the same log shapes,
// including fake PII (emails, published test cards, JWTs, sk_test_ keys) that
// the Phase 4 redaction stage must catch.

type profile struct {
	name      string
	weight    float64 // relative event rate (Python base_rate_per_s)
	errorRate float64 // baseline ERROR probability
	templates map[string][]tmpl
}

var catalogue = []profile{
	{"payment-gateway", 8, 0.020, compileAll(map[string][]string{
		"INFO": {
			"Payment authorized {txn} amount={amount} {cur} merchant={merchant} card {card}",
			"Capture settled {txn} amount={amount} {cur} in {ms}ms",
			"Refund issued re_{hex} for {txn} amount={amount} {cur}",
			"3DS challenge completed for {txn} customer={email}",
		},
		"WARNING": {
			"Card declined {txn} reason={decline} card {card}",
			"Retrying acquirer call {txn} attempt={attempt} after {ms}ms",
		},
		"ERROR": {
			"Acquirer timeout {txn} after {ms}ms upstream={ip}",
			"Payment failed {txn} code={code} for {email}",
		},
	})},
	{"auth-service", 6, 0.015, compileAll(map[string][]string{
		"INFO": {
			"Login succeeded user={email} ip={ip} session=sess_{hex}",
			"Token refreshed Authorization: Bearer {jwt} expires_in={ttl}",
			"MFA challenge passed user={email} method={mfa}",
		},
		"WARNING": {"Login failed user={email} ip={ip} attempts={attempt}"},
		"ERROR": {
			"Token validation failed Authorization: Bearer {jwt} reason=signature_mismatch",
			"Rate limit store unreachable at {ip} after {ms}ms",
		},
	})},
	{"ledger", 4, 0.015, compileAll(map[string][]string{
		"INFO": {
			"Ledger entry posted acct_{hex} amount={amount} {cur} journal={uuid}",
			"Balance check acct_{hex} balance={amount} {cur}",
			"Reconciliation batch {uuid} completed entries={entries}",
		},
		"WARNING": {"Slow query on ledger_entries took {ms}ms"},
		"ERROR": {
			"DB timeout posting acct_{hex} after {ms}ms",
			"Webhook signing failed for endpoint {uuid} key={sk}",
		},
	})},
}

// genericTemplates are used for services beyond the three catalogue ones so
// -services can scale to any shard count.
var genericTemplates = compileAll(map[string][]string{
	"INFO": {
		"GET /api/v1/items/{hex} 200 in {ms}ms",
		"POST /api/v1/orders {txn} 201 in {ms}ms",
		"Cache hit ratio={ratio} for region {region}",
		"Job {uuid} completed in {ms}ms",
	},
	"WARNING": {
		"Slow upstream {ip} took {ms}ms",
		"Retrying request {txn} attempt={attempt}",
	},
	"ERROR": {
		"Upstream {ip} returned {code} after {ms}ms",
		"Database connection pool exhausted waiting {ms}ms",
	},
})

var (
	testCards = []string{"4111111111111111", "5555 5555 5555 4444", "3782-822463-10005"}
	firsts    = []string{"alice", "bob", "carol", "dev", "erin", "farah", "gopal", "hana"}
	lasts     = []string{"smith", "khan", "garcia", "iyer", "chen", "okafor"}
	domains   = []string{"example.com", "mail.test", "corp.example"}
	merchants = []string{"acme_books", "blue_cafe", "metro_rail", "pixel_store"}
	regions   = []string{"ap-south-1", "us-east-1", "eu-west-1"}
)

const (
	alnum  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b64url = alnum + "-_"
)

func pick(r *rand.Rand, xs []string) string { return xs[r.IntN(len(xs))] }

func chars(r *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(len(alphabet))]
	}
	return string(b)
}

func hexN(r *rand.Rand, n int) string {
	const digits = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = digits[r.IntN(16)]
	}
	return string(b)
}

// fillers produce a value for each {placeholder}.
var fillers = map[string]func(*rand.Rand) string{
	"txn":      func(r *rand.Rand) string { return "txn_" + hexN(r, 12) },
	"hex":      func(r *rand.Rand) string { return hexN(r, 10) },
	"amount":   func(r *rand.Rand) string { return strconv.FormatFloat(1+r.Float64()*2499, 'f', 2, 64) },
	"cur":      func(r *rand.Rand) string { return pick(r, []string{"USD", "EUR", "GBP", "INR"}) },
	"merchant": func(r *rand.Rand) string { return pick(r, merchants) },
	"card":     func(r *rand.Rand) string { return pick(r, testCards) },
	"email": func(r *rand.Rand) string {
		return fmt.Sprintf("%s.%s%d@%s", pick(r, firsts), pick(r, lasts), 1+r.IntN(99), pick(r, domains))
	},
	"ip": func(r *rand.Rand) string {
		return fmt.Sprintf("10.%d.%d.%d", r.IntN(256), r.IntN(256), 1+r.IntN(254))
	},
	"decline": func(r *rand.Rand) string {
		return pick(r, []string{"insufficient_funds", "do_not_honor", "expired_card"})
	},
	"attempt": func(r *rand.Rand) string { return strconv.Itoa(1 + r.IntN(4)) },
	"code":    func(r *rand.Rand) string { return pick(r, []string{"502", "503", "504", "ACQ_TIMEOUT"}) },
	"jwt": func(r *rand.Rand) string {
		return "eyJhbGciOiJIUzI1NiJ9." + chars(r, b64url, 24) + "." + chars(r, b64url, 16)
	},
	"ttl": func(r *rand.Rand) string { return pick(r, []string{"900", "1800", "3600"}) },
	"mfa": func(r *rand.Rand) string { return pick(r, []string{"totp", "sms", "webauthn"}) },
	"uuid": func(r *rand.Rand) string {
		h := hexN(r, 32)
		return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-" + h[16:20] + "-" + h[20:32]
	},
	"entries": func(r *rand.Rand) string { return strconv.Itoa(10 + r.IntN(4990)) },
	"sk":      func(r *rand.Rand) string { return "sk_test_" + chars(r, alnum, 24) },
	"ms":      func(r *rand.Rand) string { return strconv.Itoa(5 + r.IntN(3000)) },
	"ratio":   func(r *rand.Rand) string { return strconv.FormatFloat(r.Float64(), 'f', 2, 64) },
	"region":  func(r *rand.Rand) string { return pick(r, regions) },
}

// tmpl is a pre-split template: literal text interleaved with placeholders.
type tmpl struct {
	lits  []string // len(lits) == len(holes)+1
	holes []string
}

func compile(s string) tmpl {
	var t tmpl
	for {
		i := strings.IndexByte(s, '{')
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			break
		}
		name := s[i+1 : i+j]
		if _, ok := fillers[name]; !ok {
			panic("loadgen: unknown placeholder {" + name + "}")
		}
		t.lits = append(t.lits, s[:i])
		t.holes = append(t.holes, name)
		s = s[i+j+1:]
	}
	t.lits = append(t.lits, s)
	return t
}

func compileAll(m map[string][]string) map[string][]tmpl {
	out := make(map[string][]tmpl, len(m))
	for level, ss := range m {
		for _, s := range ss {
			out[level] = append(out[level], compile(s))
		}
	}
	return out
}

// render fills t. Like the Python generator, a placeholder repeated in one
// message gets the same value.
func (t tmpl) render(r *rand.Rand, sb *strings.Builder) string {
	sb.Reset()
	var seen map[string]string
	for i, h := range t.holes {
		sb.WriteString(t.lits[i])
		v, ok := seen[h]
		if !ok {
			v = fillers[h](r)
			if seen == nil {
				seen = make(map[string]string, 2)
			}
			seen[h] = v
		}
		sb.WriteString(v)
	}
	sb.WriteString(t.lits[len(t.lits)-1])
	return sb.String()
}
