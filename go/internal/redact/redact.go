// Package redact removes PII from log events before anything is written to
// disk. It runs at the gateway, ahead of the WAL, so raw PII never reaches
// disk, metrics, logs or the LLM.
//
// Two treatments:
//
//   - Masking (the value is gone): emails, Indian mobile numbers, Aadhaar
//     numbers (Verhoeff-validated), PAN, payment cards (Luhn + issuer
//     prefix), API keys, bearer tokens/JWTs and other secrets.
//   - Keyed tokenization (the value is replaced by a stable pseudonym): IP
//     addresses and usernames become ip_<hmac> / usr_<hmac>, using
//     HMAC-SHA256 under a secret key, truncated to 48 bits. The same value
//     always maps to the same token, so "20 failed logins for one user from
//     one source" is still detectable, but without the key the token can't
//     be reversed or brute-forced (unlike a plain hash of an IPv4 address,
//     which can be inverted by trying all 2^32 addresses).
//
// The matchers are hand-written single-pass scanners, not regexps: the
// redactor runs on every event, and in Phase 3 Go's regexp cost ~10 us per
// message.
package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
)

// Kind is a category of PII.
type Kind uint8

const (
	KindAPIKey Kind = iota // known key formats (sk_live_, AKIA, ghp_, ...)
	KindToken              // bearer tokens and JWTs
	KindSecret             // password=..., token=..., high-entropy strings
	KindUser               // usernames (tokenized)
	KindEmail
	KindCard
	KindAadhaar
	KindPhone
	KindPAN
	KindIP // tokenized
	numKinds
)

var kindNames = [numKinds]string{"api_key", "token", "secret", "username", "email", "card", "aadhaar", "phone", "pan", "ip"}

func (k Kind) String() string { return kindNames[k] }

// Kinds lists every kind, for metrics.
func Kinds() []Kind {
	out := make([]Kind, numKinds)
	for i := range out {
		out[i] = Kind(i)
	}
	return out
}

var placeholders = [numKinds]string{"<API_KEY>", "<TOKEN>", "<SECRET>", "", "<EMAIL>", "<CARD>", "<AADHAAR>", "<PHONE>", "<PAN>", ""}

// Finding is one detected span [Start, End) in the input.
type Finding struct {
	Kind       Kind
	Start, End int
}

// Redactor is safe for concurrent use.
type Redactor struct {
	key    []byte
	counts [numKinds]atomic.Int64
}

// New returns a redactor that tokenizes with key (at least 16 bytes).
func New(key []byte) *Redactor {
	return &Redactor{key: slices.Clone(key)}
}

// Counts returns how many values of each kind have been redacted. Counts
// only: values are never recorded anywhere.
func (r *Redactor) Counts() map[string]int64 {
	out := make(map[string]int64, numKinds)
	for k := range numKinds {
		out[k.String()] = r.counts[k].Load()
	}
	return out
}

// Redact returns s with every finding replaced, plus the findings (offsets
// into s).
func (r *Redactor) Redact(s string) (string, []Finding) {
	fs := Find(s)
	if len(fs) == 0 {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, f := range fs {
		b.WriteString(s[last:f.Start])
		b.WriteString(r.replacement(f.Kind, s[f.Start:f.End]))
		last = f.End
		r.counts[f.Kind].Add(1)
	}
	b.WriteString(s[last:])
	return b.String(), fs
}

// String is Redact without the findings.
func (r *Redactor) String(s string) string {
	out, _ := r.Redact(s)
	return out
}

func (r *Redactor) replacement(k Kind, v string) string {
	switch k {
	case KindIP:
		if a, err := netip.ParseAddr(strings.Trim(v, "[]")); err == nil {
			v = a.Unmap().String() // canonical form: ::ffff:1.2.3.4 and 1.2.3.4 tokenize alike
		}
		return "ip_" + r.Token("ip", v)
	case KindUser:
		if systemAccounts[strings.ToLower(v)] {
			return v // a role, not a person: keep it readable
		}
		if strings.Contains(v, "@") {
			v = strings.ToLower(v) // email-style usernames are case-insensitive
		}
		return "usr_" + r.Token("user", v)
	}
	return placeholders[k]
}

// systemAccounts are built-in and role accounts. They identify no natural
// person, so they are not personal data, and they are exactly what attacks
// target ("brute force against root", "sudo to root"): keeping them
// readable makes the security rules and their alerts far more useful.
var systemAccounts = map[string]bool{
	"root": true, "admin": true, "administrator": true, "guest": true, "nobody": true, "daemon": true,
	"sshd": true, "www-data": true, "postgres": true, "mysql": true, "oracle": true, "ubuntu": true,
	"ec2-user": true, "centos": true, "git": true, "ftp": true, "uucp": true, "apache": true,
	"nginx": true, "test": true, "user": true, "pi": true, "support": true,
}

// IsSystemAccount reports whether name is a built-in/role account that the
// redactor leaves readable.
func IsSystemAccount(name string) bool { return systemAccounts[strings.ToLower(name)] }

// Token is the keyed pseudonym for value in a domain ("ip", "user"):
// hex(HMAC-SHA256(key, domain || 0 || value))[:12]. The domain stops an IP
// and a username with the same text from sharing a token. 48 bits keeps
// collisions unlikely below millions of distinct values per domain.
func (r *Redactor) Token(domain, value string) string {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(domain))
	m.Write([]byte{0})
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil)[:6])
}

// priority decides overlaps: lower wins. Secrets first (never leak a key
// because something else matched part of it); usernames before emails so an
// email used as a login keeps a stable identity token for the security
// rules.
var priority = [numKinds]int{
	KindAPIKey: 0, KindToken: 0, KindSecret: 1, KindUser: 2, KindEmail: 3,
	KindCard: 4, KindAadhaar: 5, KindPhone: 6, KindPAN: 7, KindIP: 8,
}

// Find returns the non-overlapping PII spans in s, in order.
func Find(s string) []Finding {
	var fs []Finding
	ls := lowerASCII(s) // one lowercase copy for every keyword search
	fs = scanWords(s, fs)
	fs = scanBearer(s, ls, fs)
	fs = scanKeyValueSecrets(s, ls, fs)
	fs = scanUsernames(s, ls, fs)
	fs = scanEmails(s, fs)
	fs = scanDigits(s, fs)
	fs = scanIPs(s, fs)
	return resolve(fs)
}

func resolve(fs []Finding) []Finding {
	if len(fs) <= 1 {
		return fs
	}
	slices.SortStableFunc(fs, func(a, b Finding) int {
		if pa, pb := priority[a.Kind], priority[b.Kind]; pa != pb {
			return pa - pb
		}
		if la, lb := a.End-a.Start, b.End-b.Start; la != lb {
			return lb - la // longer first
		}
		return a.Start - b.Start
	})
	var kept []Finding
	for _, f := range fs {
		ok := true
		for _, k := range kept {
			if f.Start < k.End && k.Start < f.End {
				ok = false
				break
			}
		}
		if ok {
			kept = append(kept, f)
		}
	}
	slices.SortFunc(kept, func(a, b Finding) int { return a.Start - b.Start })
	return kept
}

// Pseudonym returns what the redactor writes in place of a username
// (KindUser) or IP address (KindIP): the token, or the value itself for a
// system account. Evaluators use it to compute expected tokens.
func (r *Redactor) Pseudonym(k Kind, v string) string { return r.replacement(k, v) }
