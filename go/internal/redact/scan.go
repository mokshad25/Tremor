package redact

import (
	"net/netip"
	"strings"
)

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isAlnum(c byte) bool { return isDigit(c) || isUpper(c) || isLower(c) }
func isHex(c byte) bool   { return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }

// isWordByte is the character set of keys, tokens and base64 blobs.
func isWordByte(c byte) bool {
	return isAlnum(c) || c == '_' || c == '-' || c == '.' || c == '+' || c == '/' || c == '=' || c == '~'
}

// apiKeyPrefixes are well-known secret formats; minRest is the minimum
// length of what follows the prefix.
var apiKeyPrefixes = []struct {
	prefix  string
	minRest int
}{
	{"sk_live_", 16}, {"sk_test_", 16}, {"rk_live_", 16}, {"rk_test_", 16}, // Stripe secret/restricted
	{"ghp_", 30}, {"gho_", 30}, {"ghu_", 30}, {"ghs_", 30}, {"ghr_", 30}, {"github_pat_", 30}, // GitHub
	{"glpat-", 20},                                                            // GitLab
	{"xoxb-", 10}, {"xoxp-", 10}, {"xoxa-", 10}, {"xoxr-", 10}, {"xoxs-", 10}, // Slack
	{"AIza", 35},               // Google API key
	{"sk-ant-", 20},            // Anthropic
	{"sk-proj-", 20},           // OpenAI project keys
	{"gsk_", 20},               // Groq
	{"npm_", 30},               // npm
	{"SG.", 40},                // SendGrid
	{"hf_", 30},                // Hugging Face
	{"dop_v1_", 40},            // DigitalOcean
	{"shpat_", 30},             // Shopify
	{"AKIA", 16}, {"ASIA", 16}, // AWS access key id (exactly 16 after the prefix)
}

// scanWords classifies whole tokens: known API key formats, JWTs, PAN, and
// high-entropy strings.
func scanWords(s string, fs []Finding) []Finding {
	for i := 0; i < len(s); {
		if !isWordByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isWordByte(s[j]) {
			if s[j] == '=' {
				// '=' belongs to a token only as base64 padding at its end;
				// otherwise it separates key=value.
				k := j
				for k < len(s) && s[k] == '=' {
					k++
				}
				if k < len(s) && isWordByte(s[k]) {
					break
				}
			}
			j++
		}
		// Sentence punctuation is not part of a token.
		end := j
		for end > i && (s[end-1] == '.' || s[end-1] == ',') {
			end--
		}
		if end > i && !afterDigestLabel(s, i) {
			if k, ok := classifyWord(s[i:end]); ok {
				fs = append(fs, Finding{k, i, end})
			}
		}
		if j < len(s) && s[j] == '=' {
			j++ // skip the separator
		}
		i = j
	}
	return fs
}

func classifyWord(w string) (Kind, bool) {
	if len(w) < 10 {
		return 0, false // shorter than any key, JWT, PAN or entropy candidate
	}
	if len(w) == 10 && pan(w) {
		return KindPAN, true
	}
	if len(w) < 14 {
		return 0, false
	}
	for _, p := range apiKeyPrefixes {
		if strings.HasPrefix(w, p.prefix) && len(w)-len(p.prefix) >= p.minRest {
			if p.prefix == "AKIA" || p.prefix == "ASIA" {
				if len(w) != 20 || !allUpperAlnum(w) {
					continue
				}
			}
			return KindAPIKey, true
		}
	}
	if strings.HasPrefix(w, "eyJ") && strings.Count(w, ".") == 2 && len(w) >= 20 {
		return KindToken, true // JWT: base64url("{"...) . payload . signature
	}
	if highEntropy(w) {
		return KindSecret, true
	}
	return 0, false
}

func allUpperAlnum(w string) bool {
	for i := 0; i < len(w); i++ {
		if !isUpper(w[i]) && !isDigit(w[i]) {
			return false
		}
	}
	return true
}

// highEntropy flags random-looking strings: at least 24 characters, mixed
// case and digits, and at least 4.2 bits of Shannon entropy per character.
// Hex digests (git SHAs, sha256) top out at log2(16) = 4 bits and have no
// mixed case, and UUIDs have no upper case, so neither trips it; base64
// keys and session secrets typically score 4.5-5.5.
func highEntropy(w string) bool {
	core := strings.TrimRight(w, "=")
	if len(core) < 24 || len(core) > 512 {
		return false
	}
	var up, lo, dg bool
	for i := 0; i < len(core); i++ {
		c := core[i]
		up, lo, dg = up || isUpper(c), lo || isLower(c), dg || isDigit(c)
	}
	return up && lo && dg && shannon(core) >= 4.2
}

// lowerASCII returns s with ASCII letters lowercased. Byte offsets are
// unchanged, so matches found in the lowered copy index into s directly.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if isUpper(s[i]) {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if isUpper(b[j]) {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// indexFrom is strings.Index starting at from; ls is already lowercased and
// needle is lowercase, so this is a case-insensitive search.
func indexFrom(ls, needle string, from int) int {
	if from > len(ls) {
		return -1
	}
	k := strings.Index(ls[from:], needle)
	if k < 0 {
		return -1
	}
	return from + k
}

// scanBearer masks the credential after "Bearer " / "Basic ".
func scanBearer(s, ls string, fs []Finding) []Finding {
	for _, scheme := range []string{"bearer ", "basic "} {
		for i := 0; ; {
			k := indexFrom(ls, scheme, i)
			if k < 0 {
				break
			}
			if k > 0 && isAlnum(s[k-1]) {
				i = k + 1
				continue
			}
			v := k + len(scheme)
			for v < len(s) && s[v] == ' ' {
				v++
			}
			e := v
			for e < len(s) && isWordByte(s[e]) {
				e++
			}
			if e-v >= 8 && s[v] != '<' {
				fs = append(fs, Finding{KindToken, v, e})
			}
			i = e
		}
	}
	return fs
}

// secretKeys are field names whose value is a secret whatever it looks like.
var secretKeys = []string{
	"password", "passwd", "secret", // not "pwd": sudo's PWD= is the working directory "client_secret", "api_key", "apikey", "api-key",
	"access_token", "refresh_token", "auth_token", "token", "private_key", "authorization",
	"x-api-key", "session_token", "aws_secret_access_key",
}

// scanKeyValueSecrets masks values of password=..., "token": "...", etc.
func scanKeyValueSecrets(s, ls string, fs []Finding) []Finding {
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
				continue // e.g. "my_password_hint" is fine; "xpassword" is not this key
			}
			v, ok := valueAfterKey(s, k+len(key))
			if !ok {
				continue
			}
			e := valueEnd(s, v)
			val := s[v:e]
			if strings.EqualFold(val, "bearer") || strings.EqualFold(val, "basic") {
				continue // "Authorization: Bearer x": scanBearer masks x
			}
			if len(val) >= 4 && !isPlaceholder(val) {
				fs = append(fs, Finding{KindSecret, v, e})
			}
		}
	}
	return fs
}

// valueAfterKey skips `"`? `:` or `=` and spaces/quotes after a key name.
func valueAfterKey(s string, p int) (int, bool) {
	if p < len(s) && (s[p] == '"' || s[p] == '\'') {
		p++
	}
	for p < len(s) && s[p] == ' ' {
		p++
	}
	if p >= len(s) || (s[p] != '=' && s[p] != ':') {
		return 0, false
	}
	p++
	for p < len(s) && (s[p] == ' ' || s[p] == '"' || s[p] == '\'') {
		p++
	}
	return p, p < len(s)
}

func valueEnd(s string, v int) int {
	e := v
	for e < len(s) {
		c := s[e]
		if c == ' ' || c == '"' || c == '\'' || c == ',' || c == ';' || c == '&' || c == ')' || c == '}' || c == ']' {
			break
		}
		e++
	}
	return e
}

func isPlaceholder(v string) bool {
	return strings.HasPrefix(v, "<") || strings.HasPrefix(v, "usr_") || strings.HasPrefix(v, "ip_") ||
		strings.Trim(v, "*x") == "" || strings.EqualFold(v, "null") || strings.EqualFold(v, "none") ||
		strings.EqualFold(v, "redacted")
}

// userKeys introduce a username as key=value / key: value.
// (uid= is deliberately absent: it is a numeric account id, not a name.)
var userKeys = []string{"username", "user_name", "user.name", "user", "login", "logname", "ruser", "account", "enduser.id"}

// userPhrases introduce a username in free text (sshd, PAM, sudo, apps).
var userPhrases = []string{
	"invalid user ", "illegal user ", "for user ", "password for ", "publickey for ",
	"keyboard-interactive/pam for ", "session opened for user ", "session closed for user ",
	"authentication failure for ", "login as ", "logged in as ", "su: from ", "by user ",
	"sudo: ", "(to root) ", "(to ", "granted to ", "by admin ",
	"/home/", "/users/", // a home directory names its owner
}

// scanUsernames finds values that identify a user account.
func scanUsernames(s, ls string, fs []Finding) []Finding {
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
			for v < len(s) && s[v] == ' ' { // "sudo:   bob : TTY=..." pads the name
				v++
			}
			if ph == "password for " && strings.HasPrefix(ls[v:], "invalid user ") {
				continue // "Failed password for invalid user X": the other phrase owns it
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

func userValueEnd(s string, v int) int {
	e := v
	for e < len(s) && e-v < 64 {
		c := s[e]
		if !(isAlnum(c) || c == '_' || c == '.' || c == '-' || c == '@' || c == '+' || c == '\\' || c == '$') {
			break
		}
		e++
	}
	for e > v && s[e-1] == '.' { // trailing sentence period
		e--
	}
	return e
}

// scanEmails expands around each '@'.
func scanEmails(s string, fs []Finding) []Finding {
	for at := strings.IndexByte(s, '@'); at >= 0; {
		st := at
		for st > 0 && isLocalByte(s[st-1]) {
			st--
		}
		for st < at && (s[st] == '.') {
			st++
		}
		e := at + 1
		for e < len(s) && (isAlnum(s[e]) || s[e] == '-' || s[e] == '.') {
			e++
		}
		for e > at+1 && (s[e-1] == '.' || s[e-1] == '-') {
			e--
		}
		if st < at && validDomain(s[at+1:e]) {
			fs = append(fs, Finding{KindEmail, st, e})
		}
		next := strings.IndexByte(s[at+1:], '@')
		if next < 0 {
			break
		}
		at += 1 + next
	}
	return fs
}

func isLocalByte(c byte) bool {
	return isAlnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-'
}

// validDomain: at least two labels, a 2+ letter TLD.
func validDomain(d string) bool {
	dot := strings.LastIndexByte(d, '.')
	if dot <= 0 || len(d)-dot-1 < 2 {
		return false
	}
	for i := dot + 1; i < len(d); i++ {
		if !isUpper(d[i]) && !isLower(d[i]) {
			return false
		}
	}
	return true
}

// digitGroup is one run of digits within a candidate number.
type digitGroup struct{ start, end int }

// scanDigits finds phone numbers, Aadhaar numbers and cards. Each maximal
// sequence of digit groups joined by single spaces or hyphens is tried as a
// whole when its grouping matches a real-world format (4-4-4-4 cards, 4-4-4
// Aadhaar, 5-5 phones...), otherwise group by group. This avoids gluing
// unrelated numbers together ("amount 5000 9876543210") while still catching
// "4111 1111 1111 1111".
func scanDigits(s string, fs []Finding) []Finding {
	var buf []byte
	for i := 0; i < len(s); {
		if !isDigit(s[i]) || (i > 0 && (isAlnum(s[i-1]) || s[i-1] == '.' || s[i-1] == '_')) {
			i++
			continue
		}
		var groups []digitGroup
		j := i
		for {
			g := digitGroup{start: j}
			for j < len(s) && isDigit(s[j]) {
				j++
			}
			g.end = j
			groups = append(groups, g)
			if j+1 < len(s) && (s[j] == ' ' || s[j] == '-') && isDigit(s[j+1]) && len(groups) < 6 {
				j++
				continue
			}
			break
		}
		// The sequence must not continue as a word or a decimal/version.
		if j < len(s) && (isAlnum(s[j]) || s[j] == '_' || (s[j] == '.' && j+1 < len(s) && isDigit(s[j+1]))) {
			i = j
			continue
		}
		plus := i > 0 && s[i-1] == '+'
		if f, ok := classifyDigits(s, groups, plus, &buf); ok {
			fs = append(fs, f)
		} else {
			for _, g := range groups {
				one := []digitGroup{g}
				if f, ok := classifyDigits(s, one, plus && g.start == i, &buf); ok {
					fs = append(fs, f)
				}
			}
		}
		i = j
	}
	return fs
}

func sizes(groups []digitGroup) []int {
	out := make([]int, len(groups))
	for i, g := range groups {
		out[i] = g.end - g.start
	}
	return out
}

func eqInts(a []int, b ...int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func allFours(a []int, last int) bool {
	for i, n := range a {
		if n != 4 && !(i == len(a)-1 && n == last) {
			return false
		}
	}
	return true
}

// classifyDigits decides what a run of digit groups is, if anything.
func classifyDigits(s string, groups []digitGroup, plus bool, buf *[]byte) (Finding, bool) {
	*buf = (*buf)[:0]
	for _, g := range groups {
		*buf = append(*buf, s[g.start:g.end]...)
	}
	d := *buf
	sz := sizes(groups)
	start, end := groups[0].start, groups[len(groups)-1].end
	single := len(groups) == 1

	// Cards: one block of 13-19, 4-4-4-4(-3), or Amex 4-6-5.
	if (single || (len(sz) >= 4 && allFours(sz, 3)) || eqInts(sz, 4, 6, 5) || eqInts(sz, 4, 6, 4)) && card(d) {
		return Finding{KindCard, start, end}, true
	}
	// Phones with the country code: +91 98765 43210, +91-9876543210, 91 9876543210.
	if len(d) == 12 && d[0] == '9' && d[1] == '1' && indianMobile(d[2:]) &&
		(plus || (len(groups) >= 2 && sz[0] == 2)) {
		if plus {
			start-- // include the '+'
		}
		return Finding{KindPhone, start, end}, true
	}
	// Aadhaar: 12 digits as one block or 4-4-4, first digit 2-9, Verhoeff.
	if (single || eqInts(sz, 4, 4, 4)) && aadhaar(d) {
		return Finding{KindAadhaar, start, end}, true
	}
	// Mobile: 10 digits starting 6-9 (98765 43210, 987-654-3210), or with a
	// leading trunk 0 (09876543210).
	if (single || eqInts(sz, 5, 5) || eqInts(sz, 3, 3, 4) || eqInts(sz, 4, 3, 3)) && indianMobile(d) && !idContext(s, start) {
		return Finding{KindPhone, start, end}, true
	}
	if single && len(d) == 11 && d[0] == '0' && indianMobile(d[1:]) {
		return Finding{KindPhone, start, end}, true
	}
	return Finding{}, false
}

// scanIPs finds IPv4 (optionally with :port, port left in place) and IPv6.
func scanIPs(s string, fs []Finding) []Finding {
	for i := 0; i < len(s); {
		c := s[i]
		if !(isHex(c) || c == ':' || c == '[') || (i > 0 && (isAlnum(s[i-1]) || s[i-1] == '.' || s[i-1] == '_')) {
			i++
			continue
		}
		j := i
		for j < len(s) && (isHex(s[j]) || s[j] == '.' || s[j] == ':' || s[j] == '[' || s[j] == ']' || s[j] == '%') {
			j++
		}
		if j < len(s) && (isAlnum(s[j]) || s[j] == '_') {
			i = j
			continue
		}
		cand := strings.TrimRight(s[i:j], ".:")
		if st, e, ok := ipSpan(cand); ok {
			fs = append(fs, Finding{KindIP, i + st, i + e})
		}
		i = j
	}
	return fs
}

// ipSpan returns the address part of cand (which may carry a :port or
// brackets).
func ipSpan(cand string) (int, int, bool) {
	if strings.Count(cand, ".") == 3 && !strings.Contains(cand, "::") {
		addr := cand
		if c := strings.LastIndexByte(cand, ':'); c > 0 && !strings.Contains(cand[:c], ":") {
			addr = cand[:c] // 10.0.0.1:8080
		}
		if a, err := netip.ParseAddr(addr); err == nil && a.Is4() {
			return 0, len(addr), true
		}
		return 0, 0, false
	}
	if strings.Count(cand, ":") < 2 {
		return 0, 0, false
	}
	st, e := 0, len(cand)
	if strings.HasPrefix(cand, "[") {
		if k := strings.IndexByte(cand, ']'); k > 0 {
			st, e = 1, k // [2001:db8::1]:443
		}
	}
	if a, err := netip.ParseAddr(cand[st:e]); err == nil && a.Is6() {
		return st, e, true
	}
	return 0, 0, false
}

// idWords mark the number after them as an identifier, not a phone number:
// "order 9876543210", "invoice #7012345678", "txn_id=8123456789".
var idWords = []string{"order", "invoice", "txn", "transaction", "ref", "id", "no", "#", "ticket", "batch", "job", "build", "seq", "offset"}

// idContext reports whether the text just before position p (skipping
// separators like " ", "=", ":", "#") ends with an id word.
func idContext(s string, p int) bool {
	q := p
	for q > 0 && (s[q-1] == ' ' || s[q-1] == '=' || s[q-1] == ':' || s[q-1] == '#' || s[q-1] == '"' || s[q-1] == '_' || s[q-1] == '.') {
		if s[q-1] == '#' {
			return true
		}
		q--
	}
	w := q
	for w > 0 && (isAlnum(s[w-1]) || s[w-1] == '_') {
		w--
	}
	word := strings.ToLower(s[w:q])
	for _, id := range idWords {
		if word == id || strings.HasSuffix(word, "_"+id) || strings.HasSuffix(word, id+"_id") {
			return true
		}
	}
	return strings.HasSuffix(word, "id")
}

// afterDigestLabel reports whether the word at i follows "SHA256:", "SHA1:"
// or "MD5:": key fingerprints and content digests are public identifiers,
// not secrets, even though they look random.
func afterDigestLabel(s string, i int) bool {
	for _, lbl := range []string{"sha256:", "sha1:", "sha512:", "md5:"} {
		if i >= len(lbl) && strings.EqualFold(s[i-len(lbl):i], lbl) {
			return true
		}
	}
	return false
}
