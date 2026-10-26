package drain

import "strings"

// Masker replaces variable parts of a message (ids, IPs, numbers) with
// placeholders like <NUM> before Drain sees it, so messages that differ only
// in those parts share a template. The rules and their order are TREMOR's
// (app/core/templates.py), applied by drain3 as one re.sub per rule:
//
//	UUID  \b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b
//	HEX   \b0x[0-9a-fA-F]+\b
//	HEX   \b(?=[0-9a-fA-F]*\d)[0-9a-fA-F]{12,}\b
//	IP    \b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b
//	ID    \b(?:txn|req|acct|ord|usr|sess|kid|pay|ch|re)_[A-Za-z0-9]+\b
//	NUM   ((?<=[^A-Za-z0-9_])|^)[-+]?\d+(?:\.\d+)?(?:ms|s)?((?=[^A-Za-z0-9_])|$)
//
// The first five rules are matched in a single scan (maskWords) rather than
// five regexp passes, which cost 98% of mask + Drain time (Phase 7 pprof).
// The scan is exact, not an approximation, because every one of those
// matches starts at the first byte of a word run and ends at the last byte of
// one, and their placeholders contain no digits and are bounded by '<' and
// '>'. So a rule can never match inside or across an earlier rule's
// placeholder. Overlaps between rules are settled by trying the rules in
// order at each word start (HEX12 on the last segment of a UUID), plus one
// look-ahead in matchIP: an IP's port can be a word an earlier rule claims.
// NUM's lookbehind does see placeholders ('>' is a non-word byte), so it
// stays a second pass (maskNum) over the scan's output.
// mask_regex_test.go keeps the regexp implementation, and the differential
// tests require identical output on real logs, Python's fixture and fuzzing.
//
// Known divergence from Python: its \b and \d are Unicode-aware for str
// patterns; Go's are ASCII, and so is this scan. Messages with non-ASCII
// letters or digits glued to a number can mask differently. TREMOR's inputs
// are overwhelmingly ASCII and the drain3 comparison test runs on real
// TREMOR logs.
type Masker struct{}

// TremorMasker returns the masker matching TREMOR's Python configuration.
func TremorMasker() *Masker { return &Masker{} }

// Mask applies the UUID, HEX, IP and ID rules, then the NUM rule.
func (m *Masker) Mask(s string) string { return maskNum(maskWords(s)) }

// idPrefixes are the ID rule's alternatives, in the regex's order.
var idPrefixes = [...]string{"txn_", "req_", "acct_", "ord_", "usr_", "sess_", "kid_", "pay_", "ch_", "re_"}

// maskWords applies the UUID, HEX, HEX12, IP and ID rules in one pass. At
// each word start it tries the rules in TREMOR's order and replaces the first
// match; a word with no match is skipped whole, since no rule can start
// inside a word.
func maskWords(s string) string {
	var b strings.Builder
	last := 0 // end of the previous match, in s
	for i := 0; i < len(s); {
		if !isWord(s[i]) {
			i++
			continue
		}
		end, name := matchWord(s, i)
		if end < 0 {
			i = wordEnd(s, i)
			continue
		}
		if last == 0 && b.Len() == 0 {
			b.Grow(len(s))
		}
		b.WriteString(s[last:i])
		b.WriteString(name)
		last, i = end, end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// matchWord tries each rule at word start i (s[i-1] is not a word byte) and
// returns the end of the first match and its placeholder, or -1.
func matchWord(s string, i int) (int, string) {
	if e := matchUUID(s, i); e >= 0 {
		return e, "<UUID>"
	}
	w := wordEnd(s, i)
	if w-i >= 3 && s[i] == '0' && s[i+1] == 'x' && allHex(s[i+2:w]) {
		return w, "<HEX>"
	}
	if w-i >= 12 && allHex(s[i:w]) && hasASCIIDigit(s[i:w]) {
		return w, "<HEX>"
	}
	if e := matchIP(s, i); e >= 0 {
		return e, "<IP>"
	}
	for _, p := range idPrefixes {
		if strings.HasPrefix(s[i:], p) {
			// [A-Za-z0-9]+ then \b: the rest of the word must be alphanumeric.
			j := i + len(p)
			k := j
			for k < len(s) && isAlnum(s[k]) {
				k++
			}
			if k > j && k == w {
				return w, "<ID>"
			}
		}
	}
	return -1, ""
}

// matchUUID matches 8-4-4-4-12 hex digits at i followed by a word boundary.
func matchUUID(s string, i int) int {
	p := i
	for g, n := range [...]int{8, 4, 4, 4, 12} {
		if g > 0 {
			if p >= len(s) || s[p] != '-' {
				return -1
			}
			p++
		}
		if p+n > len(s) || !allHex(s[p:p+n]) {
			return -1
		}
		p += n
	}
	if !boundaryAfter(s, p) {
		return -1
	}
	return p
}

// matchIP matches \d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b at i. An octet is a
// whole digit run: a longer run leaves a digit where '.' or \b is required,
// and backtracking to fewer digits leaves a digit there too.
func matchIP(s string, i int) int {
	p := i
	for octet := 0; octet < 4; octet++ {
		if octet > 0 {
			if p >= len(s) || s[p] != '.' {
				return -1
			}
			p++
		}
		n := digitsAt(s, p)
		if n < 1 || n > 3 {
			return -1
		}
		p += n
	}
	// (?::\d+)? is greedy: take the port if its digits end at a boundary...
	// unless an earlier rule claims the port word first. The port is the one
	// unbounded part of any rule: 12+ digits are a HEX12 word, and digits
	// followed by "-xxxx-..." can start a UUID; drain3 masks those before the
	// IP rule runs, and the IP then matches without its port.
	if p < len(s) && s[p] == ':' {
		n := digitsAt(s, p+1)
		if n > 0 && n < 12 && boundaryAfter(s, p+1+n) && matchUUID(s, p+1) < 0 {
			return p + 1 + n
		}
	}
	// ...otherwise match without it (':' itself is a boundary).
	if boundaryAfter(s, p) {
		return p
	}
	return -1
}

func digitsAt(s string, p int) int {
	n := 0
	for p+n < len(s) && isDigit(s[p+n]) {
		n++
	}
	return n
}

func wordEnd(s string, i int) int {
	for i < len(s) && isWord(s[i]) {
		i++
	}
	return i
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isAlnum(c byte) bool { return isWord(c) && c != '_' }

func hasASCIIDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			return true
		}
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isWord is the class [A-Za-z0-9_] used by the NUM rule's lookarounds.
func isWord(c byte) bool {
	return isDigit(c) || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// maskNum is the Python rule
//
//	((?<=[^A-Za-z0-9_])|^)[-+]?\d+(?:\.\d+)?(?:ms|s)?((?=[^A-Za-z0-9_])|$)
//
// applied with re.sub. A match may start where the previous byte is not a
// word byte (or at the start). From there the regex engine tries
// alternatives in a fixed order (sign before no sign, longest digit run
// first, fraction before no fraction, "ms" before "s" before nothing) and
// takes the first whose end is followed by a non-word byte or the end of
// the string. Lookbehinds see the original text, and re.sub resumes after
// each match.
func maskNum(s string) string {
	var b strings.Builder
	last := 0 // end of the previous match, in s
	for i := 0; i < len(s); {
		if i > 0 && isWord(s[i-1]) {
			i++
			continue
		}
		end := matchNumAt(s, i)
		if end < 0 {
			i++
			continue
		}
		if b.Len() == 0 && last == 0 {
			b.Grow(len(s))
		}
		b.WriteString(s[last:i])
		b.WriteString("<NUM>")
		last = end
		if end == i { // cannot happen (\d+ is non-empty), but never loop forever
			i++
		} else {
			i = end
		}
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// matchNumAt returns the end of the first successful match of the NUM body
// starting exactly at i, or -1.
func matchNumAt(s string, i int) int {
	// [-+]? takes the sign first, then tries without it.
	starts, ns := [2]int{i, i}, 1
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		starts[0], ns = i+1, 2
	}
	for _, p := range starts[:ns] {
		n := 0
		for p+n < len(s) && isDigit(s[p+n]) {
			n++
		}
		for k := n; k >= 1; k-- { // \d+ is greedy: longest first
			q := p + k
			// (?:\.\d+)? tries the fraction (longest first) before skipping it.
			if q+1 < len(s) && s[q] == '.' && isDigit(s[q+1]) {
				f := 0
				for q+1+f < len(s) && isDigit(s[q+1+f]) {
					f++
				}
				for m := f; m >= 1; m-- {
					if e := matchSuffix(s, q+1+m); e >= 0 {
						return e
					}
				}
			}
			if e := matchSuffix(s, q); e >= 0 {
				return e
			}
		}
	}
	return -1
}

// matchSuffix tries (?:ms|s)? then the lookahead at position q.
func matchSuffix(s string, q int) int {
	if strings.HasPrefix(s[q:], "ms") && boundaryAfter(s, q+2) {
		return q + 2
	}
	if strings.HasPrefix(s[q:], "s") && boundaryAfter(s, q+1) {
		return q + 1
	}
	if boundaryAfter(s, q) {
		return q
	}
	return -1
}

func boundaryAfter(s string, q int) bool { return q == len(s) || !isWord(s[q]) }
