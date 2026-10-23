package drain

import (
	"regexp"
	"strings"
)

// Masker replaces variable parts of a message (ids, IPs, numbers) with
// placeholders like <NUM> before Drain sees it, so messages that differ only
// in those parts share a template. The rules and their order are TREMOR's
// (app/core/templates.py): the most specific run first, so the digits in a
// UUID or an IP are not masked as <NUM> before the whole token is.
//
// Go's regexp (RE2) has no lookaround, which two of the Python patterns use:
//   - HEX12 `\b(?=[0-9a-fA-F]*\d)[0-9a-fA-F]{12,}\b` becomes the plain
//     pattern plus a "contains a digit" check on each match. Inside a run of
//     word characters there is no \b, so Python cannot match a shorter
//     suffix of a rejected run either; the results are identical.
//   - NUM, with a lookbehind and lookahead, is matched by hand (maskNum),
//     reproducing Python's backtracking order exactly.
//
// Known divergence: Python's \b and \d are Unicode-aware for str patterns;
// Go's are ASCII. Messages with non-ASCII letters or digits glued to a
// number can mask differently. TREMOR's inputs are overwhelmingly ASCII and
// the drain3 comparison test runs on real TREMOR logs.
type Masker struct {
	rules []maskRule
}

type maskRule struct {
	re   *regexp.Regexp
	name string
	keep func(string) bool // optional post-filter replacing a lookahead
}

// TremorMasker returns the masker matching TREMOR's Python configuration.
func TremorMasker() *Masker {
	return &Masker{rules: []maskRule{
		{re: regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`), name: "UUID"},
		{re: regexp.MustCompile(`\b0x[0-9a-fA-F]+\b`), name: "HEX"},
		{re: regexp.MustCompile(`\b[0-9a-fA-F]{12,}\b`), name: "HEX", keep: hasASCIIDigit},
		{re: regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`), name: "IP"},
		{re: regexp.MustCompile(`\b(?:txn|req|acct|ord|usr|sess|kid|pay|ch|re)_[A-Za-z0-9]+\b`), name: "ID"},
	}}
}

// Mask applies every rule in order, then the NUM rule.
func (m *Masker) Mask(s string) string {
	for _, r := range m.rules {
		repl := "<" + r.name + ">"
		if r.keep == nil {
			s = r.re.ReplaceAllLiteralString(s, repl)
			continue
		}
		s = r.re.ReplaceAllStringFunc(s, func(match string) string {
			if r.keep(match) {
				return repl
			}
			return match
		})
	}
	return maskNum(s)
}

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
	starts := []int{}
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		starts = append(starts, i+1) // [-+]? takes the sign first...
	}
	starts = append(starts, i) // ...then tries without it
	for _, p := range starts {
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
