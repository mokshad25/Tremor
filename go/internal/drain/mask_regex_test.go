package drain

import "regexp"

// regexMasker is the original regexp implementation of TREMOR's masking
// rules, one ReplaceAll pass per rule followed by maskNum. Masker replaced it
// with a single hand-written scan (Phase 7); it stays here as the reference
// the differential tests and benchmarks compare against.
type regexMasker struct {
	rules []regexRule
}

type regexRule struct {
	re   *regexp.Regexp
	name string
	keep func(string) bool // optional post-filter replacing a lookahead
}

func newRegexMasker() *regexMasker {
	return &regexMasker{rules: []regexRule{
		{re: regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`), name: "UUID"},
		{re: regexp.MustCompile(`\b0x[0-9a-fA-F]+\b`), name: "HEX"},
		{re: regexp.MustCompile(`\b[0-9a-fA-F]{12,}\b`), name: "HEX", keep: hasASCIIDigit},
		{re: regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`), name: "IP"},
		{re: regexp.MustCompile(`\b(?:txn|req|acct|ord|usr|sess|kid|pay|ch|re)_[A-Za-z0-9]+\b`), name: "ID"},
	}}
}

func (m *regexMasker) Mask(s string) string {
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
