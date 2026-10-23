package drain

import "strings"

// MaskTokens replaces the redactor's keyed pseudonyms with stable
// placeholders before template mining: ip_<12 hex> becomes <IP> and
// usr_<12 hex> becomes <USER>. Without this, "upstream=ip_3f2a9c1b4d5e"
// contains digits and Drain turns the whole token into <*>, losing the
// field name. It runs before TremorMasker and is kept separate from it so
// the drain3 parity tests still exercise exactly TREMOR's Python rules.
func MaskTokens(s string) string {
	if !strings.Contains(s, "ip_") && !strings.Contains(s, "usr_") {
		return s
	}
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); i++ {
		var prefix, repl string
		switch {
		case strings.HasPrefix(s[i:], "ip_"):
			prefix, repl = "ip_", "<IP>"
		case strings.HasPrefix(s[i:], "usr_"):
			prefix, repl = "usr_", "<USER>"
		default:
			continue
		}
		if i > 0 && isWord(s[i-1]) {
			continue
		}
		end := i + len(prefix) + 12
		if end > len(s) || !isHex12(s[i+len(prefix):end]) || (end < len(s) && isWord(s[end])) {
			continue
		}
		b.WriteString(s[last:i])
		b.WriteString(repl)
		last = end
		i = end - 1
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func isHex12(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isDigit(c) && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
