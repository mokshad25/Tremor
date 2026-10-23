package redact

import "math"

// luhn reports whether digits (ASCII '0'-'9' only) pass the Luhn checksum
// used by payment cards. A random digit string passes 1 time in 10.
func luhn(digits []byte) bool {
	if len(digits) == 0 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// Verhoeff tables (dihedral group D5), used by Aadhaar's check digit. Unlike
// Luhn, Verhoeff catches every single-digit error and every adjacent
// transposition; a random 12-digit string still passes 1 time in 10.
var (
	verhoeffD = [10][10]uint8{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
		{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
		{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	verhoeffP = [8][10]uint8{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
		{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
		{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
	verhoeffInv = [10]uint8{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}
)

// verhoeff reports whether digits end in a valid Verhoeff check digit.
func verhoeff(digits []byte) bool {
	c := uint8(0)
	for i := 0; i < len(digits); i++ {
		d := digits[len(digits)-1-i] - '0'
		c = verhoeffD[c][verhoeffP[i%8][d]]
	}
	return c == 0
}

// verhoeffCheckDigit returns the digit to append to digits so the whole
// string is Verhoeff-valid (used by the test-data generator).
func verhoeffCheckDigit(digits []byte) byte {
	c := uint8(0)
	for i := 0; i < len(digits); i++ {
		d := digits[len(digits)-1-i] - '0'
		c = verhoeffD[c][verhoeffP[(i+1)%8][d]]
	}
	return '0' + verhoeffInv[c]
}

// aadhaar: 12 digits, first digit 2-9 (UIDAI never issues 0 or 1), valid
// Verhoeff check digit.
func aadhaar(d []byte) bool {
	return len(d) == 12 && d[0] >= '2' && verhoeff(d)
}

// cardIIN reports whether a 13-19 digit number starts with an issuer prefix
// of a major network (Visa, Mastercard, Amex, Discover, RuPay, JCB, Diners,
// UnionPay, Maestro). Checking the prefix on top of Luhn removes most
// accidental hits from long numeric ids.
func cardIIN(d []byte) bool {
	n := len(d)
	if n < 13 || n > 19 {
		return false
	}
	p := func(k int) int {
		v := 0
		for i := 0; i < k; i++ {
			v = v*10 + int(d[i]-'0')
		}
		return v
	}
	switch {
	case d[0] == '4': // Visa
		return true
	case p(2) >= 51 && p(2) <= 55, p(4) >= 2221 && p(4) <= 2720: // Mastercard
		return n == 16
	case p(2) == 34 || p(2) == 37: // Amex
		return n == 15
	case p(4) == 6011, p(3) >= 644 && p(3) <= 649, p(2) == 65: // Discover / RuPay
		return n >= 16
	case p(2) == 60 || p(2) == 81 || p(2) == 82 || p(3) == 508 || p(3) == 353 || p(3) == 356: // RuPay
		return n == 16
	case p(4) >= 3528 && p(4) <= 3589: // JCB
		return n >= 16
	case p(2) == 36 || p(2) == 38 || (p(3) >= 300 && p(3) <= 305): // Diners
		return n >= 14
	case p(2) == 62: // UnionPay
		return n >= 16
	case p(2) == 50 || (p(2) >= 56 && p(2) <= 59) || p(2) == 63 || p(2) == 67: // Maestro
		return true
	}
	return false
}

func card(d []byte) bool { return cardIIN(d) && luhn(d) }

// indianMobile: 10 digits starting 6-9 (TRAI numbering for mobiles).
func indianMobile(d []byte) bool { return len(d) == 10 && d[0] >= '6' && d[0] <= '9' }

// panHolderTypes is the 4th character of a PAN: the holder's category
// (Person, Company, HUF, Firm, AOP, Trust, BOI, Local authority, artificial
// Juridical person, Government).
const panHolderTypes = "PCHFATBLJG"

// pan: [A-Z]{5}[0-9]{4}[A-Z] with a valid holder-type letter.
func pan(w string) bool {
	if len(w) != 10 {
		return false
	}
	for i := 0; i < 10; i++ {
		c := w[i]
		switch {
		case i < 5 || i == 9:
			if c < 'A' || c > 'Z' {
				return false
			}
		default:
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	for i := 0; i < len(panHolderTypes); i++ {
		if w[3] == panHolderTypes[i] {
			return true
		}
	}
	return false
}

// shannon returns the Shannon entropy of s in bits per byte.
func shannon(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	h, n := 0.0, float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
