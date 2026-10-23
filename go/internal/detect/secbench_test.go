package detect

import (
	"testing"
	"time"
)

func BenchmarkSecurityObserveNonAuth(b *testing.B) {
	s := NewSecurity(DefaultSecurityConfig(), "svc", nil)
	ev := secEv("Payment authorized txn_8f2a0c1d9e7b amount=1250.00 INR merchant=acme_books card <CARD> in 182ms", time.Second, 1)
	for b.Loop() {
		s.Observe(ev, 1, "", false)
	}
}

func BenchmarkSecurityObserveAuthFailure(b *testing.B) {
	s := NewSecurity(DefaultSecurityConfig(), "svc", nil)
	ev := secEv("Login failed user="+tok("usr_", 1)+" ip="+tok("ip_", 2)+" reason=bad_password", time.Second, 1)
	for i := 0; b.Loop(); i++ {
		ev.ReceivedAt = t0 + int64(i)*int64(time.Minute) // spread out: below every threshold
		s.Observe(ev, 1, "", false)
	}
}

func BenchmarkSecurityObserveNonAuthCached(b *testing.B) {
	s := NewSecurity(DefaultSecurityConfig(), "svc", nil)
	ev := secEv("Payment authorized txn_8f2a0c1d9e7b amount=1250.00 INR merchant=acme_books card <CARD> in 182ms", time.Second, 1)
	tmpl := "Payment authorized <ID> amount=<NUM> INR merchant=acme_books card <CARD> in <NUM>"
	for b.Loop() {
		s.Observe(ev, 1, tmpl, false)
	}
}
