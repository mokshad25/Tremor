package detect

import (
	"fmt"
	"testing"
	"time"

	"github.com/mokshad/tremor/internal/event"
)

const t0 = int64(1_767_571_200) * int64(time.Second) // 2026-01-05 00:00 UTC

func tok(prefix string, n int) string { return fmt.Sprintf("%s%012x", prefix, n) }

func secEv(msg string, at time.Duration, seq uint64) *event.Event {
	ns := t0 + int64(at)
	return &event.Event{Seq: seq, Service: "auth", Message: msg, ReceivedAt: ns, Timestamp: ns}
}

func TestClassify(t *testing.T) {
	cases := map[string]authKind{
		"sshd[1]: failed password for usr_x from ip_y port 22 ssh2":                   authFailure,
		"sshd[1]: failed password for invalid user root from ip_y port 22 ssh2":       authFailure,
		"login failed user=usr_x ip=ip_y":                                             authFailure,
		"sshd[1]: accepted publickey for usr_x from ip_y port 22 ssh2":                authSuccess,
		"login succeeded user=usr_x ip=ip_y":                                          authSuccess,
		"sudo:   usr_x : tty=pts/0 ; pwd=/home/usr_x ; user=root ; command=/bin/bash": authElevation,
		"role admin granted to user=usr_x by admin usr_y":                             authAccountChange,
		"group membership changed: user=usr_x added to group wheel by admin usr_y":    authAccountChange,
		// Duplicate lines sshd writes for the same attempt must not count again.
		"sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=ip_y user=root": authNone,
		"sshd[1]: input_userauth_request: invalid user admin [preauth]":              authNone,
		"sshd[1]: invalid user admin from ip_y":                                      authNone,
		"payment authorized txn_1 amount=5":                                          authNone,
	}
	for msg, want := range cases {
		if got := classify(msg); got != want {
			t.Errorf("classify(%q) = %d, want %d", msg, got, want)
		}
	}
}

func TestBruteForceThenSuccessIsCritical(t *testing.T) {
	s := NewSecurity(DefaultSecurityConfig(), "auth", nil)
	u, ip := tok("usr_", 1), tok("ip_", 2)
	var alerts []Alert
	for i := range 12 {
		alerts = append(alerts, s.Observe(secEv("Login failed user="+u+" ip="+ip, time.Duration(i)*5*time.Second, uint64(i+1)), 1, "", false)...)
	}
	if len(alerts) != 1 || alerts[0].Type != SignalBruteForce || alerts[0].Severity != "HIGH" ||
		alerts[0].User != u || alerts[0].Source != ip || alerts[0].Techniques[0] != "T1110.001" {
		t.Fatalf("brute force alerts: %+v", alerts)
	}
	if alerts[0].SourceSeqs.First != 1 || alerts[0].SourceSeqs.Last != 10 {
		t.Fatalf("source seqs %+v", alerts[0].SourceSeqs)
	}
	got := s.Observe(secEv("Login succeeded user="+u+" ip="+ip, 70*time.Second, 13), 2, "", false)
	if len(got) != 1 || got[0].Severity != "CRITICAL" || len(got[0].Techniques) != 2 {
		t.Fatalf("success after brute force: %+v", got)
	}
	// Failures spread wider than the window never add up.
	s2 := NewSecurity(DefaultSecurityConfig(), "auth", nil)
	for i := range 30 {
		if a := s2.Observe(secEv("Login failed user="+u+" ip="+ip, time.Duration(i)*time.Minute, 1), 1, "", false); len(a) > 0 {
			t.Fatalf("slow failures (1/min) alerted: %+v", a)
		}
	}
}

func TestCredentialStuffingAndNATGuard(t *testing.T) {
	attacker, nat := tok("ip_", 9), tok("ip_", 10)
	s := NewSecurity(DefaultSecurityConfig(), "auth", map[string]bool{tok("ip_", 11): true})
	var alerts []Alert
	for i := range 25 {
		alerts = append(alerts, s.Observe(secEv(fmt.Sprintf("Login failed user=%s ip=%s", tok("usr_", 100+i), attacker), time.Duration(i)*3*time.Second, uint64(i)), 1, "", false)...)
	}
	if len(alerts) != 1 || alerts[0].Type != SignalCredentialStuffing || alerts[0].Source != attacker {
		t.Fatalf("stuffing: %+v", alerts)
	}
	// An office NAT: the same number of distinct failing users, but buried
	// in successful logins. The failure-ratio guard keeps it quiet.
	for i := range 200 {
		msg := fmt.Sprintf("Login succeeded user=%s ip=%s", tok("usr_", 1000+i), nat)
		if i%8 == 0 {
			msg = fmt.Sprintf("Login failed user=%s ip=%s", tok("usr_", 1000+i), nat)
		}
		if a := s.Observe(secEv(msg, time.Duration(i)*time.Second, 1), 1, "", false); len(a) > 0 && a[0].Type == SignalCredentialStuffing {
			t.Fatalf("NAT flagged as stuffing: %+v", a)
		}
	}
	// An allowlisted source never trips the single-source rule.
	for i := range 30 {
		msg := fmt.Sprintf("Login failed user=%s ip=%s", tok("usr_", 5000+i), tok("ip_", 11))
		if a := s.Observe(secEv(msg, time.Duration(i)*time.Second, 1), 1, "", false); len(a) > 0 && a[0].Type == SignalCredentialStuffing {
			t.Fatalf("allowlisted source flagged: %+v", a)
		}
	}
}

func TestDistributedStuffingOpensOnce(t *testing.T) {
	cfg := DefaultSecurityConfig()
	cfg.DistributedWarmup = 5
	s := NewSecurity(cfg, "auth", nil)
	// Background: one typo an hour from home addresses, for 3 hours.
	n := 0
	for m := range 180 {
		if m%20 == 0 {
			s.Observe(secEv(fmt.Sprintf("Login failed user=%s ip=%s", tok("usr_", n), tok("ip_", n)), time.Duration(m)*time.Minute, 1), 1, "", false)
			n++
		}
	}
	tickRange := func(fromMin, toMin int) (out []Alert) {
		for m := fromMin; m < toMin; m++ {
			out = append(out, s.Tick(t0/int64(time.Second)+int64(m*60))...)
		}
		return out
	}
	if a := tickRange(0, 180); len(a) != 0 {
		t.Fatalf("background alerted: %+v", a)
	}
	// Low and slow: 300 users from 150 sources over an hour.
	for i := range 300 {
		at := 180*time.Minute + time.Duration(i)*12*time.Second
		s.Observe(secEv(fmt.Sprintf("Login failed user=%s ip=%s", tok("usr_", 10_000+i), tok("ip_", 20_000+i%150)), at, 1), 1, "", false)
	}
	got := tickRange(180, 360)
	if len(got) != 1 || got[0].Type != SignalCredentialStuffing || got[0].Source != "" {
		t.Fatalf("distributed stuffing should open exactly one incident while it ages out, got %d: %+v", len(got), got)
	}
}

func TestPrivilegeBaselineIsFrozen(t *testing.T) {
	cfg := DefaultSecurityConfig()
	cfg.PrivilegeLearnS, cfg.CooldownS = 3600, 60
	s := NewSecurity(cfg, "ops", nil)
	admin, emp := tok("usr_", 1), tok("usr_", 2)
	sudo := func(u string) string {
		return "sudo:   " + u + " : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
	}
	if a := s.Observe(secEv(sudo(admin), time.Minute, 1), 7, "sudo", false); len(a) != 0 {
		t.Fatal("alerted during learning")
	}
	if a := s.Observe(secEv(sudo(admin), 2*time.Hour, 2), 7, "sudo", false); len(a) != 0 {
		t.Fatal("known actor+action alerted after learning")
	}
	a := s.Observe(secEv(sudo(emp), 3*time.Hour, 3), 7, "sudo", false)
	if len(a) != 1 || a[0].Type != SignalPrivilegeChange || a[0].User != emp || a[0].Techniques[0] != "T1548.003" || a[0].Severity != "HIGH" {
		t.Fatalf("new sudo user: %+v", a)
	}
	if again := s.Observe(secEv(sudo(emp), 30*time.Hour, 4), 7, "sudo", false); len(again) != 1 {
		t.Fatal("frozen baseline: a repeat a day later must alert again")
	}
	// Actor is the one after "by", and a viewer grant does not cover an admin grant.
	grant := func(role string) string { return "Role " + role + " granted to user=" + emp + " by admin " + admin }
	s2 := NewSecurity(cfg, "portal", nil)
	s2.Observe(secEv(grant("viewer"), time.Minute, 1), 3, "Role <*> granted", false)
	if a := s2.Observe(secEv(grant("viewer"), 2*time.Hour, 2), 3, "Role <*> granted", false); len(a) != 0 {
		t.Fatalf("routine grant alerted: %+v", a)
	}
	a = s2.Observe(secEv(grant("admin"), 3*time.Hour, 3), 3, "Role <*> granted", false)
	if len(a) != 1 || a[0].User != admin || a[0].Techniques[0] != "T1098" {
		t.Fatalf("admin grant: %+v", a)
	}
}

func TestUnusualAccessNeedsMatureHistory(t *testing.T) {
	cfg := DefaultSecurityConfig()
	s := NewSecurity(cfg, "auth", nil)
	u, home, other := tok("usr_", 1), tok("ip_", 1), tok("ip_", 2)
	login := func(src string, day int, hour int) []Alert {
		at := time.Duration(day)*24*time.Hour + time.Duration(hour)*time.Hour
		return s.Observe(secEv("Login succeeded user="+u+" ip="+src, at, 1), 1, "", false)
	}
	for d := range 8 {
		for _, h := range []int{9, 10, 11} {
			if d == 2 && h == 9 {
				if a := login(other, d, h); len(a) != 0 { // new source, but history is young
					t.Fatalf("immature history alerted: %+v", a)
				}
				continue
			}
			login(home, d, h)
		}
	}
	a := login(tok("ip_", 3), 9, 10) // new source, usual hour
	if len(a) != 1 || a[0].Severity != "INFO" || a[0].Type != SignalUnusualAccess {
		t.Fatalf("new source: %+v", a)
	}
	a = login(home, 9, 3) // usual source, 03:00
	if len(a) != 1 || a[0].Severity != "INFO" {
		t.Fatalf("odd hour: %+v", a)
	}
	a = login(tok("ip_", 4), 10, 21) // both: takeover shape, pages
	if len(a) != 1 || a[0].Severity != "HIGH" || a[0].Techniques[0] != "T1078" {
		t.Fatalf("takeover: %+v", a)
	}
}

func TestIdentityFromAttributes(t *testing.T) {
	ev := &event.Event{Message: "auth failed", Attrs: map[string]string{"enduser.id": tok("usr_", 5), "client.address": tok("ip_", 6)}}
	if u, s := identity(ev); u != tok("usr_", 5) || s != tok("ip_", 6) {
		t.Fatalf("identity %q %q", u, s)
	}
	if firstToken("usr_0123456789abX", "usr_") != "" || firstToken("xusr_0123456789ab", "usr_") != "" {
		t.Fatal("token boundaries not enforced")
	}
}

func TestSystemAccountIdentity(t *testing.T) {
	ev := &event.Event{Message: "sshd[1]: Failed password for root from " + tok("ip_", 1) + " port 22 ssh2"}
	if u, s := identity(ev); u != "root" || s != tok("ip_", 1) {
		t.Fatalf("identity %q %q", u, s)
	}
	ev.Message = "sshd[1]: Failed password for invalid user admin from " + tok("ip_", 1) + " port 22 ssh2"
	if u, _ := identity(ev); u != "admin" {
		t.Fatalf("identity %q", u)
	}
}

func TestSourceDictionaryAttack(t *testing.T) {
	s := NewSecurity(DefaultSecurityConfig(), "sshd", nil)
	ip := tok("ip_", 7)
	users := []string{"admin", "root", "test", "pi", "guest", "user", "support", "ftp", "sshd", "uucp"}
	var got []Alert
	for i := range 35 { // 35 failures, 10 accounts, none above the per-user threshold
		msg := "sshd[1]: Failed password for invalid user " + users[i%len(users)] + " from " + ip + " port 22 ssh2"
		got = append(got, s.Observe(secEv(msg, time.Duration(i)*4*time.Second, uint64(i)), 1, "", false)...)
	}
	if len(got) != 1 || got[0].Type != SignalBruteForce || got[0].Source != ip || got[0].Techniques[0] != "T1110" {
		t.Fatalf("dictionary attack: %+v", got)
	}
}
