package sim

import (
	"reflect"
	"testing"
)

func TestGenerateDeterministicAndLabelled(t *testing.T) {
	cfg := DefaultConfig()
	a, la := Generate(cfg)
	b, lb := Generate(cfg)
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(la, lb) {
		t.Fatal("same seed, different scenario")
	}
	for i := 1; i < len(a); i++ {
		if a[i].TS.Before(a[i-1].TS) {
			t.Fatal("lines not sorted")
		}
	}
	types := map[string]int{}
	for _, l := range la {
		types[l.Type]++
		if l.Start.Before(cfg.Start.AddDate(0, 0, cfg.AttackFromDay)) {
			t.Fatalf("attack during the learning period: %+v", l)
		}
	}
	for _, typ := range []string{"brute_force", "credential_stuffing", "privilege_change", "unusual_access"} {
		if types[typ] == 0 {
			t.Errorf("no %s attacks", typ)
		}
	}
	t.Logf("%d lines (%s), labels %v", len(a), Summary(a), types)
	clean, cl := Generate(Config{Seed: 7, Start: cfg.Start, Days: 2, Employees: 100, NATEmployees: 60, Admins: 5})
	if len(cl) != 0 || len(clean) == 0 {
		t.Fatal("attack-free scenario has labels")
	}
}

func TestParseSyslog(t *testing.T) {
	l, ok := ParseSyslog("Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186", 2017)
	if !ok || l.Service != "sshd" || l.Message != "sshd[24200]: Invalid user webmaster from 173.234.31.186" ||
		l.TS.Year() != 2017 || l.TS.Month() != 12 || l.TS.Day() != 10 || l.TS.Hour() != 6 {
		t.Fatalf("%+v %v", l, ok)
	}
	if l, ok := ParseSyslog("Jan  5 01:02:03 host CRON[99]: job", 2018); !ok || l.Service != "CRON" || l.TS.Day() != 5 {
		t.Fatalf("single-digit day: %+v", l)
	}
	if _, ok := ParseSyslog("garbage", 2017); ok {
		t.Fatal("garbage parsed")
	}
}
